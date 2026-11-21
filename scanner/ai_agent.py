"""
scanX built-in AI analyst.

Runs on the scanX server with the operator's API key, so users (and judges)
can get an attack-vector report without bringing their own AI. It uses the
SAME tools as the MCP endpoint and the REST API (scanner.mcp_http.TOOLS), so
all three paths read identical data.

Provider is switchable (settings.AI_PROVIDER): Anthropic Claude, OpenAI, or
NVIDIA NIM (e.g. Nemotron, through its OpenAI-compatible API).
Each job is a Report row in status QUEUED; the worker's AI thread calls
process_next_report().
"""
from __future__ import annotations

import json
import logging
import time
from datetime import timedelta
from types import SimpleNamespace

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from . import mcp_http
from .models import Report, Scan

logger = logging.getLogger(__name__)

# Tools the built-in agent may use: every read tool, plus submit_report
# (which fills the queued report instead of creating a new one).
_READ_TOOLS = [n for n, s in mcp_http.TOOLS.items() if s["annotations"].get("readOnlyHint") and n != "list_reports"]
MAX_TOOL_RESULT_CHARS = 60_000  # keep any single tool result from flooding the context

SUBMIT_REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string", "description": "Report title"},
        "summary": {"type": "string", "description": "1-3 plain sentences"},
        "content": {"type": "string", "description": "Full report in Markdown"},
        "findings": {
            "type": "object",
            "description": "Structured findings",
            "properties": {
                "attack_vectors": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low"]},
                            "hosts": {"type": "array", "items": {"type": "string"}},
                            "evidence": {"type": "string"},
                            "mitre": {"type": "array", "items": {"type": "string"}},
                            "recommendation": {"type": "string"},
                        },
                        "required": ["name", "severity"],
                    },
                },
            },
        },
    },
    "required": ["title", "summary", "content"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = (
    "You are scanX's built-in security analyst. You analyse passive reconnaissance data that the "
    "organization collected about its own domains, and write an attack-vector report for its "
    "defenders. Use only the scanX tools; you cannot and must not contact, probe or attack any host. "
    "Base every finding on data the tools returned and cite the hosts. When you are done, call "
    "submit_report exactly once with the finished report. Do not invent CVEs, credentials or "
    "vulnerabilities you cannot tie to observed data; mark uncertain items 'needs verification'."
)


class AiNotConfigured(Exception):
    pass


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GENERIC_KEY_NAMES = ("API_KEY", "api_key", "AI_API_KEY", "ai_api_key")
_PROVIDER_ALIASES = {"nemotron": "nvidia", "nim": "nvidia", "nvidia_nim": "nvidia",
                     "claude": "anthropic", "gpt": "openai"}


def _generic_key() -> str:
    """A provider-neutral key, e.g. `api_key=nvapi-...` in .env."""
    import os
    for name in GENERIC_KEY_NAMES:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


def _provider_of_key(key: str) -> str | None:
    """Recognise the provider from the key's prefix."""
    if key.startswith("nvapi-"):
        return "nvidia"
    if key.startswith("sk-ant-"):
        return "anthropic"
    if key.startswith("sk-"):
        return "openai"
    return None


def provider_key(provider: str) -> str:
    """The API key to use for `provider`: its own variable, else the generic one."""
    import os
    own = {
        "anthropic": os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"),
        "openai": os.environ.get("OPENAI_API_KEY"),
        "nvidia": os.environ.get("NVIDIA_API_KEY"),
    }.get(provider)
    if own:
        return own.strip()
    generic = _generic_key()
    if generic and (_configured_choice() == provider or _provider_of_key(generic) == provider):
        return generic
    return ""


def _configured_choice() -> str:
    choice = (settings.AI_PROVIDER or "").strip().lower()
    return _PROVIDER_ALIASES.get(choice, choice)


def active_provider() -> str | None:
    """'anthropic', 'openai', 'nvidia', or None when no usable API key is configured."""
    has_anthropic = bool(provider_key("anthropic"))
    has_openai = bool(provider_key("openai"))
    has_nvidia = bool(provider_key("nvidia"))
    choice = _configured_choice()
    if choice == "anthropic":
        return "anthropic" if has_anthropic else None
    if choice == "openai":
        return "openai" if has_openai else None
    if choice == "nvidia":
        return "nvidia" if has_nvidia else None
    for name, present in (("anthropic", has_anthropic), ("openai", has_openai), ("nvidia", has_nvidia)):
        if present:
            return name
    return None


def provider_label(provider: str | None = None) -> str:
    provider = provider or active_provider()
    if provider == "anthropic":
        return f"Claude ({settings.AI_MODEL_ANTHROPIC})"
    if provider == "openai":
        return f"OpenAI ({settings.AI_MODEL_OPENAI})"
    if provider == "nvidia":
        return f"NVIDIA ({settings.AI_MODEL_NVIDIA.split('/')[-1]})"
    return "not configured"


def previous_scan(scan: Scan) -> Scan | None:
    """The completed scan of the same domain (same organization) just before this one."""
    if not scan.program_id:
        return None
    return (
        Scan.objects.filter(program_id=scan.program_id, domain=scan.domain,
                            status=Scan.Status.COMPLETED, created_at__lt=scan.created_at)
        .defer("httpx_results").order_by("-created_at").first()
    )


def availability(scan: Scan | None = None, report_type: str = Report.ReportType.ATTACK_VECTOR) -> dict:
    """
    Whether the built-in AI can be used right now, and why not if it can't.
    Returns {"ok": bool, "reason": str, "provider": str, "remaining_today": int}.
    """
    provider = active_provider()
    today = timezone.localtime().replace(hour=0, minute=0, second=0, microsecond=0)
    used = Report.objects.filter(source=Report.Source.BUILTIN_AI, created_at__gte=today).count()
    remaining = max(settings.AI_DAILY_LIMIT - used, 0)
    info = {"ok": False, "reason": "", "provider": provider_label(provider), "remaining_today": remaining}
    if not provider:
        info["reason"] = "Built-in AI isn't configured on this server yet."
        return info
    if remaining <= 0:
        info["reason"] = "Today's built-in AI reports are used up. Try again tomorrow, or connect your own agent."
        return info
    if scan is not None:
        if scan.status != Scan.Status.COMPLETED:
            info["reason"] = "Only completed scans can be analysed."
            return info
        if report_type == Report.ReportType.CHANGE_ANALYSIS and not previous_scan(scan):
            info["reason"] = "There's no earlier completed scan of this domain to compare with."
            return info
        recent = Report.objects.filter(
            scan=scan, source=Report.Source.BUILTIN_AI, report_type=report_type,
            created_at__gte=timezone.now() - timedelta(minutes=settings.AI_SCAN_COOLDOWN_MINUTES),
        ).exclude(status=Report.Status.FAILED).order_by("-created_at").first()  # failures may retry at once
        if recent:
            info["reason"] = "An AI report for this scan was requested a few minutes ago."
            info["recent_report"] = recent
            return info
    info["ok"] = True
    return info


_TITLES = {
    Report.ReportType.ATTACK_VECTOR: "AI attack vector report — {domain}",
    Report.ReportType.CHANGE_ANALYSIS: "AI change analysis — {domain}",
}


def queue_report(scan: Scan, report_type: str = Report.ReportType.ATTACK_VECTOR) -> Report:
    """Create a QUEUED built-in AI report for a completed scan (caller checked availability)."""
    return Report.objects.create(
        scan=scan,
        report_type=report_type,
        title=_TITLES.get(report_type, _TITLES[Report.ReportType.ATTACK_VECTOR]).format(domain=scan.domain),
        status=Report.Status.QUEUED,
        source=Report.Source.BUILTIN_AI,
        generated_by=f"scanX AI · {provider_label()}"[:100],
    )


# ---------------------------------------------------------------------------
# Follow-up questions about a report
# ---------------------------------------------------------------------------

MAX_QUESTION_CHARS = 500


def question_availability(report: Report) -> dict:
    """Whether a new question can be asked about this report now."""
    from .models import ReportQuestion

    info = {"ok": False, "reason": "", "provider": provider_label()}
    if not active_provider():
        info["reason"] = "Built-in AI isn't configured on this server yet."
        return info
    if report.status != Report.Status.COMPLETED:
        info["reason"] = "Questions can be asked once the report is complete."
        return info
    if report.questions.filter(status__in=[ReportQuestion.Status.QUEUED, ReportQuestion.Status.ANSWERING]).exists():
        info["reason"] = "The AI is still answering the previous question."
        return info
    if report.questions.count() >= settings.AI_QUESTIONS_PER_REPORT:
        info["reason"] = f"This report has reached its limit of {settings.AI_QUESTIONS_PER_REPORT} questions."
        return info
    today = timezone.localtime().replace(hour=0, minute=0, second=0, microsecond=0)
    if ReportQuestion.objects.filter(created_at__gte=today).count() >= settings.AI_QUESTION_DAILY_LIMIT:
        info["reason"] = "Today's AI questions are used up. Try again tomorrow."
        return info
    info["ok"] = True
    return info


def queue_question(report: Report, text: str):
    from .models import ReportQuestion
    return ReportQuestion.objects.create(report=report, question=text.strip()[:MAX_QUESTION_CHARS])


# ---------------------------------------------------------------------------
# Worker entry points
# ---------------------------------------------------------------------------

def recover_interrupted():
    """Jobs left in progress by a crashed/restarted worker can't resume; fail them."""
    from .models import ReportQuestion

    n = Report.objects.filter(source=Report.Source.BUILTIN_AI, status=Report.Status.GENERATING).update(
        status=Report.Status.FAILED,
        content="Generation failed: the worker restarted before it finished. Generate it again.",
    )
    q = ReportQuestion.objects.filter(status=ReportQuestion.Status.ANSWERING).update(
        status=ReportQuestion.Status.FAILED,
        answer="The worker restarted before the answer was ready. Ask again.",
    )
    if n or q:
        logger.warning("Marked %d interrupted AI report(s) and %d question(s) as failed", n, q)


def process_next_job() -> bool:
    """One unit of AI work for the worker: a queued report first, then a question."""
    return process_next_report() or process_next_question()


def process_next_question() -> bool:
    from .models import ReportQuestion

    with transaction.atomic():
        question = (
            ReportQuestion.objects.select_for_update(skip_locked=True)
            .select_related("report__scan__program")
            .filter(status=ReportQuestion.Status.QUEUED).order_by("created_at").first()
        )
        if not question:
            return False
        question.status = ReportQuestion.Status.ANSWERING
        question.save(update_fields=["status"])
    try:
        job = _QuestionJob(question)
        _dispatch(job)
    except Exception as e:
        logger.exception("AI question %s failed", question.id)
        question.refresh_from_db()
        if question.status != ReportQuestion.Status.ANSWERED:
            question.status = ReportQuestion.Status.FAILED
            question.answer = _user_facing_error(e)
            question.save(update_fields=["status", "answer"])
    return True


def claim_next_report() -> Report | None:
    with transaction.atomic():
        report = (
            Report.objects.select_for_update(skip_locked=True)
            .filter(source=Report.Source.BUILTIN_AI, status=Report.Status.QUEUED)
            .order_by("created_at").first()
        )
        if report:
            report.status = Report.Status.GENERATING
            report.save(update_fields=["status"])
        return report


def process_next_report() -> bool:
    """Run one queued AI report if there is one. Returns True if it did work."""
    report = claim_next_report()
    if not report:
        return False
    started = time.monotonic()
    try:
        run_report(report)
        logger.info("AI report %s completed in %.0fs", report.id, time.monotonic() - started)
    except Exception as e:  # never let one bad job kill the worker thread
        logger.exception("AI report %s failed", report.id)
        report.refresh_from_db()
        if report.status != Report.Status.COMPLETED:
            report.mark_failed(_user_facing_error(e))
    return True


def _user_facing_error(e: Exception) -> str:
    if isinstance(e, AiNotConfigured):
        return str(e)
    name = type(e).__name__
    if "RateLimit" in name:
        return "The AI provider is rate-limiting this server. Try again in a few minutes."
    if "Authentication" in name or "PermissionDenied" in name:
        return "The server's AI API key was rejected. The operator needs to check it."
    if "Timeout" in name or "Connection" in name:
        return "Couldn't reach the AI provider. Try again in a few minutes."
    return f"The AI analysis stopped unexpectedly ({name}). Try again."


# ---------------------------------------------------------------------------
# The agent
# ---------------------------------------------------------------------------

CHANGE_PROMPT = """Explain what changed in the attack surface of {domain} for {org} between the previous
completed scan {prev} ({prev_date}) and this scan {scan} ({scan_date}).

1. Call diff_scans(scan_id="{scan}") to get hosts added, removed and HTTP status changes.
2. For new hosts, call list_hosts(scan_id="{scan}", new_only=true) to see their status, title and
   technologies. Use search_hosts / list_technologies if it helps.
3. Decide which changes matter for security and why: new admin/login/dev/staging hosts, newly
   exposed technologies or versions, directory listings, hosts that changed from 403 to 200, takeover-prone
   CNAMEs. Also note exposures that disappeared (resolved).
4. Rate each new risk Critical / High / Medium / Low with a one-line reason. Map to MITRE ATT&CK where it fits.
   If nothing meaningful changed, say so plainly.
5. Call submit_report with a clear title, a 1–3 sentence summary, Markdown content (Executive summary,
   What changed (table), New risks, Resolved, Recommendations) and findings
   {{"attack_vectors": [...new risks with name, severity, hosts, evidence, recommendation...],
     "changes": {{"added": n, "removed": n, "status_changed": n}}}}.
Do not scan, probe or contact the hosts yourself — analyse the scanX data only."""

QUESTION_SYSTEM_PROMPT = (
    "You are scanX's security analyst answering a follow-up question about an attack-vector report. "
    "Use the scanX tools to check facts in the scan data when needed. Answer in concise Markdown "
    "(a few short paragraphs or a list; a small table if it helps). Cite hosts. Don't invent data; "
    "say 'needs verification' when unsure. Never probe or contact hosts yourself."
)


class _Job:
    """Shared state for one report run: tool execution + the submitted result."""

    system = SYSTEM_PROMPT

    def __init__(self, report: Report):
        self.report = report
        self.scan = report.scan
        self.deadline = time.monotonic() + settings.AI_JOB_TIMEOUT
        # A pseudo-token: tools are scoped to this scan's organization, like an MCP token
        self.token = SimpleNamespace(program=self.scan.program, label="scanX AI", prefix="builtin")
        self.submitted = False
        self.tool_calls = 0
        self.started = time.monotonic()
        self.steps: list[dict] = []

    def scan_summary(self) -> str:
        """get_scan output, given up front so the model doesn't spend a turn fetching it."""
        envelope, _ = mcp_http.run_tool("get_scan", {"scan_id": str(self.scan.id)}, self.token, None)
        return json.dumps(envelope.get("data"), default=str)

    def tool_specs(self):
        return _tool_specs()

    def finish(self, final_text: str):
        self.finish_without_submit(final_text)

    def user_prompt(self) -> str:
        org = self.scan.program.name if self.scan.program else "this organization"
        if self.report.report_type == Report.ReportType.CHANGE_ANALYSIS:
            prev = previous_scan(self.scan)
            if not prev:
                raise AiNotConfigured("There's no earlier completed scan of this domain to compare with.")
            return CHANGE_PROMPT.format(
                domain=self.scan.domain, org=org, scan=self.scan.id, prev=prev.id,
                scan_date=timezone.localtime(self.scan.completed_at).strftime("%Y-%m-%d %H:%M") if self.scan.completed_at else "?",
                prev_date=timezone.localtime(prev.completed_at).strftime("%Y-%m-%d %H:%M") if prev.completed_at else "?",
            )
        return (
            f"Analyse scan {self.scan.id} of {self.scan.domain} for {org} and map possible attack vectors.\n\n"
            f"Scan summary (already fetched for you; no need to call get_scan):\n{self.scan_summary()}\n\n"
            "list_hosts returns up to 200 hosts per call; use nextCursor for the rest.\n\n"
            + mcp_http.ATTACK_VECTOR_PROMPT.format(target=org, scan_hint=f"scan {self.scan.id}.")
            # submit_report has no report_type; replace the whole phrase first
            .replace('Call save_report with report_type "attack_vector", a clear title', "Call submit_report with a clear title")
            .replace("save_report", "submit_report")
        )

    def note(self, text: str):
        """Record a live progress step (shown on the report page while the AI works)."""
        self.steps.append({"at": int(time.monotonic() - self.started), "text": text[:160]})
        Report.objects.filter(pk=self.report.pk).update(progress=self.steps[-40:])

    def thinking(self):
        """Mark that we're waiting on the model (unless that's already the last step)."""
        if not self.steps or self.steps[-1]["text"] != "Thinking…":
            self.note("Thinking…")

    def execute(self, name: str, args: dict) -> tuple[str, bool]:
        """Run a tool call from the model; returns (result_text, is_error)."""
        self.tool_calls += 1
        if time.monotonic() > self.deadline:
            return "Time limit reached. Call submit_report now with what you have.", True
        self.note(_step_text(name, args or {}))
        if name == "submit_report":
            return self._submit(args)
        if name not in _READ_TOOLS:
            return f"Unknown tool {name}.", True
        args = dict(args or {})
        if name in ("get_scan", "list_hosts", "diff_scans") and not args.get("scan_id"):
            args["scan_id"] = str(self.scan.id)
        if name in ("list_hosts", "search_hosts", "list_technologies") and "limit" not in args:
            args["limit"] = 200  # fewer round trips on big targets
        envelope, is_error = mcp_http.run_tool(name, args, self.token, None)
        text = json.dumps(envelope, default=str)
        if len(text) > MAX_TOOL_RESULT_CHARS:
            text = text[:MAX_TOOL_RESULT_CHARS] + '…"} [truncated: use a smaller limit or filters]'
        return text, is_error

    def _submit(self, args: dict) -> tuple[str, bool]:
        if self.submitted:
            return "A report was already submitted; you are done.", True
        title = str(args.get("title") or "").strip()[:255]
        content = str(args.get("content") or "").strip()
        summary = str(args.get("summary") or "").strip()[: mcp_http.MAX_REPORT_SUMMARY]
        findings = args.get("findings") if isinstance(args.get("findings"), dict) else {}
        if not content:
            return "content is required (the full Markdown report).", True
        if len(content) > mcp_http.MAX_REPORT_CONTENT:
            content = content[: mcp_http.MAX_REPORT_CONTENT]
        r = self.report
        r.title = title or r.title
        r.summary = summary
        r.status = Report.Status.COMPLETED
        r.content = content
        r.findings = findings
        r.completed_at = timezone.now()
        r.save(update_fields=["title", "summary", "status", "content", "findings", "completed_at"])
        self.submitted = True
        return "Report saved to scanX. You are done; reply with one short sentence.", False

    def finish_without_submit(self, final_text: str):
        """The model ended without calling submit_report: keep its text if it wrote one."""
        if self.submitted:
            return
        if final_text and len(final_text) > 200:
            self._submit({"title": self.report.title, "summary": "", "content": final_text})
        else:
            self.report.mark_failed("The AI finished without producing a report. Try again.")


class _QuestionJob(_Job):
    """Answer one follow-up question about a completed report (read-only tools, no submit)."""

    system = QUESTION_SYSTEM_PROMPT

    def __init__(self, question):
        super().__init__(question.report)
        self.question = question

    def note(self, text: str):
        pass  # questions show a simple "Thinking…" state, not a step log

    def tool_specs(self):
        return [s for s in _tool_specs() if s[0] != "submit_report"]

    def user_prompt(self) -> str:
        r = self.report
        earlier = list(r.questions.filter(status="answered").exclude(pk=self.question.pk).order_by("created_at"))[-3:]
        history = "\n\n".join(f"Q: {q.question}\nA: {q.answer[:1500]}" for q in earlier)
        return (
            f"Report: {r.title}\nScan: {self.scan.id} of {self.scan.domain}\n"
            f"Summary: {r.summary}\n\nReport content (may be truncated):\n{r.content[:15000]}\n\n"
            + (f"Earlier questions on this report:\n{history}\n\n" if history else "")
            + f"Question: {self.question.question}"
        )

    def finish(self, final_text: str):
        q = self.question
        text = (final_text or "").strip()
        q.status = q.Status.ANSWERED if text else q.Status.FAILED
        q.answer = text[:20000] if text else "The AI didn't produce an answer. Try rephrasing the question."
        q.answered_at = timezone.now()
        q.save(update_fields=["status", "answer", "answered_at"])


_STEP_TEXT = {
    "get_organization": "Reading the organization",
    "list_scans": "Listing scans",
    "get_scan": "Reading the scan summary",
    "list_hosts": "Reading live hosts",
    "search_hosts": "Searching hosts",
    "list_technologies": "Reviewing detected technologies",
    "diff_scans": "Comparing with the previous scan",
    "submit_report": "Writing the report",
}


def _step_text(name: str, args: dict) -> str:
    """Human-readable progress line for a tool call."""
    text = _STEP_TEXT.get(name, f"Using {name}")
    if name == "search_hosts" and args.get("query"):
        text += f" for “{str(args['query'])[:40]}”"
    if name == "list_hosts":
        extras = [f"{k} {str(args[k])[:30]}" for k in ("status", "technology", "ip") if args.get(k)]
        if args.get("new_only"):
            extras.append("new only")
        if args.get("cursor"):
            extras.append(f"from #{args['cursor']}")
        if extras:
            text += f" ({', '.join(extras)})"
    return text + "…"


def _tool_specs():
    """(name, description, json_schema) for every tool the built-in agent gets."""
    specs = []
    for name in _READ_TOOLS:
        t = mcp_http.TOOLS[name]
        specs.append((name, t["description"], t["inputSchema"]))
    specs.append((
        "submit_report",
        "Submit the finished attack-vector report. Call exactly once, at the end. It appears on the "
        "scanX Reports page.",
        SUBMIT_REPORT_SCHEMA,
    ))
    return specs


def run_report(report: Report):
    if not report.scan.program:
        raise AiNotConfigured("This scan has no organization, so the AI can't be scoped to it.")
    job = _Job(report)
    job.note(f"Starting {provider_label()}")
    _dispatch(job)


def _dispatch(job: _Job):
    """Run the job's tool loop on the configured provider, then let the job finish."""
    provider = active_provider()
    if provider == "anthropic":
        final_text = _run_anthropic(job)
    elif provider == "openai":
        final_text = _run_openai(job)
    elif provider == "nvidia":
        final_text = _run_openai(job, nvidia=True)
    else:
        raise AiNotConfigured("Built-in AI isn't configured on this server (no API key).")
    job.finish(final_text)


# --- Anthropic Claude -------------------------------------------------------

def _run_anthropic(job: _Job):
    import anthropic

    client = anthropic.Anthropic(api_key=provider_key("anthropic"), max_retries=3, timeout=180.0)
    tools = [{"name": n, "description": d, "input_schema": s} for n, d, s in job.tool_specs()]
    messages = [{"role": "user", "content": job.user_prompt()}]
    final_text = ""

    for _turn in range(settings.AI_MAX_TURNS):
        job.thinking()
        response = client.beta.messages.create(
            model=settings.AI_MODEL_ANTHROPIC,
            max_tokens=16000,
            system=job.system,
            tools=tools,
            messages=messages,
            output_config={"effort": "high"},
            cache_control={"type": "ephemeral"},  # caches tools + system + growing history
            # On a safety decline, the API re-runs the request on a fallback model
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
        # Keep the full content (incl. thinking blocks) unchanged in the history
        messages.append({"role": "assistant", "content": response.content})
        final_text = "".join(b.text for b in response.content if b.type == "text")

        if response.stop_reason == "refusal":
            raise AiNotConfigured("The AI model declined to analyse this scan.")
        if response.stop_reason == "pause_turn":
            continue
        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if not tool_uses:
            break  # end_turn (or max_tokens with nothing to run)

        results = []
        for block in tool_uses:
            if response.stop_reason == "max_tokens":
                # The output was cut off mid-call, so this tool input may be incomplete
                text, is_error = ("Your response hit the length limit and this call was cut off. "
                                  "Send it again, shorter (e.g. a more concise report).", True)
            else:
                text, is_error = job.execute(block.name, block.input if isinstance(block.input, dict) else {})
            results.append({"type": "tool_result", "tool_use_id": block.id, "content": text, "is_error": is_error})
        messages.append({"role": "user", "content": results})  # all results in one message
        if job.submitted:
            break
    return final_text


# --- OpenAI ------------------------------------------------------------------

def _run_openai(job: _Job, nvidia: bool = False):
    """OpenAI chat-completions tool loop. With nvidia=True, the same loop against NVIDIA NIM."""
    import openai

    if nvidia:
        client = openai.OpenAI(
            base_url=settings.NVIDIA_BASE_URL,
            api_key=provider_key("nvidia"),
            max_retries=3,
            timeout=300.0,
        )
        model = settings.AI_MODEL_NVIDIA
        # NIM accepts the classic max_tokens parameter
        token_limit = {"max_tokens": 16000}
    else:
        client = openai.OpenAI(api_key=provider_key("openai"), max_retries=3, timeout=180.0)
        model = settings.AI_MODEL_OPENAI
        token_limit = {"max_completion_tokens": 16000}
    tools = [
        {"type": "function", "function": {"name": n, "description": d, "parameters": s}}
        for n, d, s in job.tool_specs()
    ]
    messages = [
        {"role": "system", "content": job.system},
        {"role": "user", "content": job.user_prompt()},
    ]
    final_text = ""

    for _turn in range(settings.AI_MAX_TURNS):
        job.thinking()
        completion = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=tools,
            **token_limit,
        )
        choice = completion.choices[0]
        msg = choice.message
        final_text = msg.content or ""
        calls = msg.tool_calls or []
        truncated = getattr(choice, "finish_reason", None) == "length"  # same cut-off guard as Claude
        messages.append({
            "role": "assistant",
            "content": msg.content,
            **({"tool_calls": [c.model_dump() for c in calls]} if calls else {}),
        })
        if not calls:
            break
        for call in calls:
            try:
                args = json.loads(call.function.arguments or "{}")
            except ValueError:
                text, _ = "Arguments were not valid JSON; send a JSON object.", True
            else:
                if truncated:
                    text = "Your response hit the length limit and this call was cut off. Send it again, shorter."
                else:
                    text, _ = job.execute(call.function.name, args if isinstance(args, dict) else {})
            messages.append({"role": "tool", "tool_call_id": call.id, "content": text})
        if job.submitted:
            break
    return final_text
