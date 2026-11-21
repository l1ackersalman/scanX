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
        "findings": {"type": "object", "description": "Structured findings, e.g. {\"attack_vectors\": [...]}"},
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

def active_provider() -> str | None:
    """'anthropic', 'openai', or None when no API key is configured."""
    import os
    has_anthropic = bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
    has_openai = bool(os.environ.get("OPENAI_API_KEY"))
    has_nvidia = bool(os.environ.get("NVIDIA_API_KEY"))
    choice = settings.AI_PROVIDER
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


def availability(scan: Scan | None = None) -> dict:
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
        recent = Report.objects.filter(
            scan=scan, source=Report.Source.BUILTIN_AI,
            created_at__gte=timezone.now() - timedelta(minutes=settings.AI_SCAN_COOLDOWN_MINUTES),
        ).order_by("-created_at").first()
        if recent:
            info["reason"] = "An AI report for this scan was requested a few minutes ago."
            info["recent_report"] = recent
            return info
    info["ok"] = True
    return info


def queue_report(scan: Scan) -> Report:
    """Create a QUEUED built-in AI report for a completed scan (caller checked availability)."""
    return Report.objects.create(
        scan=scan,
        report_type=Report.ReportType.ATTACK_VECTOR,
        title=f"AI attack vector report — {scan.domain}",
        status=Report.Status.QUEUED,
        source=Report.Source.BUILTIN_AI,
        generated_by=f"scanX AI · {provider_label()}"[:100],
    )


# ---------------------------------------------------------------------------
# Worker entry points
# ---------------------------------------------------------------------------

def recover_interrupted():
    """Reports left GENERATING by a crashed/restarted worker can't resume; fail them."""
    n = Report.objects.filter(source=Report.Source.BUILTIN_AI, status=Report.Status.GENERATING).update(
        status=Report.Status.FAILED,
        content="Generation failed: the worker restarted before it finished. Generate it again.",
    )
    if n:
        logger.warning("Marked %d interrupted AI report(s) as failed", n)


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

class _Job:
    """Shared state for one report run: tool execution + the submitted result."""

    def __init__(self, report: Report):
        self.report = report
        self.scan = report.scan
        self.deadline = time.monotonic() + settings.AI_JOB_TIMEOUT
        # A pseudo-token: tools are scoped to this scan's organization, like an MCP token
        self.token = SimpleNamespace(program=self.scan.program, label="scanX AI", prefix="builtin")
        self.submitted = False
        self.tool_calls = 0

    def user_prompt(self) -> str:
        org = self.scan.program.name if self.scan.program else "this organization"
        return (
            f"Analyse scan {self.scan.id} of {self.scan.domain} for {org} and map possible attack vectors.\n\n"
            + mcp_http.ATTACK_VECTOR_PROMPT.format(target=org, scan_hint=f"scan {self.scan.id}.")
            .replace("Call save_report", "Call submit_report")
            .replace('save_report with report_type "attack_vector", a clear title', "submit_report with a clear title")
        )

    def execute(self, name: str, args: dict) -> tuple[str, bool]:
        """Run a tool call from the model; returns (result_text, is_error)."""
        self.tool_calls += 1
        if time.monotonic() > self.deadline:
            return "Time limit reached. Call submit_report now with what you have.", True
        if name == "submit_report":
            return self._submit(args)
        if name not in _READ_TOOLS:
            return f"Unknown tool {name}.", True
        args = dict(args or {})
        if name in ("get_scan", "list_hosts", "diff_scans") and not args.get("scan_id"):
            args["scan_id"] = str(self.scan.id)
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
    provider = active_provider()
    job = _Job(report)
    if provider == "anthropic":
        _run_anthropic(job)
    elif provider == "openai":
        _run_openai(job)
    elif provider == "nvidia":
        _run_openai(job, nvidia=True)
    else:
        raise AiNotConfigured("Built-in AI isn't configured on this server (no API key).")


# --- Anthropic Claude -------------------------------------------------------

def _run_anthropic(job: _Job):
    import anthropic

    client = anthropic.Anthropic(max_retries=3, timeout=180.0)
    tools = [{"name": n, "description": d, "input_schema": s} for n, d, s in _tool_specs()]
    messages = [{"role": "user", "content": job.user_prompt()}]
    final_text = ""

    for _turn in range(settings.AI_MAX_TURNS):
        response = client.beta.messages.create(
            model=settings.AI_MODEL_ANTHROPIC,
            max_tokens=16000,
            system=SYSTEM_PROMPT,
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
            text, is_error = job.execute(block.name, block.input if isinstance(block.input, dict) else {})
            results.append({"type": "tool_result", "tool_use_id": block.id, "content": text, "is_error": is_error})
        messages.append({"role": "user", "content": results})  # all results in one message
        if job.submitted:
            break
    job.finish_without_submit(final_text)


# --- OpenAI ------------------------------------------------------------------

def _run_openai(job: _Job, nvidia: bool = False):
    """OpenAI chat-completions tool loop. With nvidia=True, the same loop against NVIDIA NIM."""
    import os

    import openai

    if nvidia:
        client = openai.OpenAI(
            base_url=settings.NVIDIA_BASE_URL,
            api_key=os.environ.get("NVIDIA_API_KEY"),
            max_retries=3,
            timeout=300.0,
        )
        model = settings.AI_MODEL_NVIDIA
        # NIM accepts the classic max_tokens parameter
        token_limit = {"max_tokens": 16000}
    else:
        client = openai.OpenAI(max_retries=3, timeout=180.0)
        model = settings.AI_MODEL_OPENAI
        token_limit = {"max_completion_tokens": 16000}
    tools = [
        {"type": "function", "function": {"name": n, "description": d, "parameters": s}}
        for n, d, s in _tool_specs()
    ]
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": job.user_prompt()},
    ]
    final_text = ""

    for _turn in range(settings.AI_MAX_TURNS):
        completion = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=tools,
            **token_limit,
        )
        msg = completion.choices[0].message
        final_text = msg.content or ""
        calls = msg.tool_calls or []
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
                text, _ = job.execute(call.function.name, args if isinstance(args, dict) else {})
            messages.append({"role": "tool", "tool_call_id": call.id, "content": text})
        if job.submitted:
            break
    job.finish_without_submit(final_text)
