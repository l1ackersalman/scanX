"""
scanX MCP endpoint — Streamable HTTP transport, served by Django at /api/mcp.

Design follows the PlayCanvas Editor MCP server:
  * one response envelope for every tool: {"data": ..., "meta": {...}}
    (errors live in meta.status/meta.message, an empty list is [] not an error)
  * tools carry read-only / destructive annotations
  * descriptions say when NOT to use a tool
  * long lists are paginated with an opaque cursor

Differences, because scanX is a hosted multi-user service instead of a local
desktop bridge:
  * the agent connects over HTTPS to the VPS, not to a local port
  * every request needs `Authorization: Bearer <token>`; a token is created by
    the Connect button on /mcp and is scoped to ONE organization
  * the endpoint is stateless JSON (no SSE stream, no session id), which every
    current MCP client supports and needs no extra process on the server

Agents read scan data and save their analysis with `save_report`; the report
then shows up on /reports.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import uuid
from collections import Counter
from datetime import timedelta

from django.db.models import Count
from django.urls import reverse
from django.utils import timezone

from .models import McpToken, Report, Scan
from .services import _extract_tech_from_entry, mark_new_subdomains

logger = logging.getLogger(__name__)

SERVER_NAME = "scanx"
SERVER_VERSION = "1.0.0"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
LATEST_PROTOCOL_VERSION = "2025-06-18"

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
MAX_REPORT_CONTENT = 200_000   # characters of Markdown
MAX_REPORT_SUMMARY = 5_000
MAX_FINDINGS_BYTES = 200_000

INSTRUCTIONS = (
    "scanX holds reconnaissance results (subdomains, live hosts, HTTP status, page titles, "
    "technologies, IPs, CNAMEs) for ONE organization — the one this token was created for. "
    "Typical flow: get_organization → list_scans → get_scan → list_hosts / list_technologies / "
    "diff_scans → analyse → save_report. Reports you save appear on the scanX /reports page. "
    "Only analyse data returned by these tools; do not probe or attack hosts."
)


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

TOKEN_PREFIX = "sx_"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_token(program, label: str = "") -> tuple[McpToken, str]:
    """Create a token for `program`. Returns (record, plaintext) — plaintext is never stored."""
    plaintext = TOKEN_PREFIX + secrets.token_urlsafe(32)
    record = McpToken.objects.create(
        program=program,
        label=(label or "AI agent").strip()[:100] or "AI agent",
        token_hash=hash_token(plaintext),
        prefix=plaintext[:10],
    )
    return record, plaintext


def authenticate(header_value: str) -> McpToken | None:
    """Resolve an `Authorization` header to an active token, or None."""
    if not header_value or not header_value.startswith("Bearer "):
        return None
    plaintext = header_value[len("Bearer "):].strip()
    if not plaintext.startswith(TOKEN_PREFIX):
        return None
    token = (
        McpToken.objects.select_related("program")
        .filter(token_hash=hash_token(plaintext), revoked_at__isnull=True)
        .first()
    )
    if token:
        now = timezone.now()
        # Throttle the write: at most once a minute per token
        if not token.last_used_at or now - token.last_used_at > timedelta(minutes=1):
            McpToken.objects.filter(pk=token.pk).update(last_used_at=now)
    return token


# ---------------------------------------------------------------------------
# Envelope helpers
# ---------------------------------------------------------------------------

class ToolError(Exception):
    """Raised by a tool for an expected, user-facing failure."""


def _paginate(items: list, cursor, limit) -> tuple[list, dict]:
    try:
        offset = max(int(cursor or 0), 0)
    except (TypeError, ValueError):
        raise ToolError("cursor must be the nextCursor value from a previous call")
    try:
        limit = int(limit or DEFAULT_LIMIT)
    except (TypeError, ValueError):
        raise ToolError("limit must be a number")
    limit = min(max(limit, 1), MAX_LIMIT)
    page = items[offset:offset + limit]
    has_more = offset + limit < len(items)
    return page, {
        "total": len(items),
        "count": len(page),
        "hasMore": has_more,
        "nextCursor": str(offset + limit) if has_more else None,
    }


def _iso(dt):
    return dt.isoformat() if dt else None


def _abs(request, path: str) -> str:
    """Absolute URL when serving an HTTP request; site-relative path inside the worker."""
    return request.build_absolute_uri(path) if request is not None else path


def _scan_summary(scan: Scan) -> dict:
    return {
        "scan_id": str(scan.id),
        "domain": scan.domain,
        "status": scan.status,
        "created_at": _iso(scan.created_at),
        "started_at": _iso(scan.started_at),
        "completed_at": _iso(scan.completed_at),
        "duration_seconds": scan.duration_seconds,
        "total_subdomains": scan.total_subdomains,
        "live_subdomains": scan.live_subdomains,
        "http_success": scan.http_success,
        "http_failed": scan.http_failed,
        "error_message": scan.error_message or None,
    }


def _host(entry: dict) -> dict:
    cname = entry.get("cname") or []
    if isinstance(cname, str):
        cname = [cname] if cname else []
    return {
        "url": entry.get("url") or "",
        "status": entry.get("status"),
        "title": entry.get("title") or "",
        "technologies": _extract_tech_from_entry(entry),
        "ip": entry.get("ip") or "",
        "cname": cname,
    }


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

def _org_scans(token: McpToken):
    return Scan.objects.filter(program=token.program)


def _get_scan(token: McpToken, scan_id) -> Scan:
    if not scan_id:
        raise ToolError("scan_id is required")
    try:
        uid = uuid.UUID(str(scan_id))
    except ValueError:
        raise ToolError(f"scan_id {scan_id!r} is not a valid UUID. Call list_scans for valid ids.")
    scan = _org_scans(token).filter(id=uid).first()
    if not scan:
        raise ToolError(f"No scan {scan_id} in this organization. Call list_scans for valid ids.")
    return scan


def _completed_scan(token, scan_id) -> Scan:
    scan = _get_scan(token, scan_id)
    if scan.status != Scan.Status.COMPLETED:
        raise ToolError(
            f"Scan {scan_id} is {scan.status}, not completed; it has no host data. "
            "Pick a completed scan from list_scans(status='completed')."
        )
    return scan


def tool_get_organization(token, args, request):
    program = token.program
    # order_by() clears Scan.Meta.ordering, which would otherwise split the GROUP BY
    counts = dict(
        _org_scans(token).order_by().values("status").annotate(n=Count("id")).values_list("status", "n")
    )
    latest = (
        _org_scans(token).filter(status=Scan.Status.COMPLETED)
        .order_by("-completed_at").values_list("id", "domain").first()
    )
    domains = list(_org_scans(token).values_list("domain", flat=True).distinct().order_by("domain"))
    return {
        "id": program.id,
        "name": program.name,
        "type": program.get_organization_type_display(),
        "description": program.description,
        "scan_counts": {s: counts.get(s, 0) for s in Scan.Status.values},
        "domains": domains,
        "latest_completed_scan": {"scan_id": str(latest[0]), "domain": latest[1]} if latest else None,
    }, {}


def tool_list_scans(token, args, request):
    qs = _org_scans(token).defer("httpx_results").order_by("-created_at")
    status = args.get("status")
    if status:
        if status not in Scan.Status.values:
            raise ToolError(f"status must be one of {', '.join(Scan.Status.values)}")
        qs = qs.filter(status=status)
    if args.get("domain"):
        qs = qs.filter(domain__icontains=str(args["domain"]).strip().lower())
    scans = [_scan_summary(s) for s in qs]
    return _paginate(scans, args.get("cursor"), args.get("limit"))


def tool_get_scan(token, args, request):
    scan = _get_scan(token, args.get("scan_id"))
    results = scan.httpx_results or []
    status_counts = Counter(str(r.get("status") or "none") for r in results)
    tech_counts = Counter(t for r in results for t in _extract_tech_from_entry(r))
    data = _scan_summary(scan)
    data.update({
        "web_url": _abs(request, reverse("scanner:scan_detail", args=[scan.id])),
        "hosts_with_http_response": len(results),
        "status_code_counts": dict(status_counts.most_common()),
        "top_technologies": dict(tech_counts.most_common(25)),
        "unique_ips": len({r.get("ip") for r in results if r.get("ip")}),
    })
    return data, {}


def tool_list_hosts(token, args, request):
    scan = _completed_scan(token, args.get("scan_id"))
    entries = mark_new_subdomains(scan, [dict(r) for r in (scan.httpx_results or [])])
    hosts = []
    status = str(args.get("status") or "").strip()
    tech = str(args.get("technology") or "").strip().lower()
    ip = str(args.get("ip") or "").strip()
    new_only = bool(args.get("new_only"))
    for entry in entries:
        host = _host(entry)
        host["is_new"] = bool(entry.get("is_new"))
        if status and not str(host["status"] or "").startswith(status):
            continue
        if tech and not any(tech in t.lower() for t in host["technologies"]):
            continue
        if ip and ip not in host["ip"]:
            continue
        if new_only and not host["is_new"]:
            continue
        hosts.append(host)
    hosts.sort(key=lambda h: h["url"])
    return _paginate(hosts, args.get("cursor"), args.get("limit"))


def tool_search_hosts(token, args, request):
    query = str(args.get("query") or "").strip().lower()
    if not query:
        raise ToolError("query is required, e.g. 'admin', 'staging', 'login'")
    seen, hits = set(), []
    scans = _org_scans(token).filter(status=Scan.Status.COMPLETED).order_by("-completed_at")
    for scan in scans:
        for entry in scan.httpx_results or []:
            host = _host(entry)
            if host["url"] in seen:
                continue  # newest scan wins
            haystack = " ".join([host["url"], host["title"], " ".join(host["technologies"])]).lower()
            if query in haystack:
                seen.add(host["url"])
                host["scan_id"] = str(scan.id)
                host["scanned_at"] = _iso(scan.completed_at)
                hits.append(host)
    return _paginate(hits, args.get("cursor"), args.get("limit"))


def tool_list_technologies(token, args, request):
    if args.get("scan_id"):
        scans = [_completed_scan(token, args["scan_id"])]
    else:
        scans = list(_org_scans(token).filter(status=Scan.Status.COMPLETED).order_by("-completed_at"))
    hosts_by_tech: dict[str, set] = {}
    seen_urls = set()
    for scan in scans:
        for entry in scan.httpx_results or []:
            url = entry.get("url") or ""
            if url in seen_urls:
                continue
            seen_urls.add(url)
            for t in _extract_tech_from_entry(entry):
                hosts_by_tech.setdefault(t, set()).add(url)
    items = sorted(
        ({"technology": t, "hosts": len(u), "example_hosts": sorted(u)[:5]} for t, u in hosts_by_tech.items()),
        key=lambda x: (-x["hosts"], x["technology"].lower()),
    )
    return _paginate(items, args.get("cursor"), args.get("limit"))


def tool_diff_scans(token, args, request):
    scan = _completed_scan(token, args.get("scan_id"))
    if args.get("previous_scan_id"):
        prev = _completed_scan(token, args["previous_scan_id"])
    else:
        prev = (
            _org_scans(token)
            .filter(domain=scan.domain, status=Scan.Status.COMPLETED, created_at__lt=scan.created_at)
            .order_by("-created_at").first()
        )
        if not prev:
            raise ToolError(f"No earlier completed scan of {scan.domain} to compare with.")
    now = {h["url"]: h for h in map(_host, scan.httpx_results or [])}
    before = {h["url"]: h for h in map(_host, prev.httpx_results or [])}
    changed = [
        {"url": u, "status_before": before[u]["status"], "status_now": now[u]["status"]}
        for u in sorted(now.keys() & before.keys())
        if str(now[u]["status"]) != str(before[u]["status"])
    ]
    cap = 200
    return {
        "scan_id": str(scan.id),
        "previous_scan_id": str(prev.id),
        "added": [now[u] for u in sorted(now.keys() - before.keys())][:cap],
        "removed": sorted(before.keys() - now.keys())[:cap],
        "status_changed": changed[:cap],
        "counts": {
            "added": len(now.keys() - before.keys()),
            "removed": len(before.keys() - now.keys()),
            "status_changed": len(changed),
        },
    }, {}


def tool_list_reports(token, args, request):
    qs = Report.objects.filter(scan__program=token.program).select_related("scan").order_by("-created_at")
    if args.get("scan_id"):
        qs = qs.filter(scan_id=_get_scan(token, args["scan_id"]).id)
    items = [{
        "report_id": str(r.id),
        "title": r.title,
        "report_type": r.report_type,
        "scan_id": str(r.scan_id),
        "domain": r.scan.domain,
        "summary": r.summary,
        "created_at": _iso(r.created_at),
        "web_url": _abs(request, reverse("scanner:report_detail", args=[r.id])),
    } for r in qs]
    return _paginate(items, args.get("cursor"), args.get("limit"))


def tool_save_report(token, args, request):
    scan = _completed_scan(token, args.get("scan_id"))
    title = str(args.get("title") or "").strip()
    content = str(args.get("content") or "").strip()
    summary = str(args.get("summary") or "").strip()
    report_type = args.get("report_type") or Report.ReportType.ATTACK_VECTOR
    findings = args.get("findings")

    if not title:
        raise ToolError("title is required")
    if not content:
        raise ToolError("content (the Markdown report body) is required")
    if report_type not in Report.ReportType.values:
        raise ToolError(f"report_type must be one of {', '.join(Report.ReportType.values)}")
    if len(content) > MAX_REPORT_CONTENT:
        raise ToolError(f"content is too long ({len(content)} chars, max {MAX_REPORT_CONTENT})")
    if len(summary) > MAX_REPORT_SUMMARY:
        raise ToolError(f"summary is too long (max {MAX_REPORT_SUMMARY} chars)")
    if findings is not None:
        if not isinstance(findings, dict):
            raise ToolError("findings must be a JSON object")
        if len(json.dumps(findings)) > MAX_FINDINGS_BYTES:
            raise ToolError(f"findings is too large (max {MAX_FINDINGS_BYTES} bytes of JSON)")

    channel = getattr(token, "channel", Report.Source.MCP)  # set by the REST API view
    via = "REST API" if channel == Report.Source.API else "MCP"
    report = Report.objects.create(
        scan=scan,
        report_type=report_type,
        title=title[:255],
        summary=summary,
        content=content,
        findings=findings or {},
        status=Report.Status.COMPLETED,
        source=channel,
        generated_by=f"{token.label} ({via})"[:100],
        completed_at=timezone.now(),
    )
    logger.info("MCP token %s saved report %s for scan %s", token.prefix, report.id, scan.id)
    return {
        "report_id": str(report.id),
        "title": report.title,
        "web_url": _abs(request, reverse("scanner:report_detail", args=[report.id])),
    }, {"message": "Report saved. It is now listed on the scanX Reports page."}


# ---------------------------------------------------------------------------
# Tool registry (name → schema, annotations, handler)
# ---------------------------------------------------------------------------

_PAGING = {
    "cursor": {"type": "string", "description": "nextCursor from the previous page; omit for the first page"},
    "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT, "description": f"Page size (default {DEFAULT_LIMIT})"},
}
_SCAN_ID = {"type": "string", "description": "Scan UUID from list_scans"}
_READ = {"readOnlyHint": True, "openWorldHint": False}

TOOLS = {
    "get_organization": {
        "title": "Get organization",
        "description": (
            "Start here. Returns the organization this token belongs to: name, type, the domains it has "
            "scanned, scan counts by status and the latest completed scan id. "
            "When NOT to use: to list individual scans (use list_scans)."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": _READ,
        "handler": tool_get_organization,
    },
    "list_scans": {
        "title": "List scans",
        "description": (
            "List this organization's scans, newest first, with summary counts (subdomains found, live, "
            "HTTP 2xx/3xx vs other). Paginated. Only status='completed' scans have host data. "
            "When NOT to use: to read hosts of a scan (use list_hosts)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": list(Scan.Status.values)},
                "domain": {"type": "string", "description": "Filter by domain (substring)"},
                **_PAGING,
            },
            "additionalProperties": False,
        },
        "annotations": _READ,
        "handler": tool_list_scans,
    },
    "get_scan": {
        "title": "Get scan summary",
        "description": (
            "Summary of one scan: counts, status-code distribution, top technologies, unique IPs, any "
            "error, and its web page URL. Small output — no host list. "
            "When NOT to use: to see individual hosts (use list_hosts)."
        ),
        "inputSchema": {"type": "object", "properties": {"scan_id": _SCAN_ID}, "required": ["scan_id"], "additionalProperties": False},
        "annotations": _READ,
        "handler": tool_get_scan,
    },
    "list_hosts": {
        "title": "List hosts of a scan",
        "description": (
            "Live web hosts from a completed scan: url, HTTP status, page title, technologies, IP, CNAME "
            "and is_new (not seen in this domain's earlier scans). Filter by status prefix ('2', '403'), "
            "technology substring, IP or new_only. Paginated. "
            "When NOT to use: to search across all scans (use search_hosts)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": _SCAN_ID,
                "status": {"type": "string", "description": "HTTP status prefix, e.g. '2', '30', '403'"},
                "technology": {"type": "string", "description": "Technology substring, e.g. 'wordpress'"},
                "ip": {"type": "string"},
                "new_only": {"type": "boolean", "description": "Only hosts new since the previous scan"},
                **_PAGING,
            },
            "required": ["scan_id"],
            "additionalProperties": False,
        },
        "annotations": _READ,
        "handler": tool_list_hosts,
    },
    "search_hosts": {
        "title": "Search hosts",
        "description": (
            "Search every completed scan of this organization for hosts whose URL, title or technology "
            "contains the query (case-insensitive), e.g. 'admin', 'dev', 'login', 'jenkins'. Newest result "
            "per URL. Paginated. When NOT to use: to list one scan's hosts (use list_hosts)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}, **_PAGING},
            "required": ["query"],
            "additionalProperties": False,
        },
        "annotations": _READ,
        "handler": tool_search_hosts,
    },
    "list_technologies": {
        "title": "List technologies",
        "description": (
            "Technologies detected (web servers, frameworks, CMS, versions) with host counts and example "
            "hosts — for one scan, or across all completed scans when scan_id is omitted. Paginated."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"scan_id": {**_SCAN_ID, "description": "Optional scan UUID"}, **_PAGING},
            "additionalProperties": False,
        },
        "annotations": _READ,
        "handler": tool_list_technologies,
    },
    "diff_scans": {
        "title": "Compare two scans",
        "description": (
            "What changed between two completed scans of the same domain: hosts added, hosts removed and "
            "HTTP status changes. previous_scan_id defaults to the scan before scan_id. Lists are capped "
            "at 200; counts are exact."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"scan_id": _SCAN_ID, "previous_scan_id": {"type": "string"}},
            "required": ["scan_id"],
            "additionalProperties": False,
        },
        "annotations": _READ,
        "handler": tool_diff_scans,
    },
    "list_reports": {
        "title": "List reports",
        "description": (
            "Reports already saved for this organization (optionally one scan), with links. Check this "
            "before writing a new report to avoid duplicates. Paginated."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"scan_id": {**_SCAN_ID, "description": "Optional scan UUID"}, **_PAGING},
            "additionalProperties": False,
        },
        "annotations": _READ,
        "handler": tool_list_reports,
    },
    "save_report": {
        "title": "Save report",
        "description": (
            "Save your finished analysis of a completed scan. It appears on the scanX Reports page. "
            "content is Markdown (max 200,000 chars); summary is 1–3 plain sentences; findings is an "
            "optional JSON object, e.g. {\"attack_vectors\": [{\"name\", \"hosts\", \"severity\", "
            "\"evidence\", \"recommendation\"}]}. Base every claim on data from the other tools. "
            "When NOT to use: for drafts — each call creates a new report."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": _SCAN_ID,
                "title": {"type": "string", "maxLength": 255},
                "report_type": {"type": "string", "enum": list(Report.ReportType.values), "default": "attack_vector"},
                "summary": {"type": "string", "maxLength": MAX_REPORT_SUMMARY},
                "content": {"type": "string", "description": "Report body in Markdown"},
                "findings": {"type": "object", "description": "Optional structured findings"},
            },
            "required": ["scan_id", "title", "content"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
        "handler": tool_save_report,
    },
}


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

ATTACK_VECTOR_PROMPT = """Analyse the scanX reconnaissance data for {target} and map possible attack vectors.

1. Call get_organization, then pick the scan: {scan_hint}
2. Call get_scan, list_technologies(scan_id) and list_hosts(scan_id) (page through all results).
   Use diff_scans to see what is new, and search_hosts for terms like admin, login, dev, staging,
   test, api, vpn, jenkins, grafana, phpmyadmin.
3. Map attack vectors from the evidence only. Consider:
   - exposed admin / login / management panels and default-looking pages
   - development, staging or test hosts reachable from the internet
   - directory listings ("Index of /") and verbose error pages
   - outdated or version-disclosing technologies (name the version you saw)
   - hosts answering 401/403 that suggest protected but exposed services
   - CNAMEs to third-party services that may allow subdomain takeover
   - many services on one IP, or newly appeared hosts since the last scan
   Map each vector to a MITRE ATT&CK technique where it fits (e.g. T1190 Exploit Public-Facing
   Application, T1133 External Remote Services, T1078 Valid Accounts).
4. Rate each vector Critical / High / Medium / Low with a one-line reason. Do not invent
   vulnerabilities or CVEs you cannot tie to observed data; say "needs verification" instead.
5. Call save_report with report_type "attack_vector", a clear title, a 1–3 sentence summary,
   Markdown content (Executive summary, Attack surface overview, Attack vectors table,
   Recommendations, Methodology & limits) and findings {{"attack_vectors": [...]}}.
Do not scan, probe or contact the hosts yourself — analyse the scanX data only."""

PROMPTS = {
    "attack_vector_report": {
        "title": "Attack vector report",
        "description": "Analyse a scan, map possible attack vectors (with MITRE ATT&CK) and save a report to scanX.",
        "arguments": [
            {"name": "scan_id", "description": "Scan to analyse (default: latest completed scan)", "required": False},
        ],
    },
}


def _get_prompt(name, args, token):
    if name != "attack_vector_report":
        raise ToolError(f"Unknown prompt: {name}")
    scan_id = (args or {}).get("scan_id")
    text = ATTACK_VECTOR_PROMPT.format(
        target=token.program.name,
        scan_hint=f"scan {scan_id}." if scan_id else "the latest completed scan (from get_organization).",
    )
    return {
        "description": PROMPTS[name]["description"],
        "messages": [{"role": "user", "content": {"type": "text", "text": text}}],
    }


# ---------------------------------------------------------------------------
# JSON-RPC dispatch
# ---------------------------------------------------------------------------

def _tool_list():
    return [
        {
            "name": name,
            "title": spec["title"],
            "description": spec["description"],
            "inputSchema": spec["inputSchema"],
            "annotations": {"title": spec["title"], **spec["annotations"]},
        }
        for name, spec in TOOLS.items()
    ]


def run_tool(name, args, token, request, tools=None):
    """
    Run one scanX tool and return (envelope, is_error).

    Shared by all three ways of reaching the tools: the MCP endpoint, the
    plain REST API and the built-in AI agent, so they always behave the same.
    """
    spec = (tools or TOOLS).get(name)
    if not spec:
        return {"data": None, "meta": {"tool": name, "status": "error", "message": f"Unknown tool: {name}"}}, True
    if not isinstance(args, dict):
        return {"data": None, "meta": {"tool": name, "status": "error", "message": "arguments must be a JSON object"}}, True
    try:
        data, meta = spec["handler"](token, args, request)
        return {"data": data, "meta": {"tool": name, "status": "ok", **meta}}, False
    except ToolError as e:
        return {"data": None, "meta": {"tool": name, "status": "error", "message": str(e)}}, True
    except Exception:
        logger.exception("scanX tool %s failed", name)
        return {"data": None, "meta": {"tool": name, "status": "error",
                                       "message": "Internal error in scanX; try again or report it."}}, True


def _call_tool(token, params, request):
    name = params.get("name")
    args = params.get("arguments") or {}
    if name not in TOOLS:
        raise _RpcError(-32602, f"Unknown tool: {name}")
    if not isinstance(args, dict):
        raise _RpcError(-32602, "arguments must be an object")
    envelope, is_error = run_tool(name, args, token, request)
    return {
        "content": [{"type": "text", "text": json.dumps(envelope, default=str)}],
        "structuredContent": envelope,
        "isError": is_error,
    }


class _RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def _initialize(params):
    requested = (params or {}).get("protocolVersion")
    version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else LATEST_PROTOCOL_VERSION
    return {
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": False}, "prompts": {"listChanged": False}},
        "serverInfo": {"name": SERVER_NAME, "title": "scanX", "version": SERVER_VERSION},
        "instructions": INSTRUCTIONS,
    }


def handle_message(message, token, request):
    """
    Handle one JSON-RPC message. Returns a response dict, or None for
    notifications and client responses (which get no reply).
    """
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}

    method = message.get("method")
    msg_id = message.get("id")
    if method is None:  # a response from the client; nothing to do
        return None
    is_notification = "id" not in message
    params = message.get("params") or {}

    try:
        if method == "initialize":
            result = _initialize(params)
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": _tool_list()}
        elif method == "tools/call":
            result = _call_tool(token, params, request)
        elif method == "prompts/list":
            result = {"prompts": [{"name": n, **p} for n, p in PROMPTS.items()]}
        elif method == "prompts/get":
            try:
                result = _get_prompt(params.get("name"), params.get("arguments"), token)
            except ToolError as e:
                raise _RpcError(-32602, str(e))
        elif method.startswith("notifications/"):
            return None
        else:
            raise _RpcError(-32601, f"Method not found: {method}")
    except _RpcError as e:
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": e.code, "message": e.message}}

    if is_notification:
        return None
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}
