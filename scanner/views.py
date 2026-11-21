"""
scanX Scanner Views

Dashboard, scan initiation, live logs, and scan history.
"""
import json
import logging
import socket
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    JsonResponse,
)
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt

from django.urls import reverse
from django.utils import timezone

import uuid

from . import ai_agent, mcp_http
from .models import McpToken, Scan, Program, Report
from .services import (
    get_log_lines,
    get_assets_overview,
    get_technology_breakdown,
    get_technology_subdomains,
    get_program_statistics,
    get_programs_with_stats,
    mark_new_subdomains,
)
from core.validators import normalize_domain, validate_domain

logger = logging.getLogger(__name__)


def get_status_class(status):
    """Return CSS class for HTTP status code badge."""
    if not status or str(status).strip() == "" or str(status).strip().upper() in ("N/A", "NONE", "NULL"):
        return "http-status-unreachable"  # white
    s = str(status)
    if s.startswith("2"):
        return "http-status-success"   # green
    elif s.startswith("3"):
        return "http-status-redirect"  # yellow/amber
    elif s == "403":
        return "http-status-forbidden" # orange
    elif s == "404":
        return "http-status-not-found" # red
    elif s.startswith("5"):
        return "http-status-server-error"  # purple
    elif s.startswith("4"):
        return "http-status-client-error"  # red for other 4xx
    return "http-status-unknown"


def _normalize_tech(tech):
    """Normalize tech field to a list of individual technology strings."""
    if tech is None:
        return []
    if isinstance(tech, list):
        return [t.strip() for t in tech if t and str(t).strip()]
    if isinstance(tech, str):
        tech = tech.strip()
        if not tech:
            return []
        return [t.strip() for t in tech.split(",") if t.strip()]
    return []


def dashboard(request):
    """
    Main dashboard: scan form + scan history.
    """
    if request.method == "POST":
        return start_scan(request)

    # GET: show dashboard with scan history
    scans_list = Scan.objects.all()
    paginator = Paginator(scans_list, 10)
    page_number = request.GET.get("page")
    scans = paginator.get_page(page_number)

    context = {
        "scans": scans,
        "page_title": "Dashboard",
        **_dashboard_form_context(),
    }
    return render(request, "dashboard.html", context)


def _dashboard_form_context() -> dict:
    """Shared context for the overview page (initial load and form errors)."""
    programs = list(Program.objects.all().order_by("-created_at"))
    return {
        "programs": programs,
        "recent_scans": Scan.objects.select_related("program")[:6],
        # Pre-select the only organization so the user doesn't have to
        "program_id": str(programs[0].id) if len(programs) == 1 else "",
    }


@require_http_methods(["POST"])
def start_scan(request):
    """
    Handle scan initiation from dashboard form.
    Validates input, creates Scan record, launches background worker.
    """
    domain = normalize_domain(request.POST.get("domain", ""))
    program_id = request.POST.get("program", "").strip()

    # Validation
    domain_error = ""
    program_error = ""
    
    if not domain:
        domain_error = "Domain is required."
    else:
        try:
            validate_domain(domain)
        except ValidationError as e:
            domain_error = " ".join(e.messages)

    if not program_id:
        program_error = "Please add organization before scan."
    else:
        try:
            Program.objects.get(id=program_id)
        except Program.DoesNotExist:
            program_error = "Selected program does not exist."

    if domain_error or program_error:
        context = {
            **_dashboard_form_context(),
            "domain": domain or request.POST.get("domain", "").strip(),
            "program_id": program_id,  # keep the user's selection
            "program_error": program_error,
            "domain_error": domain_error,
            "page_title": "Dashboard",
        }
        return render(request, "dashboard.html", context, status=400)

    # Create scan record (authorization fields removed from UI)
    scan = Scan.objects.create(
        domain=domain.lower(),
        authorized=False,
        authorized_by="",
    )

    # Link scan to the selected program (now required)
    scan.program = Program.objects.get(id=program_id)
    scan.save(update_fields=["program"])

    # Leave it PENDING: the separate worker process (manage.py worker) claims
    # and runs it. Running it here too made both execute the same scan.
    messages.success(request, f"Scan queued for {domain} (ID: {scan.id})")

    return redirect("scanner:scan_detail", scan_id=scan.id)


def scan_detail(request, scan_id):
    """
    Scan detail page: live logs, status, download links.
    """
    scan = get_object_or_404(Scan, id=scan_id)

    # Prepare raw HTTP results
    httpx_results_raw = scan.httpx_results or []
    httpx_results_all = [
        {**r,
         "status_class": get_status_class(r.get("status", "")),
         "tech": _normalize_tech(r.get("tech"))
        }
        for r in httpx_results_raw
    ]

    # Mark which subdomains are new compared to previous scans
    httpx_results_all = mark_new_subdomains(scan, httpx_results_all)

    # --- Filtering ---
    status_filter = request.GET.get("status", "").strip()
    tech_filter = request.GET.get("tech", "").strip()
    ip_filter = request.GET.get("ip", "").strip()
    cname_filter = request.GET.get("cname", "").strip()

    # Collect unique filter options from ALL results (unfiltered)
    all_statuses = sorted({str(r.get("status", "")) for r in httpx_results_all if str(r.get("status", ""))})
    all_technologies = sorted({t for r in httpx_results_all for t in r.get("tech", [])})
    all_ips = sorted({str(r.get("ip", "")) for r in httpx_results_all if str(r.get("ip", ""))})
    all_cnames = sorted({str(c) for r in httpx_results_all for c in (r.get("cname") or []) if str(c)})

    # Apply filters
    filtered_results = httpx_results_all

    if status_filter:
        filtered_results = [
            r for r in filtered_results
            if str(r.get("status", "")).startswith(status_filter)
        ]

    if tech_filter:
        filtered_results = [
            r for r in filtered_results
            if any(tech_filter.lower() in t.lower() for t in r.get("tech", []))
        ]

    if ip_filter:
        filtered_results = [
            r for r in filtered_results
            if ip_filter.lower() in str(r.get("ip", "")).lower()
        ]

    if cname_filter:
        filtered_results = [
            r for r in filtered_results
            if any(cname_filter.lower() in str(c).lower() for c in (r.get("cname") or []))
        ]

    # Pagination on filtered results
    paginator = Paginator(filtered_results, 50)
    page_number = request.GET.get("page")
    httpx_page = paginator.get_page(page_number)

    active_filters = {
        k: v for k, v in (
            ("status", status_filter), ("tech", tech_filter),
            ("ip", ip_filter), ("cname", cname_filter),
        ) if v
    }

    # Show what the scanner printed when a scan did not succeed
    final_log = ""
    if scan.status in (Scan.Status.FAILED, Scan.Status.CANCELLED):
        lines, _, _ = get_log_lines(str(scan.id), 0)
        final_log = "\n".join(lines[-200:])

    context = {
        "scan": scan,
        "httpx_page": httpx_page,
        "httpx_results": httpx_page,
        "total_results": len(httpx_results_all),
        "new_count": sum(1 for r in httpx_results_all if r.get("is_new")),
        "is_filtered": bool(active_filters),
        "filter_query": urlencode(active_filters),
        "final_log": final_log,
        "ai": ai_agent.availability(scan) if scan.status == Scan.Status.COMPLETED else None,
        "all_statuses": all_statuses,
        "all_technologies": all_technologies,
        "all_ips": all_ips,
        "all_cnames": all_cnames,
        "total_technologies": len(all_technologies),
        "current_status": status_filter,
        "current_tech": tech_filter,
        "current_ip": ip_filter,
        "current_cname": cname_filter,
        "page_title": f"Scan: {scan.domain}",
    }
    return render(request, "scan_detail.html", context)


@require_http_methods(["POST"])
def stop_scan(request, scan_id):
    """
    Stop a running scan.
    """
    scan = get_object_or_404(Scan, id=scan_id)
    if scan.status in (Scan.Status.RUNNING, Scan.Status.PENDING):
        scan.mark_cancelled()
        messages.success(request, f"Scan for {scan.domain} has been cancelled.")
    else:
        messages.error(request, f"Cannot cancel scan with status: {scan.get_status_display()}")
    return redirect("scanner:history")


def scan_logs(request, scan_id):
    """
    API endpoint for live log streaming.
    Returns JSON: {lines: [...], offset: int, status: str}
    Poll this endpoint every 1-2 seconds from frontend.
    """
    scan = get_object_or_404(Scan, id=scan_id)

    try:
        since = int(request.GET.get("since", "0"))
    except ValueError:
        since = 0

    lines, offset, status = get_log_lines(str(scan_id), since)

    return JsonResponse(
        {
            "lines": lines,
            "offset": offset,
            "status": status,
            "is_terminal": status in ("completed", "failed", "cancelled", "not_found"),
        }
    )


def scan_history(request):
    """
    Scan history page (can be same as dashboard or separate).
    """
    scans_list = Scan.objects.select_related("program")
    paginator = Paginator(scans_list, 10)
    page_number = request.GET.get("page")
    scans = paginator.get_page(page_number)

    context = {
        "scans": scans,
        "page_title": "Scan History",
    }
    return render(request, "history.html", context)

def programs(request):
    """
    Organizations page - shows all Organizations with statistics.
    """
    context = {
        "organizations": get_programs_with_stats(),
        "page_title": "Organizations",
    }
    return render(request, "programs.html", context)


@require_http_methods(["GET", "POST"])
def create_program(request):
    """
    Create a new organization from the Add Organization page.
    """
    if request.method == "POST":
        name = request.POST.get("program_name", "").strip()
        description = request.POST.get("description", "").strip()
        organization_type = request.POST.get("program_type", "").strip()

        errors = []
        if not name:
            errors.append("Organization name is required.")
        if not organization_type:
            errors.append("Organization type is required.")

        # Validate organization type against model choices
        valid_types = [c[0] for c in Program.OrganizationType.choices]
        if organization_type and organization_type not in valid_types:
            errors.append("Invalid organization type selected.")

        if errors:
            for error in errors:
                messages.error(request, error)
            return redirect("scanner:organizations_add")

        try:
            program, created = Program.objects.get_or_create(
                name=name,
                defaults={
                    "description": description,
                    "organization_type": organization_type,
                },
            )
            if created:
                messages.success(request, f"Organization '{name}' created successfully.")
            else:
                messages.info(request, f"Organization '{name}' already exists.")
        except Exception as e:
            messages.error(request, f"Failed to create organization: {e}")

        return redirect("scanner:organizations")

    # GET request - show the create organization form
    return render(request, "programs_add.html")


@require_http_methods(["GET", "POST"])
def edit_program(request, organization_id):
    """
    Edit an existing organization.
    """
    program = get_object_or_404(Program, id=organization_id)

    if request.method == "POST":
        name = request.POST.get("program_name", "").strip()
        description = request.POST.get("description", "").strip()
        organization_type = request.POST.get("program_type", "").strip()

        errors = []
        if not name:
            errors.append("Organization name is required.")
        if not organization_type:
            errors.append("Organization type is required.")

        # Validate organization type against model choices
        valid_types = [c[0] for c in Program.OrganizationType.choices]
        if organization_type and organization_type not in valid_types:
            errors.append("Invalid organization type selected.")

        if errors:
            for error in errors:
                messages.error(request, error)
            return redirect("scanner:organizations_edit", organization_id=program.id)

        try:
            program.name = name
            program.description = description
            program.organization_type = organization_type
            program.save()
            messages.success(request, f"Organization '{name}' updated successfully.")
        except Exception as e:
            messages.error(request, f"Failed to update organization: {e}")

        return redirect("scanner:organizations")

    context = {
        "program": program,
        "page_title": f"Edit Organization — {program.name}",
    }
    return render(request, "programs_edit.html", context)


@require_http_methods(["POST"])
def delete_program(request, organization_id):
    """
    Delete an organization.
    """
    program = get_object_or_404(Program, id=organization_id)
    program_name = program.name

    try:
        program.delete()
        messages.success(request, f"Organization '{program_name}' deleted successfully.")
    except Exception as e:
        messages.error(request, f"Failed to delete organization: {e}")

    return redirect("scanner:organizations")


@require_http_methods(["GET"])
def program_detail(request, organization_id):
    """
    Organization detail page: shows all scans for an organization with aggregate statistics.
    """
    program = get_object_or_404(Program, id=organization_id)

    # Aggregate stats from service layer
    stats = get_program_statistics(program)

    # Pagination on unique domains (not individual scans)
    paginator = Paginator(stats["domain_stats"], 10)
    page_number = request.GET.get("page")
    domain_page = paginator.get_page(page_number)

    context = {
        "program": program,
        "domain_stats": domain_page,
        "total_scans": stats["total_scans"],
        "total_targets": stats["total_targets"],
        "total_technologies": stats["total_technologies"],
        "completed_scans": stats["completed_scans"],
        "running_scans": stats["running_scans"],
        "failed_scans": stats["failed_scans"],
        "pending_scans": stats["pending_scans"],
        "cancelled_scans": stats["cancelled_scans"],
        "total_subdomains": stats["total_subdomains"],
        "live_subdomains": stats["live_subdomains"],
        "http_success": stats["http_success"],
        "http_failed": stats["http_failed"],
        "last_scanned": stats["last_scanned"],
        "page_title": f"Program: {program.name}",
    }
    return render(request, "programs_detail.html", context)


def assets(request):
    """
    Assets page — aggregate statistics across all programs and scans.
    """
    overview = get_assets_overview()

    tech_data = get_technology_breakdown(
        sort_by=request.GET.get("sort_by", "alpha"),
        search=request.GET.get("tech_search", "").strip(),
        page_number=request.GET.get("page"),
        per_page=50,
    )

    context = {
        **overview,
        "tech_page": tech_data["tech_page"],
        "tech_search": tech_data["search"],
        "sort_by": tech_data["sort_by"],
        "total_technologies": tech_data["total_technologies"],
        "page_title": "Assets",
    }
    return render(request, "assets.html", context)


def technology_detail(request):
    """
    Technology detail page — shows all subdomains using a specific technology,
    along with the program each subdomain belongs to.
    """
    technology = request.GET.get("tech", "").strip()

    if not technology:
        messages.warning(request, "No technology specified.")
        return redirect("scanner:assets")

    tech_data = get_technology_subdomains(
        technology=technology,
        page_number=request.GET.get("page"),
        per_page=50,
    )

    # Count distinct programs across matching subdomains
    distinct_programs = set()
    for item in tech_data["subdomain_page"].object_list:
        if item["program"]:
            distinct_programs.add(item["program"].id)

    context = {
        "technology": technology,
        "subdomain_page": tech_data["subdomain_page"],
        "total_subdomains": tech_data["total_subdomains"],
        "distinct_programs": len(distinct_programs),
        "page_title": f"Technology: {technology}",
    }
    return render(request, "technology_detail.html", context)


# =====================================================================
# Reports (MCP Analysis Reports)
# =====================================================================

def reports_list(request):
    """
    Reports listing page — shows all AI-generated analysis reports.
    """
    reports_list = Report.objects.select_related("scan", "scan__program").order_by("-created_at")
    paginator = Paginator(reports_list, 15)
    page_number = request.GET.get("page")
    reports = paginator.get_page(page_number)
    
    context = {
        "reports": reports,
        "page_title": "Reports",
        **_ai_picker_context(),
    }
    return render(request, "reports.html", context)


def _ai_picker_context() -> dict:
    """Context for the 'Generate AI report' scan picker (Reports and /mcp pages)."""
    return {
        "ai": ai_agent.availability(),
        "ai_scans": Scan.objects.filter(status=Scan.Status.COMPLETED, program__isnull=False)
        .select_related("program").defer("httpx_results").order_by("-completed_at")[:50],
    }


MCP_SESSION_TOKENS = "mcp_token_ids"   # tokens created in this browser
MCP_SESSION_NEW = "mcp_new_token"      # plaintext shown once after Connect


def mcp_guide(request):
    """
    /mcp — Connect an AI agent (PlayCanvas-style Connect panel) + user documentation.
    """
    my_ids = request.session.get(MCP_SESSION_TOKENS, [])
    new_token = request.session.pop(MCP_SESSION_NEW, None)  # shown once
    endpoint_url = request.build_absolute_uri(reverse("scanner:mcp_endpoint"))
    context = {
        "page_title": "MCP",
        "programs": Program.objects.order_by("name"),
        "endpoint_url": endpoint_url,
        "new_token": new_token,
        "my_connections": McpToken.objects.filter(id__in=my_ids).select_related("program"),
        "tools": mcp_http.TOOLS,
        "prompts": mcp_http.PROMPTS,
        "server_name": mcp_http.SERVER_NAME,
        "api_base": request.build_absolute_uri("/api/v1/"),
        **_ai_picker_context(),
    }
    return render(request, "mcp_guide.html", context)


@require_http_methods(["POST"])
def mcp_connect(request):
    """Create an organization-scoped MCP token (the Connect button)."""
    program = Program.objects.filter(id=request.POST.get("program") or 0).first()
    if not program:
        messages.error(request, "Choose the organization your AI agent should analyse.")
        return redirect(reverse("scanner:mcp_guide") + "#connect")

    token, plaintext = mcp_http.create_token(program, request.POST.get("label", ""))
    ids = request.session.get(MCP_SESSION_TOKENS, [])
    request.session[MCP_SESSION_TOKENS] = (ids + [token.id])[-50:]
    request.session[MCP_SESSION_NEW] = {
        "id": token.id,
        "token": plaintext,
        "program": program.name,
        "label": token.label,
    }
    return redirect(reverse("scanner:mcp_guide") + "#connect")


@require_http_methods(["POST"])
def mcp_revoke(request, token_id):
    """Disconnect: revoke a token created from this browser."""
    if token_id not in request.session.get(MCP_SESSION_TOKENS, []):
        messages.error(request, "You can only disconnect agents you connected from this browser.")
        return redirect(reverse("scanner:mcp_guide") + "#connections")
    McpToken.objects.filter(id=token_id, revoked_at__isnull=True).update(revoked_at=timezone.now())
    messages.success(request, "Agent disconnected. Its token no longer works.")
    return redirect(reverse("scanner:mcp_guide") + "#connections")


# =====================================================================
# REST API — the same tools for agents and scripts that don't speak MCP
# =====================================================================

def _api_error(status, message):
    response = JsonResponse({"data": None, "meta": {"status": "error", "message": message}}, status=status)
    if status == 401:
        response["WWW-Authenticate"] = 'Bearer realm="scanx-api"'
    return response


def _api_token(request):
    token = mcp_http.authenticate(request.headers.get("Authorization", ""))
    if token:
        token.channel = Report.Source.API  # reports saved through the API are labelled as such
    return token


@require_http_methods(["GET"])
def api_tools(request):
    """GET /api/v1/tools — tool list with JSON Schemas (drop-in for function calling)."""
    if not _api_token(request):
        return _api_error(401, "Missing or invalid token. Create one with the Connect button on /mcp.")
    tools = [
        {
            "name": name,
            "description": spec["description"],
            "read_only": bool(spec["annotations"].get("readOnlyHint")),
            "input_schema": spec["inputSchema"],
            "url": request.build_absolute_uri(reverse("scanner:api_tool_call", args=[name])),
        }
        for name, spec in mcp_http.TOOLS.items()
    ]
    return JsonResponse({"data": tools, "meta": {"status": "ok", "count": len(tools)}})


@csrf_exempt  # bearer-token auth, not cookies
@require_http_methods(["POST"])
def api_tool_call(request, name):
    """POST /api/v1/tools/<name> — run one tool; JSON body = the tool's arguments."""
    token = _api_token(request)
    if not token:
        return _api_error(401, "Missing or invalid token. Create one with the Connect button on /mcp.")
    if name not in mcp_http.TOOLS:
        return _api_error(404, f"Unknown tool {name!r}. GET /api/v1/tools lists them.")
    try:
        args = json.loads(request.body or b"{}")
    except (ValueError, UnicodeDecodeError):
        return _api_error(400, "Body must be a JSON object with the tool's arguments.")
    envelope, is_error = mcp_http.run_tool(name, args, token, request)
    return JsonResponse(envelope, status=422 if is_error else 200)


@require_http_methods(["GET"])
def api_openapi(request):
    """GET /api/v1/openapi.json — OpenAPI 3.1 spec of the tools (public, no data)."""
    base = request.build_absolute_uri("/").rstrip("/")
    paths = {}
    for name, spec in mcp_http.TOOLS.items():
        paths[f"/api/v1/tools/{name}"] = {
            "post": {
                "operationId": name,
                "summary": spec["title"],
                "description": spec["description"],
                "requestBody": {"required": True, "content": {"application/json": {"schema": spec["inputSchema"]}}},
                "responses": {
                    "200": {"description": "Envelope {data, meta}"},
                    "401": {"description": "Missing or invalid token"},
                    "422": {"description": "Tool error; see meta.message"},
                },
            }
        }
    return JsonResponse({
        "openapi": "3.1.0",
        "info": {"title": "scanX analysis API", "version": mcp_http.SERVER_VERSION,
                 "description": mcp_http.INSTRUCTIONS},
        "servers": [{"url": base}],
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
        "security": [{"bearer": []}],
        "paths": paths,
    })


# =====================================================================
# Built-in AI ("Generate AI report") — runs on this server
# =====================================================================

@require_http_methods(["POST"])
def ai_report_create(request):
    scan_id = request.POST.get("scan")
    scan = Scan.objects.select_related("program").filter(id=scan_id).first() if _is_uuid(scan_id) else None
    back = request.POST.get("next") or reverse("scanner:reports")
    if not back.startswith("/"):
        back = reverse("scanner:reports")
    if not scan:
        messages.error(request, "Choose a completed scan to analyse.")
        return redirect(back)

    info = ai_agent.availability(scan)
    if not info["ok"]:
        recent = info.get("recent_report")
        if recent:
            messages.info(request, "An AI report for this scan was just requested — showing it.")
            return redirect("scanner:report_detail", report_id=recent.id)
        messages.error(request, info["reason"])
        return redirect(back)

    report = ai_agent.queue_report(scan)
    return redirect("scanner:report_detail", report_id=report.id)


def _is_uuid(value) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, TypeError):
        return False


@require_http_methods(["GET"])
def report_status(request, report_id):
    """Small JSON poll endpoint used by the report page while the AI writes."""
    report = get_object_or_404(Report, id=report_id)
    return JsonResponse({"status": report.status})


@csrf_exempt  # authenticated by bearer token, not cookies
def mcp_endpoint(request):
    """
    MCP Streamable HTTP endpoint. JSON-RPC 2.0 over POST, JSON responses.
    GET is not offered (no server-initiated stream), per the MCP spec.
    """
    if request.method != "POST":
        response = JsonResponse(
            {"error": "This is an MCP endpoint. Connect an MCP client to it; see /mcp."}, status=405
        )
        response["Allow"] = "POST"
        return response

    token = mcp_http.authenticate(request.headers.get("Authorization", ""))
    if not token:
        response = JsonResponse(
            {"jsonrpc": "2.0", "id": None, "error": {
                "code": -32001,
                "message": "Missing or invalid token. Create one with the Connect button on /mcp.",
            }},
            status=401,
        )
        response["WWW-Authenticate"] = 'Bearer realm="scanx-mcp"'
        return response

    try:
        payload = json.loads(request.body or b"null")
    except (ValueError, UnicodeDecodeError):
        return JsonResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}, status=400
        )

    if isinstance(payload, list):  # JSON-RPC batch (older protocol versions)
        replies = [r for r in (mcp_http.handle_message(m, token, request) for m in payload) if r]
        return JsonResponse(replies, safe=False) if replies else HttpResponse(status=202)

    reply = mcp_http.handle_message(payload, token, request)
    if reply is None:  # notification or client response
        return HttpResponse(status=202)
    return JsonResponse(reply)


def report_detail(request, report_id):
    """
    Report detail page — view a single AI-generated report.
    """
    report = get_object_or_404(Report, id=report_id)
    
    context = {
        "report": report,
        "page_title": f"Report: {report.title}",
        # Pretty JSON, auto-escaped by the template (json_script rendered nothing visible)
        "findings_json": json.dumps(report.findings, indent=2, ensure_ascii=False) if report.findings else "",
    }
    return render(request, "report_detail.html", context)


@require_http_methods(["GET"])
def report_download(request, report_id):
    """
    Download a report as Markdown file.
    """
    report = get_object_or_404(Report, id=report_id)
    
    # Create markdown content
    md_content = f"""# {report.title}

**Report Type:** {report.get_report_type_display()}
**Scan:** {report.scan.domain}
**Organization:** {report.scan.program.name if report.scan.program else 'N/A'}
**Scan Date:** {report.scan.completed_at.strftime('%Y-%m-%d %H:%M') if report.scan.completed_at else 'N/A'}
**Generated By:** {report.generated_by}
**Generated At:** {report.created_at.strftime('%Y-%m-%d %H:%M:%S')}

---

## Summary

{report.summary}

---

## Findings

{report.content}

---

## Structured Findings

```json
{json.dumps(report.findings, indent=2) if report.findings else '{}'}
```
"""
    
    response = HttpResponse(md_content, content_type="text/markdown")
    filename = f"scanx-report-{report.id}.md"
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response

# =====================================================================
# MCP HTTP Server Management
# =====================================================================

def _is_local_request(request) -> bool:
    return request.META.get("REMOTE_ADDR") in ("127.0.0.1", "::1")


@require_http_methods(["GET"])
def mcp_http_status(request):
    """Check if MCP HTTP server is running on port 8001"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', 8001))
        sock.close()
        running = result == 0
    except Exception:
        running = False

    # Get VPS IP for external connection
    vps_ip = getattr(settings, 'MCP_VPS_IP', None)
    if not vps_ip:
        # Try to detect external IP
        try:
            vps_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            vps_ip = 'your-vps-ip'

    return JsonResponse({
        'running': running,
        'url': f'http://{vps_ip}:8001/mcp' if running else None,
        'port': 8001,
    })


@require_http_methods(["POST"])
def mcp_http_start(request):
    """Start MCP HTTP server in background (only from the local machine)."""
    # The app has no login system, so the old @login_required just 404'd.
    # Spawning a network-facing server must not be open to remote visitors.
    if not _is_local_request(request):
        return JsonResponse(
            {"status": "error", "message": "MCP server can only be started from localhost."},
            status=403,
        )
    try:
        # Check if already running
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', 8001))
        sock.close()
        if result == 0:
            return JsonResponse({'status': 'already_running', 'message': 'MCP HTTP server is already running'})

        # Start server in background
        subprocess.Popen([
            sys.executable, 'manage.py', 'mcp_server_http',
            '--host', '0.0.0.0',
            '--port', '8001'
        ], cwd=settings.BASE_DIR, start_new_session=True)

        return JsonResponse({'status': 'starting', 'message': 'MCP HTTP server starting...'})
    except Exception as e:
        logger.exception("Failed to start MCP HTTP server")
        return JsonResponse({'status': 'error', 'message': 'Failed to start MCP server; see server log.'}, status=500)
