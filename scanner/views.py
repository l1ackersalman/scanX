"""
scanX Scanner Views

Dashboard, scan initiation, live logs, and scan history.
"""
import json
import logging
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    JsonResponse,
)
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt

from .models import Scan
from .services import (
    get_log_lines,
    run_scan_in_background,
)
from core.validators import validate_domain

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
    }
    return render(request, "dashboard.html", context)


@require_http_methods(["POST"])
def start_scan(request):
    """
    Handle scan initiation from dashboard form.
    Validates input, creates Scan record, launches background worker.
    """
    domain = request.POST.get("domain", "").strip()

    # Validation
    errors = []
    if not domain:
        errors.append("Domain is required.")
    else:
        try:
            validate_domain(domain)
        except Exception as e:
            errors.append(str(e))

    if errors:
        for error in errors:
            messages.error(request, error)
        return redirect("scanner:dashboard")

    # Create scan record (authorization fields removed from UI)
    scan = Scan.objects.create(
        domain=domain.lower(),
        authorized=False,
        authorized_by="",
    )

    # Launch background scan
    run_scan_in_background(scan)
    messages.success(request, f"Scan started for {domain} (ID: {scan.id})")

    return redirect("scanner:scan_detail", scan_id=scan.id)


def scan_detail(request, scan_id):
    """
    Scan detail page: live logs, status, download links.
    """
    scan = get_object_or_404(Scan, id=scan_id)

    context = {
        "scan": scan,
        "httpx_results": [
            {**r,
             "status_class": get_status_class(r.get("status", "")),
             "tech": r.get("tech", []) if isinstance(r.get("tech"), list)
                     else [r.get("tech")] if r.get("tech")
                     else []
            }
            for r in (scan.httpx_results or [])
        ],
        "page_title": f"Scan: {scan.domain}",
    }
    return render(request, "scan_detail.html", context)


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
            "is_terminal": status in ("completed", "failed"),
        }
    )


def scan_history(request):
    """
    Scan history page (can be same as dashboard or separate).
    """
    scans_list = Scan.objects.all()
    paginator = Paginator(scans_list, 50)
    page_number = request.GET.get("page")
    scans = paginator.get_page(page_number)

    context = {
        "scans": scans,
        "page_title": "Scan History",
    }
    return render(request, "history.html", context)