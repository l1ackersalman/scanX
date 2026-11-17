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

from .models import Scan, Program
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

    programs = Program.objects.all().order_by("-created_at")

    context = {
        "scans": scans,
        "programs": programs,
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

    # Link scan to a program if one was selected
    program_id = request.POST.get("program", "").strip()
    if program_id:
        try:
            scan.program = Program.objects.get(id=program_id)
            scan.save(update_fields=["program"])
        except Program.DoesNotExist:
            pass

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
             "tech": _normalize_tech(r.get("tech"))
            }
            for r in (scan.httpx_results or [])
        ],
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
            "is_terminal": status in ("completed", "failed"),
        }
    )


def scan_history(request):
    """
    Scan history page (can be same as dashboard or separate).
    """
    scans_list = Scan.objects.all()
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
    Programs page - shows all Programs with statistics.
    """
    programs_list = Program.objects.all().order_by('-created_at')

    programs_with_stats = []
    for program in programs_list:
        scans = Scan.objects.filter(program=program)
        total_subdomains = sum(s.total_subdomains or 0 for s in scans)
        live_subdomains = sum(s.live_subdomains or 0 for s in scans)
        http_success = sum(s.http_success or 0 for s in scans)
        completed_scans = scans.filter(status=Scan.Status.COMPLETED).count()
        last_completed = scans.filter(status=Scan.Status.COMPLETED).order_by('-completed_at').first()
        last_scanned = last_completed.completed_at if last_completed else None

        programs_with_stats.append({
            'scan': program,
            'total_subdomains': total_subdomains,
            'live_subdomains': live_subdomains,
            'http_success': http_success,
            'scan_count': scans.count(),
            'completed_scans': completed_scans,
            'last_scanned': last_scanned,
        })

    context = {
        'programs': programs_with_stats,
        'page_title': 'Programs',
    }
    return render(request, 'programs.html', context)


@require_http_methods(["GET", "POST"])
def create_program(request):
    """
    Create a new program from the Add Program page.
    """
    if request.method == "POST":
        title = request.POST.get("title", "").strip()
        name = request.POST.get("program_name", "").strip()
        description = request.POST.get("description", "").strip()
        platform = request.POST.get("program_platform", "").strip()
        program_type = request.POST.get("program_type", "").strip()

        errors = []
        if not title:
            errors.append("Title is required.")
        if not name:
            errors.append("Program name is required.")
        if not description:
            errors.append("Description is required.")
        if not platform:
            errors.append("Platform is required.")
        if not program_type:
            errors.append("Program type is required.")

        # Validate platform and program type against model choices
        valid_platforms = [c[0] for c in Program.Platform.choices]
        valid_types = [c[0] for c in Program.ProgramType.choices]
        if platform and platform not in valid_platforms:
            errors.append("Invalid platform selected.")
        if program_type and program_type not in valid_types:
            errors.append("Invalid program type selected.")

        if errors:
            for error in errors:
                messages.error(request, error)
            return redirect("scanner:programs_add")

        try:
            program, created = Program.objects.get_or_create(
                name=name,
                defaults={
                    "title": title,
                    "description": description,
                    "platform": platform,
                    "program_type": program_type,
                },
            )
            if created:
                messages.success(request, f"Program '{name}' created successfully.")
            else:
                messages.info(request, f"Program '{name}' already exists.")
        except Exception as e:
            messages.error(request, f"Failed to create program: {e}")

        return redirect("scanner:programs")

    # GET request - show the create program form
    return render(request, "programs_add.html")
