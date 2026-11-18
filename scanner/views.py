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
    program_id = request.POST.get("program", "").strip()

    # Validation
    errors = []
    if not domain:
        errors.append("Domain is required.")
    else:
        try:
            validate_domain(domain)
        except Exception as e:
            errors.append(str(e))

    if not program_id:
        errors.append("Program selection is required.")
    else:
        try:
            Program.objects.get(id=program_id)
        except Program.DoesNotExist:
            errors.append("Selected program does not exist.")

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

    # Link scan to the selected program (now required)
    scan.program = Program.objects.get(id=program_id)
    scan.save(update_fields=["program"])

    # Launch background scan
    run_scan_in_background(scan)
    messages.success(request, f"Scan started for {domain} (ID: {scan.id})")

    return redirect("scanner:scan_detail", scan_id=scan.id)


def scan_detail(request, scan_id):
    """
    Scan detail page: live logs, status, download links.
    """
    scan = get_object_or_404(Scan, id=scan_id)

    # Prepare and paginate HTTP results (50 per page)
    httpx_results_raw = scan.httpx_results or []
    httpx_results = [
        {**r,
         "status_class": get_status_class(r.get("status", "")),
         "tech": _normalize_tech(r.get("tech"))
        }
        for r in httpx_results_raw
    ]

    paginator = Paginator(httpx_results, 50)
    page_number = request.GET.get("page")
    httpx_page = paginator.get_page(page_number)

    context = {
        "scan": scan,
        "httpx_page": httpx_page,
        "httpx_results": httpx_page,
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


@require_http_methods(["GET", "POST"])
def edit_program(request, program_id):
    """
    Edit an existing program.
    """
    program = get_object_or_404(Program, id=program_id)

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
            return redirect("scanner:programs_edit", program_id=program.id)

        try:
            program.title = title
            program.name = name
            program.description = description
            program.platform = platform
            program.program_type = program_type
            program.save()
            messages.success(request, f"Program '{name}' updated successfully.")
        except Exception as e:
            messages.error(request, f"Failed to update program: {e}")

        return redirect("scanner:programs")

    context = {
        "program": program,
        "page_title": f"Edit Program — {program.name}",
    }
    return render(request, "programs_edit.html", context)


@require_http_methods(["POST"])
def delete_program(request, program_id):
    """
    Delete a program.
    """
    program = get_object_or_404(Program, id=program_id)
    program_name = program.name

    try:
        program.delete()
        messages.success(request, f"Program '{program_name}' deleted successfully.")
    except Exception as e:
        messages.error(request, f"Failed to delete program: {e}")

    return redirect("scanner:programs")


@require_http_methods(["GET"])
def program_detail(request, program_id):
    """
    Program detail page: shows all scans for a program with aggregate statistics.
    """
    program = get_object_or_404(Program, id=program_id)
    scans_qs = Scan.objects.filter(program=program).order_by("-created_at")

    # Scan-operation counts (count all scans, not deduplicated by domain)
    total_scans = scans_qs.count()
    completed_scans = scans_qs.filter(status=Scan.Status.COMPLETED).count()
    running_scans = scans_qs.filter(status=Scan.Status.RUNNING).count()
    failed_scans = scans_qs.filter(status=Scan.Status.FAILED).count()
    pending_scans = scans_qs.filter(status=Scan.Status.PENDING).count()
    cancelled_scans = scans_qs.filter(status=Scan.Status.CANCELLED).count()

    # Group scans by domain; for each domain take the MAX of each metric
    # so a domain scanned repeatedly is counted only once (at its peak).
    from collections import defaultdict

    domain_scans = defaultdict(list)
    for scan in scans_qs:
        domain_scans[scan.domain].append(scan)

    domain_stats = []
    for domain, scans in domain_scans.items():
        latest_scan = max(scans, key=lambda s: s.created_at)
        domain_stats.append(
            {
                "domain": domain,
                "latest_scan": latest_scan,
                "total_subdomains": max((s.total_subdomains or 0 for s in scans), default=0),
                "live_subdomains": max((s.live_subdomains or 0 for s in scans), default=0),
                "http_success": max((s.http_success or 0 for s in scans), default=0),
                "http_failed": max((s.http_failed or 0 for s in scans), default=0),
            }
        )

    # Sort by latest scan date descending
    domain_stats.sort(key=lambda d: d["latest_scan"].created_at, reverse=True)

    # Sum the per-domain maximums across unique domains
    total_subdomains = sum(d["total_subdomains"] for d in domain_stats)
    live_subdomains = sum(d["live_subdomains"] for d in domain_stats)
    http_success = sum(d["http_success"] for d in domain_stats)
    http_failed = sum(d["http_failed"] for d in domain_stats)

    last_completed = (
        scans_qs.filter(status=Scan.Status.COMPLETED)
        .order_by("-completed_at")
        .first()
    )
    last_scanned = last_completed.completed_at if last_completed else None

    # Pagination on unique domains (not individual scans)
    paginator = Paginator(domain_stats, 10)
    page_number = request.GET.get("page")
    domain_page = paginator.get_page(page_number)

    context = {
        "program": program,
        "domain_stats": domain_page,
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "running_scans": running_scans,
        "failed_scans": failed_scans,
        "pending_scans": pending_scans,
        "cancelled_scans": cancelled_scans,
        "total_subdomains": total_subdomains,
        "live_subdomains": live_subdomains,
        "http_success": http_success,
        "http_failed": http_failed,
        "last_scanned": last_scanned,
        "page_title": f"Program: {program.name}",
    }
    return render(request, "programs_detail.html", context)
