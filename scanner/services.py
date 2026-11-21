"""
scanX Scanner Services

Core logic for executing the Bash scanner, streaming logs, and managing scan lifecycle.
"""
import os
import re
import signal
import subprocess
import threading
import time
import json
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict, deque

from django.conf import settings
from django.db import connection
from django.db.models import Count, Q, Sum
from django.utils import timezone
from django.core.paginator import Paginator

from .models import Scan, Program

logger = logging.getLogger(__name__)

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class ScanExecutor:
    """
    Executes the scanx.sh script in a controlled environment,
    captures output, streams logs, and updates the Scan model.
    """

    def __init__(self, scan: Scan):
        self.scan = scan
        self.process: subprocess.Popen | None = None
        self.log_file_path: Path | None = None
        self._stop_event = threading.Event()

    def _prepare_environment(self) -> dict:
        """Prepare environment variables for the scanner subprocess."""
        env = os.environ.copy()

        # Add TOOLS_PATH to PATH if configured
        if settings.TOOLS_PATH:
            env["PATH"] = f"{settings.TOOLS_PATH}:{env.get('PATH', '')}"

        # Inject Chaos API key
        if settings.CHAOS_API_KEY:
            env["CHAOS_API_KEY"] = settings.CHAOS_API_KEY

        # Ensure script can find figlet and other tools
        env["HOME"] = str(Path.home())

        return env

    def _prepare_scan_directory(self) -> Path:
        """
        Create isolated scan directory.
        Returns the directory where scanx.sh will run (cwd).
        The script creates its own subdirectory inside this.
        """
        scan_dir = settings.SCANX_DATA_DIR / str(self.scan.id)
        scan_dir.mkdir(parents=True, exist_ok=True)

        # Log file for live streaming (in scan_dir, not in script's subdir)
        self.log_file_path = scan_dir / "live.log"
        return scan_dir

    def _parse_statistics(self, scan_subdir: Path) -> dict:
        """Parse statistics from scan output files."""
        import json
        stats = {}
        try:
            # alldomains.txt - total unique subdomains
            alldomains = scan_subdir / "alldomains.txt"
            if alldomains.exists():
                stats["total_subdomains"] = len(alldomains.read_text().strip().splitlines())

            # live.txt - live subdomains
            live = scan_subdir / "live.txt"
            if live.exists():
                stats["live_subdomains"] = len(live.read_text().strip().splitlines())

            # httpx.json - HTTP results (JSON lines)
            httpx = scan_subdir / "httpx.json"
            if httpx.exists():
                success = 0
                failed = 0
                for line in httpx.read_text().strip().splitlines():
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                        status = str(entry.get("status-code", entry.get("status_code", "")))
                        if status.startswith("2") or status.startswith("3"):
                            success += 1
                        else:
                            failed += 1
                    except json.JSONDecodeError:
                        if "SUCCESS" in line:
                            success += 1
                        elif "FAILED" in line:
                            failed += 1
                stats["http_success"] = success
                stats["http_failed"] = failed
        except Exception as e:
            logger.warning(f"Failed to parse statistics: {e}")
        return stats

    def _parse_httpx_results(self, scan_subdir: Path) -> list[dict]:
        """Parse httpx.json into a list of result dicts for display."""
        import json
        results = []
        try:
            httpx = scan_subdir / "httpx.json"
            if not httpx.exists():
                return results
            for line in httpx.read_text().strip().splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    tech_list = _extract_tech_from_entry(entry)  # one parser for the whole app
                    # Get IP from host_ip, ip, or first element of 'a' array
                    ip_val = entry.get("host_ip") or entry.get("ip") or (entry.get("a", [""])[0] if entry.get("a") else "")
                    results.append({
                        "url": entry.get("url", ""),
                        "status": entry.get("status-code", entry.get("status_code", "N/A")),
                        "title": entry.get("title", ""),
                        "tech": tech_list,
                        "ip": ip_val,
                        "cname": entry.get("cname", ""),
                    })
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            logger.warning(f"Failed to parse httpx results: {e}")
        return results

    def _find_script_output_dir(self, cwd: Path) -> Path | None:
        """The folder scanx.sh creates in this scan's private cwd: named after the domain."""
        out = cwd / self.scan.domain
        return out if out.is_dir() else None

    def _kill_process_group(self) -> None:
        """
        Terminate the scanner and every tool it spawned (subfinder, httpx, ...).
        The process runs in its own session, so its pgid == its pid.
        """
        proc = self.process
        if not proc or proc.poll() is not None:
            return
        for sig, grace in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
            try:
                os.killpg(proc.pid, sig)
            except ProcessLookupError:
                return
            try:
                proc.wait(timeout=grace)
                return
            except subprocess.TimeoutExpired:
                continue

    def _monitor(self) -> None:
        """
        Watchdog thread: enforces SCAN_TIMEOUT and reacts to cancellation
        even when the scanner produces no output (e.g. a hung tool).
        """
        deadline = time.monotonic() + settings.SCAN_TIMEOUT
        last_db_check = 0.0
        try:
            while self.process and self.process.poll() is None:
                now = time.monotonic()
                if self._stop_event.is_set():
                    self._kill_process_group()
                    return
                if now >= deadline:
                    self._timed_out = True
                    self._kill_process_group()
                    return
                if now - last_db_check >= 2:
                    last_db_check = now
                    status = (
                        Scan.objects.filter(id=self.scan.id)
                        .values_list("status", flat=True)
                        .first()
                    )
                    if status == Scan.Status.CANCELLED:
                        self._cancelled = True
                        self._kill_process_group()
                        return
                time.sleep(0.5)
        except Exception:
            logger.exception("Scan monitor failed; killing scanner")
            self._kill_process_group()
        finally:
            connection.close()

    @staticmethod
    def _failure_reason(tail) -> str:
        """Pick the most useful line from the end of the scanner output."""
        lines = [ANSI_RE.sub("", l).strip() for l in tail]
        lines = [l for l in lines if l]
        for line in reversed(lines):
            if line.startswith(("[!]", "[✘]")) or "error" in line.lower():
                return line
        return lines[-1] if lines else ""

    def run(self) -> None:
        """
        Main entry point: execute the scan.
        Updates Scan model status and streams output to log file.
        """
        logger.info(f"Starting scan {self.scan.id} for {self.scan.domain}")

        # Prepare
        cwd = self._prepare_scan_directory()
        env = self._prepare_environment()

        # Update scan with output directory (relative to SCANX_DATA_DIR)
        self.scan.output_dir = str(self.scan.id)
        self.scan.mark_running(output_dir=str(self.scan.id))

        # Script path
        script_path = settings.SCANNER_SCRIPT_PATH
        if not script_path.exists():
            error = f"Scanner script not found at {script_path}"
            logger.error(error)
            self.scan.mark_failed(error)
            return

        # Command: [script, domain] - no shell=True
        cmd = [str(script_path), self.scan.domain]

        # Open log file for writing (append mode, line buffered)
        log_file = open(self.log_file_path, "a", buffering=1, encoding="utf-8")
        self._timed_out = False
        self._cancelled = False
        tail = deque(maxlen=20)

        try:
            logger.info(f"Executing: {' '.join(cmd)} in {cwd}")

            # Own session so cancel/timeout can kill the whole tool tree
            self.process = subprocess.Popen(
                cmd,
                cwd=str(cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Merge stderr into stdout
                text=True,
                encoding="utf-8",
                errors="replace",  # tool output is not guaranteed UTF-8
                bufsize=1,  # Line buffered
                env=env,
                start_new_session=True,
            )

            monitor = threading.Thread(target=self._monitor, daemon=True)
            monitor.start()

            # Stream output to log file in real-time
            assert self.process.stdout is not None
            for line in self.process.stdout:
                log_file.write(line)
                tail.append(line)

            returncode = self.process.wait()
            monitor.join(timeout=15)

            if self._timed_out:
                error = f"Scan timed out after {settings.SCAN_TIMEOUT} seconds"
                logger.error(error)
                log_file.write(f"\n[ERROR] {error}\n")
                self.scan.mark_failed(error)
                return

            # Check if scan was cancelled via web interface
            self.scan.refresh_from_db()
            if self._cancelled or self.scan.status == Scan.Status.CANCELLED:
                log_file.write("\n[!] Scan cancelled by user\n")
                logger.info(f"Scan {self.scan.id} was cancelled")
                return

            if self._stop_event.is_set():
                self.scan.mark_failed("Scan interrupted: worker shutting down")
                return

            if returncode == 0:
                # Success - find script output dir and parse stats
                script_out_dir = self._find_script_output_dir(cwd)
                if script_out_dir:
                    stats = self._parse_statistics(script_out_dir)
                    httpx_results = self._parse_httpx_results(script_out_dir)
                    stats["httpx_results"] = httpx_results
                    # scanx.sh hides tool errors, so a broken step still exits 0.
                    # Live hosts but no HTTP output means httpx did not run.
                    httpx_file = script_out_dir / "httpx.json"
                    if (stats.get("live_subdomains") or 0) > 0 and (
                        not httpx_file.exists() or httpx_file.stat().st_size == 0
                    ):
                        stats["error_message"] = (
                            "Warning: httpx produced no output although live hosts were found, "
                            "so HTTP results are missing. Check that httpx is installed "
                            "(python manage.py check_tools) and scan again."
                        )
                    self.scan.mark_completed(**stats)
                    logger.info(f"Scan {self.scan.id} completed successfully")
                else:
                    error = "Scan completed but output directory not found"
                    logger.error(error)
                    self.scan.mark_failed(error)
            else:
                error = f"Scanner exited with code {returncode}"
                reason = self._failure_reason(tail)
                if reason:
                    error = f"{error}: {reason}"
                logger.error(error)
                self.scan.mark_failed(error)

        except Exception as e:
            error = f"Scan execution failed: {type(e).__name__}: {e}"
            logger.exception(error)
            self._kill_process_group()
            self.scan.refresh_from_db()
            if not self.scan.is_terminal:
                self.scan.mark_failed(error)
        finally:
            if not log_file.closed:
                log_file.close()

    def stop(self):
        """Request graceful stop of the running scan (and its child tools)."""
        self._stop_event.set()
        self._kill_process_group()


# Files a user may download for a scan: published name → (folder, file, description).
# A fixed list, so a crafted URL can never reach any other file on the server.
SCAN_DOWNLOADS = {
    "subdomains.txt": ("domain", "alldomains.txt", "All subdomains found"),
    "live.txt": ("domain", "live.txt", "Subdomains that resolve (live)"),
    "httpx.json": ("domain", "httpx.json", "HTTP results: status, title, tech, IP, CNAME (JSON lines)"),
    "scanner-output.log": ("scan", "live.log", "Full scanner output"),
}


def get_scan_files(scan: Scan) -> list[dict]:
    """Downloadable files that exist for this scan: [{name, description, path, size}]."""
    base = settings.SCANX_DATA_DIR / str(scan.id)
    folders = {"scan": base, "domain": base / scan.domain}
    files = []
    for name, (folder, filename, description) in SCAN_DOWNLOADS.items():
        path = folders[folder] / filename
        if path.is_file():
            files.append({"name": name, "description": description, "path": path, "size": path.stat().st_size})
    return files


def get_log_lines(scan_id: str, since_offset: int = 0) -> tuple[list[str], int, str]:
    """
    Read log lines from a scan's live.log file.
    Returns (lines, new_offset, status).
    """
    from django.conf import settings

    scan = Scan.objects.filter(id=scan_id).first()
    if not scan:
        return [], since_offset, "not_found"

    log_path = settings.SCANX_DATA_DIR / scan_id / "live.log"
    if not log_path.exists():
        return [], since_offset, scan.status

    try:
        # Binary mode: offsets are plain byte positions, so a bogus `since`
        # value can't wedge the reader on a half-decoded character.
        with open(log_path, "rb") as f:
            size = f.seek(0, os.SEEK_END)
            if since_offset < 0 or since_offset > size:
                since_offset = 0
            f.seek(since_offset)
            data = f.read()
        # Only hand out complete lines; a partial last line comes next poll.
        end = data.rfind(b"\n") + 1
        text = data[:end].decode("utf-8", errors="replace")
        return text.splitlines(), since_offset + end, scan.status
    except Exception as e:
        logger.error(f"Failed to read log for {scan_id}: {e}")
        return [], since_offset, scan.status


# ---------------------------------------------------------------------------
# Aggregation helpers (moved out of views to keep views thin)
# ---------------------------------------------------------------------------

def _extract_tech_from_entry(entry: dict) -> list[str]:
    """Extract technology strings from a single httpx result entry."""
    tech_raw = (
        entry.get("tech-detect")
        or entry.get("tech")
        or entry.get("technologies")
        or entry.get("tech_detect")
        or entry.get("technology")
        or entry.get("webserver")
        or entry.get("server")
        or entry.get("http-server")
    )
    if not tech_raw:
        return []
    if isinstance(tech_raw, list):
        return [str(t).strip() for t in tech_raw if str(t).strip()]
    if isinstance(tech_raw, dict):
        return [str(k).strip() for k in tech_raw if str(k).strip()]
    if isinstance(tech_raw, str) and tech_raw.strip():
        return [t.strip() for t in tech_raw.split(",") if t.strip()]
    return []


def get_program_statistics(program: Program) -> dict:
    """
    Return aggregate statistics for a single Program.

    Includes scan counts by status, per-domain deduplicated metrics,
    and a sorted list of domain stats for the program detail page.
    """
    scans_qs = Scan.objects.filter(program=program).order_by("-created_at")

    # Scan-operation counts
    total_scans = scans_qs.count()
    total_targets = scans_qs.values("domain").distinct().count()
    completed_scans = scans_qs.filter(status=Scan.Status.COMPLETED).count()
    running_scans = scans_qs.filter(status=Scan.Status.RUNNING).count()
    failed_scans = scans_qs.filter(status=Scan.Status.FAILED).count()
    pending_scans = scans_qs.filter(status=Scan.Status.PENDING).count()
    cancelled_scans = scans_qs.filter(status=Scan.Status.CANCELLED).count()

    # Group scans by domain; take MAX of each metric per domain
    domain_scans: dict[str, list[Scan]] = defaultdict(list)
    for scan in scans_qs:
        domain_scans[scan.domain].append(scan)

    domain_stats = []
    all_technologies: set[str] = set()
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

        for scan in scans:
            for r in scan.httpx_results or []:
                for tech in _extract_tech_from_entry(r):
                    all_technologies.add(tech)

    domain_stats.sort(key=lambda d: d["latest_scan"].created_at, reverse=True)

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

    return {
        "program": program,
        "domain_stats": domain_stats,
        "total_scans": total_scans,
        "total_targets": total_targets,
        "completed_scans": completed_scans,
        "running_scans": running_scans,
        "failed_scans": failed_scans,
        "pending_scans": pending_scans,
        "cancelled_scans": cancelled_scans,
        "total_subdomains": total_subdomains,
        "live_subdomains": live_subdomains,
        "http_success": http_success,
        "http_failed": http_failed,
        "total_technologies": len(all_technologies),
        "last_scanned": last_scanned,
    }


def get_assets_overview() -> dict:
    """
    Return aggregate statistics across all programs and scans
    for the Assets overview page.
    """
    total_programs = Program.objects.count()

    # One aggregate query instead of loading every scan (and its JSON results) 4 times
    counts = Scan.objects.aggregate(
        total_scans=Count("id"),
        completed_scans=Count("id", filter=Q(status=Scan.Status.COMPLETED)),
        running_scans=Count("id", filter=Q(status=Scan.Status.RUNNING)),
        failed_scans=Count("id", filter=Q(status=Scan.Status.FAILED)),
        pending_scans=Count("id", filter=Q(status=Scan.Status.PENDING)),
        cancelled_scans=Count("id", filter=Q(status=Scan.Status.CANCELLED)),
        total_targets=Count("domain", distinct=True),
        total_subdomains=Sum("total_subdomains"),
        live_subdomains=Sum("live_subdomains"),
        http_success=Sum("http_success"),
        http_failed=Sum("http_failed"),
    )
    total_scans = counts["total_scans"]
    completed_scans = counts["completed_scans"]
    running_scans = counts["running_scans"]
    failed_scans = counts["failed_scans"]
    pending_scans = counts["pending_scans"]
    cancelled_scans = counts["cancelled_scans"]
    total_targets = counts["total_targets"]
    total_subdomains = counts["total_subdomains"] or 0
    live_subdomains = counts["live_subdomains"] or 0
    http_success = counts["http_success"] or 0
    http_failed = counts["http_failed"] or 0

    return {
        "total_programs": total_programs,
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "running_scans": running_scans,
        "failed_scans": failed_scans,
        "pending_scans": pending_scans,
        "cancelled_scans": cancelled_scans,
        "total_targets": total_targets,
        "total_subdomains": total_subdomains,
        "live_subdomains": live_subdomains,
        "http_success": http_success,
        "http_failed": http_failed,
    }


def get_technology_breakdown(
    sort_by: str = "alpha",
    search: str = "",
    page_number: int | None = None,
    per_page: int = 50,
) -> dict:
    """
    Return paginated technology breakdown across all scans.

    Each item is (technology_name, subdomain_count, target_count).
    Results are sorted alphabetically by default, or by subdomain count
    descending when sort_by == "count". Optional case-insensitive search
    filters by technology name.
    """
    tech_subdomains: dict[str, set[str]] = defaultdict(set)
    tech_targets: dict[str, set[str]] = defaultdict(set)

    for scan in Scan.objects.all():
        domain = scan.domain
        for r in scan.httpx_results or []:
            subdomain = r.get("url") or domain
            for tech in _extract_tech_from_entry(r):
                tech_subdomains[tech].add(subdomain)
                tech_targets[tech].add(domain)

    # Build sorted list
    if sort_by == "count":
        tech_list = sorted(
            [(tech, len(subs), len(tech_targets[tech])) for tech, subs in tech_subdomains.items()],
            key=lambda x: x[1],
            reverse=True,
        )
    else:
        tech_list = sorted(
            [(tech, len(subs), len(tech_targets[tech])) for tech, subs in tech_subdomains.items()],
            key=lambda x: x[0].lower(),
        )

    # Apply search filter
    if search:
        search_lower = search.lower()
        tech_list = [
            (tech, subs, targets)
            for tech, subs, targets in tech_list
            if search_lower in tech.lower()
        ]

    # Paginate
    paginator = Paginator(tech_list, per_page)
    page = paginator.get_page(page_number)

    return {
        "tech_page": page,
        "total_technologies": len(tech_list),
        "sort_by": sort_by,
        "search": search,
    }


def get_programs_with_stats() -> list[dict]:
    """
    Return all programs with aggregate statistics for the programs listing page.
    """
    # Two queries in total (was ~8 per organization, plus every scan's JSON).
    # Same numbers as get_program_statistics: per-domain MAX, summed per program.
    rows = Scan.objects.filter(program__isnull=False).values(
        "program_id", "domain", "status", "completed_at",
        "total_subdomains", "live_subdomains", "http_success",
    )
    per_program: dict[int, dict] = defaultdict(lambda: {
        "domains": defaultdict(lambda: [0, 0, 0]), "scans": 0, "completed": 0, "last": None,
    })
    for r in rows:
        p = per_program[r["program_id"]]
        p["scans"] += 1
        d = p["domains"][r["domain"]]
        d[0] = max(d[0], r["total_subdomains"] or 0)
        d[1] = max(d[1], r["live_subdomains"] or 0)
        d[2] = max(d[2], r["http_success"] or 0)
        if r["status"] == Scan.Status.COMPLETED:
            p["completed"] += 1
            if r["completed_at"] and (p["last"] is None or r["completed_at"] > p["last"]):
                p["last"] = r["completed_at"]

    results = []
    for program in Program.objects.all().order_by("-created_at"):
        p = per_program.get(program.id)
        domains = p["domains"].values() if p else []
        results.append(
            {
                "scan": program,
                "total_subdomains": sum(d[0] for d in domains),
                "live_subdomains": sum(d[1] for d in domains),
                "http_success": sum(d[2] for d in domains),
                "scan_count": p["scans"] if p else 0,
                "completed_scans": p["completed"] if p else 0,
                "last_scanned": p["last"] if p else None,
            }
        )
    return results


def get_technology_subdomains(
    technology: str,
    page_number: int | None = None,
    per_page: int = 50,
) -> dict:
    """
    Return paginated list of subdomains using a specific technology,
    along with the program each subdomain belongs to.

    Each item is a dict with keys:
      - subdomain: the URL/subdomain string
      - program: the Program object (or None)
      - scan: the Scan object where this tech was found
      - status_code: the HTTP status code from the matching httpx result
    """
    from django.core.paginator import Paginator

    matching = []
    seen_subdomains: set[str] = set()

    for scan in Scan.objects.all().select_related("program"):
        for r in scan.httpx_results or []:
            subdomain = r.get("url") or scan.domain
            for tech in _extract_tech_from_entry(r):
                if tech == technology and subdomain not in seen_subdomains:
                    seen_subdomains.add(subdomain)
                    matching.append(
                        {
                            "subdomain": subdomain,
                            "program": scan.program,
                            "scan": scan,
                            "status_code": str(
                                r.get("status-code")
                                or r.get("status_code")
                                or r.get("status")
                                or r.get("statusCode")
                                or "N/A"
                            ),
                        }
                    )
                    break

    # Sort by subdomain name alphabetically
    matching.sort(key=lambda x: x["subdomain"].lower())

    # Paginate
    paginator = Paginator(matching, per_page)
    page = paginator.get_page(page_number)

    return {
        "technology": technology,
        "subdomain_page": page,
        "total_subdomains": len(matching),
        # Across ALL matches, not just the current page
        "distinct_programs": len({m["program"].id for m in matching if m["program"]}),
        "sort_by": "alpha",
    }


def get_previous_scan_urls(scan: Scan) -> set[str]:
    """
    Return a set of all subdomain URLs from previous completed scans
    of the same domain (excluding the current scan).
    """
    previous_urls: set[str] = set()

    previous_scans = (
        Scan.objects.filter(domain=scan.domain, status=Scan.Status.COMPLETED)
        .exclude(id=scan.id)
    )

    for prev_scan in previous_scans:
        for r in prev_scan.httpx_results or []:
            url = r.get("url") or prev_scan.domain
            if url:
                previous_urls.add(url)

    return previous_urls


def mark_new_subdomains(scan: Scan, httpx_results: list[dict]) -> list[dict]:
    """
    Mark each httpx result with an `is_new` boolean indicating whether
    the subdomain URL was seen in any previous completed scan of the
    same domain.
    """
    previous_urls = get_previous_scan_urls(scan)

    for r in httpx_results:
        url = r.get("url") or scan.domain
        r["is_new"] = url not in previous_urls

    return httpx_results