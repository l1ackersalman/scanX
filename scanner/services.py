"""
scanX Scanner Services

Core logic for executing the Bash scanner, streaming logs, and managing scan lifecycle.
"""
import os
import subprocess
import threading
import time
import json
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict

from django.conf import settings
from django.utils import timezone
from django.core.paginator import Paginator

from .models import Scan, Program

logger = logging.getLogger(__name__)


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
                    tech_raw = entry.get("tech-detect") or entry.get("tech") or entry.get("technologies") or entry.get("tech_detect") or entry.get("technology") or entry.get("webserver") or entry.get("server") or entry.get("http-server")
                    tech_list = []
                    if isinstance(tech_raw, list):
                        tech_list = [str(t).strip() for t in tech_raw if str(t).strip()]
                    elif isinstance(tech_raw, dict):
                        tech_list = [f"{k}:{v}" if v else k for k, v in tech_raw.items() if k]
                    elif isinstance(tech_raw, str) and tech_raw.strip():
                        tech_list = [t.strip() for t in tech_raw.split(",") if t.strip()]
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
        """Find the subdirectory created by scanx.sh inside cwd."""
        # The script creates a directory named after the domain (or domain-XX)
        for item in cwd.iterdir():
            if item.is_dir() and item.name.startswith(self.scan.domain.replace(".", "-")):
                return item
            # Also check for exact domain match
            if item.is_dir() and item.name == self.scan.domain:
                return item
        return None

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
        log_file = open(self.log_file_path, "a", buffering=1)

        try:
            logger.info(f"Executing: {' '.join(cmd)} in {cwd}")

            # Start process with pipes for stdout/stderr
            self.process = subprocess.Popen(
                cmd,
                cwd=str(cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Merge stderr into stdout
                text=True,
                bufsize=1,  # Line buffered
                env=env,
            )

            # Stream output to log file in real-time
            assert self.process.stdout is not None
            for line in self.process.stdout:
                if self._stop_event.is_set():
                    self.process.terminate()
                    break
                # Check if scan was cancelled via web interface
                self.scan.refresh_from_db()
                if self.scan.status == Scan.Status.CANCELLED:
                    self.process.terminate()
                    break
                log_file.write(line)
                log_file.flush()

            # Wait for completion with timeout
            try:
                returncode = self.process.wait(timeout=settings.SCAN_TIMEOUT)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                error = f"Scan timed out after {settings.SCAN_TIMEOUT} seconds"
                logger.error(error)
                log_file.write(f"\n[ERROR] {error}\n")
                self.scan.mark_failed(error)
                return

            log_file.close()

            # Check if scan was cancelled via web interface
            self.scan.refresh_from_db()
            if self.scan.status == Scan.Status.CANCELLED:
                logger.info(f"Scan {self.scan.id} was cancelled")
                return

            if returncode == 0:
                # Success - find script output dir and parse stats
                script_out_dir = self._find_script_output_dir(cwd)
                if script_out_dir:
                    stats = self._parse_statistics(script_out_dir)
                    httpx_results = self._parse_httpx_results(script_out_dir)
                    stats["httpx_results"] = httpx_results
                    self.scan.mark_completed(**stats)
                    logger.info(f"Scan {self.scan.id} completed successfully")
                else:
                    error = "Scan completed but output directory not found"
                    logger.error(error)
                    self.scan.mark_failed(error)
            else:
                error = f"Scanner exited with code {returncode}"
                logger.error(error)
                self.scan.mark_failed(error)

        except Exception as e:
            error = f"Scan execution failed: {type(e).__name__}: {e}"
            logger.exception(error)
            if not self.scan.is_terminal:
                self.scan.mark_failed(error)
        finally:
            if not log_file.closed:
                log_file.close()

    def stop(self):
        """Request graceful stop of the running scan."""
        self._stop_event.set()
        if self.process and self.process.poll() is None:
            self.process.terminate()
            # Give it a moment to terminate gracefully
            time.sleep(2)
            if self.process.poll() is None:
                self.process.kill()


def run_scan_in_background(scan: Scan) -> threading.Thread:
    """
    Run a scan in a background thread.
    Returns the thread object for monitoring.
    """
    executor = ScanExecutor(scan)
    thread = threading.Thread(target=executor.run, daemon=True)
    thread.start()
    return thread


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
        with open(log_path, "r") as f:
            f.seek(since_offset)
            lines = f.readlines()
            new_offset = f.tell()
        return [line.rstrip("\n") for line in lines], new_offset, scan.status
    except Exception as e:
        logger.error(f"Failed to read log for {scan_id}: {e}")
        return [], since_offset, scan.status


def get_scan_artifacts(scan: Scan) -> dict[str, Path]:
    """
    Get paths to scan artifact files if they exist.
    Returns dict of artifact_name -> Path.
    """
    artifacts = {}
    if not scan.output_dir:
        return artifacts

    # The script creates a subdirectory named after the domain
    base = settings.SCANX_DATA_DIR / scan.output_dir
    script_out_dir = None
    for item in base.iterdir():
        if item.is_dir() and (item.name == scan.domain or item.name.startswith(scan.domain.replace(".", "-"))):
            script_out_dir = item
            break

    if not script_out_dir:
        return artifacts

    artifact_files = {
        "alldomains.txt": "alldomains.txt",
        "live.txt": "live.txt",
        "httpx.json": "httpx.json",
        "report.txt": "report.txt",  # This is in parent dir per script
    }

    for name, filename in artifact_files.items():
        path = script_out_dir / filename
        if path.exists():
            artifacts[name] = path

    # Also check for report.txt in parent (script writes to ../report.txt)
    parent_report = base / "report.txt"
    if parent_report.exists():
        artifacts["report.txt"] = parent_report

    return artifacts


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

    total_scans = Scan.objects.count()
    completed_scans = Scan.objects.filter(status=Scan.Status.COMPLETED).count()
    running_scans = Scan.objects.filter(status=Scan.Status.RUNNING).count()
    failed_scans = Scan.objects.filter(status=Scan.Status.FAILED).count()
    pending_scans = Scan.objects.filter(status=Scan.Status.PENDING).count()
    cancelled_scans = Scan.objects.filter(status=Scan.Status.CANCELLED).count()

    total_targets = Scan.objects.values("domain").distinct().count()

    total_subdomains = sum(s.total_subdomains or 0 for s in Scan.objects.all())
    live_subdomains = sum(s.live_subdomains or 0 for s in Scan.objects.all())
    http_success = sum(s.http_success or 0 for s in Scan.objects.all())
    http_failed = sum(s.http_failed or 0 for s in Scan.objects.all())

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
    programs_list = Program.objects.all().order_by("-created_at")
    results = []
    for program in programs_list:
        stats = get_program_statistics(program)
        results.append(
            {
                "scan": program,
                "total_subdomains": stats["total_subdomains"],
                "live_subdomains": stats["live_subdomains"],
                "http_success": stats["http_success"],
                "scan_count": stats["total_scans"],
                "completed_scans": stats["completed_scans"],
                "last_scanned": stats["last_scanned"],
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