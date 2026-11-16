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

from django.conf import settings
from django.utils import timezone

from .models import Scan

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