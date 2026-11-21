"""
scanX Worker Command

Background worker process that polls for pending scans and executes them.
Run as a separate process: python manage.py worker

This satisfies the Phase 1 requirement: "Use a separate worker process for
long-running scans. Do not run the scanner directly inside a normal Django
HTTP request."
"""
import logging
import signal
import sys
import threading
import time

from django.core.management.base import BaseCommand
from django.db import transaction
from django.db.models import F

from scanner.models import Scan
from scanner.services import ScanExecutor

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Run background scan worker (polls for pending scans)"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.running = True
        self.current_executor = None

    def add_arguments(self, parser):
        parser.add_argument(
            "--interval",
            type=int,
            default=2,
            help="Polling interval in seconds (default: 2)",
        )
        parser.add_argument(
            "--once",
            action="store_true",
            help="Process one scan and exit",
        )
        parser.add_argument(
            "--max-scans",
            type=int,
            default=0,
            help="Maximum scans to process (0 = unlimited)",
        )

    def handle(self, *args, **options):
        interval = options["interval"]
        once = options["once"]
        max_scans = options["max_scans"]
        scans_processed = 0

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self.stdout.write(self.style.SUCCESS("Starting scan worker..."))
        self.stdout.write(f"Polling interval: {interval}s")
        if once:
            self.stdout.write("Mode: single scan")
        if max_scans:
            self.stdout.write(f"Max scans: {max_scans}")

        self._recover_interrupted_scans()
        self._start_ai_thread(interval)

        try:
            while self.running:
                # Check for pending scans
                scan = self._claim_pending_scan()

                if scan:
                    self.stdout.write(
                        f"Processing scan {scan.id} for {scan.domain}"
                    )
                    self.current_executor = ScanExecutor(scan)
                    self.current_executor.run()
                    scans_processed += 1

                    if once or (max_scans and scans_processed >= max_scans):
                        break
                else:
                    # No pending scans, wait before polling again
                    if self.running:
                        time.sleep(interval)

        except KeyboardInterrupt:
            self.stdout.write("\nShutting down...")
        finally:
            self.stdout.write(self.style.SUCCESS(f"Worker stopped. Scans processed: {scans_processed}"))

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        self.stdout.write(f"\nReceived signal {signum}, shutting down...")
        self.running = False
        if self.current_executor:
            self.current_executor.stop()

    def _start_ai_thread(self, interval: int) -> None:
        """
        Built-in AI reports run in their own thread so a long scan never
        blocks them (and vice versa). One report at a time.
        """
        from django.db import connection
        from scanner import ai_agent

        ai_agent.recover_interrupted()

        def loop():
            while self.running:
                try:
                    worked = ai_agent.process_next_report()
                except Exception:
                    logger.exception("AI report loop error")
                    worked = False
                finally:
                    connection.close()  # this thread's DB connection
                if not worked:
                    time.sleep(interval)

        threading.Thread(target=loop, name="ai-reports", daemon=True).start()
        self.stdout.write("AI report thread started")

    def _recover_interrupted_scans(self) -> None:
        """
        A scan still RUNNING when the worker starts was orphaned by a crash or
        restart (only one worker runs scans). Fail it so it doesn't spin forever.
        """
        from django.utils import timezone
        count = Scan.objects.filter(status=Scan.Status.RUNNING).update(
            status=Scan.Status.FAILED,
            completed_at=timezone.now(),
            error_message="Scan interrupted: worker was restarted before it finished",
        )
        if count:
            self.stdout.write(self.style.WARNING(f"Marked {count} interrupted scan(s) as failed"))

    def _claim_pending_scan(self) -> Scan | None:
        """
        Atomically claim a pending scan using SELECT FOR UPDATE SKIP LOCKED.
        This prevents multiple workers from picking up the same scan.
        """
        try:
            with transaction.atomic():
                # Lock the row and skip if another transaction has it locked
                scan = (
                    Scan.objects.select_for_update(skip_locked=True)
                    .filter(status=Scan.Status.PENDING)
                    .order_by("created_at")
                    .first()
                )

                if scan:
                    # Mark as running immediately to prevent other workers from claiming
                    from django.utils import timezone
                    scan.status = Scan.Status.RUNNING
                    scan.started_at = timezone.now()
                    scan.save(update_fields=["status", "started_at"])
                    return scan
        except Exception as e:
            logger.error(f"Error claiming scan: {e}")

        return None