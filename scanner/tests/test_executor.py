"""
ScanExecutor tests using small stand-in scanner scripts (POSIX only).
"""
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import reverse

from scanner.models import Program, Report, Scan
from scanner.services import ScanExecutor, get_log_lines


def _script(dir_: Path, body: str) -> Path:
    path = dir_ / "fake_scanx.sh"
    path.write_text("#!/bin/bash\n" + body + "\n", encoding="utf-8", newline="\n")
    path.chmod(0o755)
    return path


@unittest.skipIf(sys.platform == "win32", "process groups are POSIX-only")
class ScanExecutorTests(TransactionTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.data = self.tmp / "data"
        self.data.mkdir()
        self.scan = Scan.objects.create(domain="example.com")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, body, timeout=60):
        with override_settings(
            SCANNER_SCRIPT_PATH=_script(self.tmp, body),
            SCANX_DATA_DIR=self.data,
            SCAN_TIMEOUT=timeout,
        ):
            ScanExecutor(self.scan).run()
        self.scan.refresh_from_db()

    def test_missing_tool_reason_in_error(self):
        self._run('echo "[*] starting"\necho "[!] Error: crt is not installed. Please install it first."\nexit 1')
        self.assertEqual(self.scan.status, Scan.Status.FAILED)
        self.assertIn("crt is not installed", self.scan.error_message)
        self.assertIn("exited with code 1", self.scan.error_message)

    def test_timeout_kills_silent_hung_tool(self):
        pidfile = self.tmp / "child.pid"
        start = time.monotonic()
        self._run(f"sleep 60 &\necho $! > {pidfile}\nwait", timeout=1)
        self.assertLess(time.monotonic() - start, 15)
        self.assertEqual(self.scan.status, Scan.Status.FAILED)
        self.assertIn("timed out", self.scan.error_message)
        child = int(pidfile.read_text())
        time.sleep(0.5)
        with self.assertRaises(ProcessLookupError):
            os.kill(child, 0)  # child tool was killed too

    def test_cancel_stops_silent_scan(self):
        def cancel_soon():
            time.sleep(1.5)
            Scan.objects.get(id=self.scan.id).mark_cancelled()

        t = threading.Thread(target=cancel_soon)
        t.start()
        start = time.monotonic()
        self._run("sleep 60")
        t.join()
        self.assertLess(time.monotonic() - start, 15)
        self.assertEqual(self.scan.status, Scan.Status.CANCELLED)

    def test_success_parses_output(self):
        self._run(
            'mkdir -p "$1" && cd "$1"\n'
            "printf 'a.example.com\\nb.example.com\\n' > alldomains.txt\n"
            "printf 'a.example.com\\n' > live.txt\n"
            'echo \'{"url":"https://a.example.com","status-code":200,"tech":["nginx"]}\' > httpx.json'
        )
        self.assertEqual(self.scan.status, Scan.Status.COMPLETED)
        self.assertEqual(self.scan.total_subdomains, 2)
        self.assertEqual(self.scan.live_subdomains, 1)
        self.assertEqual(self.scan.http_success, 1)

    def test_invalid_utf8_output_does_not_crash(self):
        self._run("printf 'bad \\xff byte\\n'\nexit 0")
        # No output dir -> failed, but not with a decode crash
        self.assertNotIn("UnicodeDecodeError", self.scan.error_message)


class LogAndEndpointTests(TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.scan = Scan.objects.create(domain="example.com", status=Scan.Status.CANCELLED)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_log_reader_handles_bad_offset_and_bytes(self):
        d = self.tmp / str(self.scan.id)
        d.mkdir()
        (d / "live.log").write_bytes(b"one\nt\xffwo\npartial")
        with override_settings(SCANX_DATA_DIR=self.tmp):
            lines, offset, _ = get_log_lines(str(self.scan.id), 10_000)
            self.assertEqual(lines, ["one", "t�wo"])
            self.assertEqual(offset, 9)
            lines, offset2, _ = get_log_lines(str(self.scan.id), offset)
            self.assertEqual((lines, offset2), ([], 9))

    def test_cancelled_scan_logs_are_terminal(self):
        res = self.client.get(reverse("scanner:scan_logs", args=[self.scan.id]))
        self.assertTrue(res.json()["is_terminal"])

    def test_mcp_status_no_login_redirect(self):
        res = self.client.get(reverse("scanner:mcp_http_status"))
        self.assertEqual(res.status_code, 200)
        self.assertIn("running", res.json())

    def test_mcp_start_rejects_remote(self):
        res = self.client.post(reverse("scanner:mcp_http_start"), REMOTE_ADDR="10.0.0.5")
        self.assertEqual(res.status_code, 403)

    def test_report_download_link_works_with_get(self):
        report = Report.objects.create(scan=self.scan, title="R")
        res = self.client.get(reverse("scanner:report_download", args=[report.id]))
        self.assertEqual(res.status_code, 200)
        self.assertIn("attachment", res["Content-Disposition"])
