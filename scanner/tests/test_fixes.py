"""Regression tests for bugs fixed during the test-fix loop."""
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import reverse

from scanner.models import Program, Scan
from scanner.services import (
    ScanExecutor,
    get_assets_overview,
    get_program_statistics,
    get_programs_with_stats,
    get_technology_subdomains,
)


class QueueLimitTests(TestCase):
    @override_settings(SCAN_QUEUE_LIMIT=2)
    def test_full_queue_rejects_new_scan(self):
        p = Program.objects.create(name="Acme")
        for i in range(2):
            Scan.objects.create(domain=f"q{i}.test", program=p, status=Scan.Status.PENDING)
        res = self.client.post(reverse("scanner:start_scan"), {"domain": "new.test", "program": p.id})
        self.assertEqual(res.status_code, 429)
        self.assertContains(res, "scan queue is full", status_code=429)
        self.assertFalse(Scan.objects.filter(domain="new.test").exists())


class ScanDownloadTests(TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.scan = Scan.objects.create(domain="a.test", status=Scan.Status.COMPLETED,
                                        program=Program.objects.create(name="P"))
        out = self.tmp / str(self.scan.id) / "a.test"
        out.mkdir(parents=True)
        (out / "alldomains.txt").write_text("a.test\nb.a.test\n")
        (out / "httpx.json").write_text('{"url": "https://a.test"}\n')
        (self.tmp / str(self.scan.id) / "live.log").write_text("[✔] done\n")
        self.settings_ctx = override_settings(SCANX_DATA_DIR=self.tmp)
        self.settings_ctx.enable()

    def tearDown(self):
        self.settings_ctx.disable()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_page_lists_existing_files_only(self):
        res = self.client.get(reverse("scanner:scan_detail", args=[self.scan.id]))
        self.assertContains(res, "subdomains.txt")
        self.assertContains(res, "httpx.json")
        self.assertNotContains(res, ">live.txt<")  # not produced by this scan

    def test_download_file(self):
        res = self.client.get(reverse("scanner:scan_download", args=[self.scan.id, "subdomains.txt"]))
        self.assertEqual(res.status_code, 200)
        self.assertIn("attachment", res["Content-Disposition"])
        self.assertEqual(b"".join(res.streaming_content), b"a.test\nb.a.test\n")

    def test_only_listed_files_can_be_downloaded(self):
        for name in ("alldomains.txt", "settings.py", "..", "live.log", ".secret_key"):
            res = self.client.get(f"/scan/{self.scan.id}/download/{name}")
            self.assertEqual(res.status_code, 404, name)
        self.assertEqual(self.client.get(f"/scan/{self.scan.id}/download/..%2F..%2Fdb.sqlite3").status_code, 404)

    def test_zip_contains_all_files(self):
        import io
        import zipfile
        res = self.client.get(reverse("scanner:scan_download_all", args=[self.scan.id]))
        self.assertEqual(res.status_code, 200)
        names = zipfile.ZipFile(io.BytesIO(b"".join(res.streaming_content))).namelist()
        self.assertEqual(sorted(names), ["a.test/httpx.json", "a.test/scanner-output.log", "a.test/subdomains.txt"])


class ReportMarkdownTests(TestCase):
    def test_markdown_renders_and_is_sanitized(self):
        from scanner.templatetags.report_markdown import render_markdown
        html = str(render_markdown(
            "## Vectors\n\n| Host | Risk |\n|---|---|\n| a.test | **High** |\n\n"
            "<script>alert(1)</script>\n\n[x](javascript:alert(1)) <img src=x onerror=alert(1)>\n\n"
            "[ok](https://example.test)"
        ))
        self.assertIn("<h2>Vectors</h2>", html)
        self.assertIn("<table>", html)
        self.assertIn("<strong>High</strong>", html)
        self.assertNotIn("<script", html)
        self.assertNotIn("javascript:", html)
        self.assertNotIn("onerror", html)
        self.assertNotIn("<img", html)
        self.assertIn('href="https://example.test"', html)
        self.assertIn('rel="noopener noreferrer nofollow"', html)

    def test_report_page_renders_markdown(self):
        from scanner.models import Report
        p = Program.objects.create(name="Acme")
        scan = Scan.objects.create(domain="a.test", program=p, status=Scan.Status.COMPLETED)
        report = Report.objects.create(scan=scan, title="R", status=Report.Status.COMPLETED,
                                       content="## Findings\n\n- one")
        res = self.client.get(reverse("scanner:report_detail", args=[report.id]))
        self.assertContains(res, "<h2>Findings</h2>", html=False)
        self.assertNotContains(res, "## Findings")


class ProbeFindingTests(TestCase):
    """Bugs found by feeding the running app odd input (round 2)."""

    def setUp(self):
        self.p = Program.objects.create(name="Acme")

    def test_non_numeric_program_id_is_a_form_error_not_500(self):
        res = self.client.post(reverse("scanner:start_scan"), {"domain": "example.com", "program": "abc"})
        self.assertEqual(res.status_code, 400)
        self.assertContains(res, "does not exist", status_code=400)

    def test_mcp_connect_non_numeric_program(self):
        res = self.client.post(reverse("scanner:mcp_connect"), {"program": "abc"})
        self.assertEqual(res.status_code, 302)

    def test_control_characters_do_not_change_the_target(self):
        from core.validators import normalize_domain
        self.assertEqual(normalize_domain("example.com\nfoo"), "example.com\nfoo")  # left for the validator
        res = self.client.post(reverse("scanner:start_scan"), {"domain": "example.com\nfoo", "program": self.p.id})
        self.assertEqual(res.status_code, 400)
        self.assertFalse(Scan.objects.exists())

    def test_ai_report_next_cannot_redirect_offsite(self):
        for evil in ("//evil.com", "https://evil.com/x", "/\\evil.com"):
            res = self.client.post(reverse("scanner:ai_report_create"), {"scan": "garbage", "next": evil})
            self.assertEqual(res.status_code, 302)
            self.assertNotIn("evil.com", res["Location"])

    def test_org_name_length_enforced(self):
        self.client.post(reverse("scanner:organizations_add"), {"program_name": "N" * 300, "program_type": "fintech"})
        self.assertFalse(Program.objects.filter(name="N" * 300).exists())
        self.client.post(reverse("scanner:organizations_edit", args=[self.p.id]),
                         {"program_name": "M" * 300, "program_type": "fintech"})
        self.p.refresh_from_db()
        self.assertEqual(self.p.name, "Acme")


class StatsConsistencyTests(TestCase):
    def setUp(self):
        self.a = Program.objects.create(name="A")
        self.b = Program.objects.create(name="B")
        for prog, dom, total, live, ok, status in [
            (self.a, "x.test", 10, 4, 3, Scan.Status.COMPLETED),
            (self.a, "x.test", 12, 5, 2, Scan.Status.COMPLETED),  # same domain: MAX per field
            (self.a, "y.test", 3, 1, 1, Scan.Status.COMPLETED),
            (self.a, "z.test", None, None, None, Scan.Status.FAILED),
            (self.b, "w.test", 7, 7, 7, Scan.Status.COMPLETED),
        ]:
            Scan.objects.create(domain=dom, program=prog, status=status, total_subdomains=total,
                                live_subdomains=live, http_success=ok,
                                completed_at="2026-11-20T10:00:00Z" if status == Scan.Status.COMPLETED else None)

    def test_listing_matches_detail_statistics(self):
        listing = {row["scan"].id: row for row in get_programs_with_stats()}
        for prog in (self.a, self.b):
            detail = get_program_statistics(prog)
            row = listing[prog.id]
            self.assertEqual(row["total_subdomains"], detail["total_subdomains"])
            self.assertEqual(row["live_subdomains"], detail["live_subdomains"])
            self.assertEqual(row["http_success"], detail["http_success"])
            self.assertEqual(row["scan_count"], detail["total_scans"])
            self.assertEqual(row["completed_scans"], detail["completed_scans"])
        self.assertEqual(listing[self.a.id]["total_subdomains"], 12 + 3)

    def test_listing_query_count_is_constant(self):
        for i in range(5):
            Program.objects.create(name=f"extra{i}")
        with self.assertNumQueries(2):
            get_programs_with_stats()

    def test_assets_overview_single_query(self):
        with self.assertNumQueries(2):  # programs count + one aggregate
            data = get_assets_overview()
        self.assertEqual(data["total_scans"], 5)
        self.assertEqual(data["failed_scans"], 1)
        self.assertEqual(data["total_subdomains"], 10 + 12 + 3 + 7)
        self.assertEqual(data["total_targets"], 4)


class TechnologyCountTests(TestCase):
    def test_distinct_programs_counts_all_pages(self):
        for i in range(3):
            p = Program.objects.create(name=f"P{i}")
            Scan.objects.create(
                domain=f"d{i}.test", program=p, status=Scan.Status.COMPLETED,
                httpx_results=[{"url": f"https://h{i}-{j}.test", "tech": ["nginx"]} for j in range(30)],
            )
        data = get_technology_subdomains("nginx", page_number=1, per_page=50)
        self.assertEqual(data["total_subdomains"], 90)
        self.assertEqual(data["distinct_programs"], 3)  # page 1 alone only covers 2 programs


@unittest.skipIf(sys.platform == "win32", "POSIX scanner script")
class HttpxSilentFailureTests(TransactionTestCase):
    def test_live_hosts_without_httpx_output_warns(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            script = tmp / "fake.sh"
            script.write_text(
                '#!/bin/bash\nmkdir -p "$1" && cd "$1"\n'
                "printf 'a.t\\nb.t\\n' > alldomains.txt\nprintf 'a.t\\n' > live.txt\n",
                newline="\n",
            )
            script.chmod(0o755)
            (tmp / "data").mkdir()
            scan = Scan.objects.create(domain="example.com")
            with override_settings(SCANNER_SCRIPT_PATH=script, SCANX_DATA_DIR=tmp / "data", SCAN_TIMEOUT=30):
                ScanExecutor(scan).run()
            scan.refresh_from_db()
            self.assertEqual(scan.status, Scan.Status.COMPLETED)
            self.assertIn("httpx produced no output", scan.error_message)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipIf(sys.platform == "win32", "fcntl is POSIX-only")
class WorkerLockTests(TransactionTestCase):
    def test_second_worker_refuses_to_start(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            import fcntl
            lock = open(tmp / ".worker.lock", "w")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)  # pretend a worker holds it
            from django.core.management import call_command
            with override_settings(SCANX_DATA_DIR=tmp):
                with self.assertRaises(SystemExit) as ctx:
                    call_command("worker", "--once")
            self.assertEqual(ctx.exception.code, 1)
            lock.close()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
