"""Rendering tests for the scan pages' user-facing states."""
from django.test import TestCase
from django.urls import reverse

from scanner.models import Program, Scan


class ScanDetailStatesTests(TestCase):
    def setUp(self):
        self.program = Program.objects.create(name="Acme")

    def _get(self, scan, query=""):
        return self.client.get(reverse("scanner:scan_detail", args=[scan.id]) + query)

    def test_failed_scan_shows_reason_and_fix(self):
        scan = Scan.objects.create(
            domain="example.com", program=self.program, status=Scan.Status.FAILED,
            error_message="Scanner exited with code 1: [!] Error: crt is not installed.",
        )
        res = self._get(scan)
        self.assertContains(res, "The scan failed")
        self.assertContains(res, "crt is not installed")
        self.assertContains(res, "./scripts/install.sh")
        self.assertContains(res, "Scan again")

    def test_cancelled_scan_has_notice(self):
        scan = Scan.objects.create(domain="example.com", program=self.program, status=Scan.Status.CANCELLED)
        res = self._get(scan)
        self.assertContains(res, "You stopped this scan")

    def test_running_scan_has_live_log_and_stop(self):
        scan = Scan.objects.create(domain="example.com", program=self.program, status=Scan.Status.RUNNING)
        res = self._get(scan)
        self.assertContains(res, 'id="log-viewer"')
        self.assertContains(res, "Stop scan")

    def test_pagination_keeps_filters(self):
        results = [
            {"url": f"https://h{i}.example.com", "status": 200, "tech": ["nginx"], "ip": "1.1.1.1"}
            for i in range(60)
        ]
        scan = Scan.objects.create(
            domain="example.com", program=self.program, status=Scan.Status.COMPLETED,
            httpx_results=results, live_subdomains=60, total_subdomains=60,
        )
        res = self._get(scan, "?tech=nginx")
        self.assertContains(res, "60 of 60 match your filters")
        self.assertContains(res, "?tech=nginx&amp;page=2")

    def test_completed_without_http_explains_empty(self):
        scan = Scan.objects.create(
            domain="example.com", program=self.program, status=Scan.Status.COMPLETED,
            httpx_results=[], live_subdomains=3, total_subdomains=5,
        )
        res = self._get(scan)
        self.assertContains(res, "none answered over HTTP")


class OverviewTests(TestCase):
    def test_lists_recent_scans_and_preselects_single_org(self):
        program = Program.objects.create(name="Acme")
        Scan.objects.create(domain="recent.example.com", program=program)
        res = self.client.get(reverse("scanner:overview"))
        self.assertContains(res, "recent.example.com")
        self.assertContains(res, f'value="{program.id}" selected')

    def test_no_org_prompts_to_add(self):
        res = self.client.get(reverse("scanner:overview"))
        self.assertContains(res, "Add an organization first")
