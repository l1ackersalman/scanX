"""
Tests for scanner aggregation services.
"""
from django.test import TestCase
from django.utils import timezone
from django.core.paginator import Paginator

from scanner.models import Scan, Program
from scanner.services import (
    get_assets_overview,
    get_technology_breakdown,
    get_program_statistics,
    get_programs_with_stats,
    get_technology_subdomains,
    mark_new_subdomains,
    _extract_tech_from_entry,
)


class ExtractTechFromEntryTests(TestCase):
    """Tests for the _extract_tech_from_entry helper."""

    def test_list_tech(self):
        entry = {"tech": ["nginx", "PHP"]}
        self.assertEqual(_extract_tech_from_entry(entry), ["nginx", "PHP"])

    def test_dict_tech(self):
        entry = {"tech": {"nginx": "1.18", "PHP": "8.0"}}
        self.assertEqual(_extract_tech_from_entry(entry), ["nginx", "PHP"])

    def test_string_tech(self):
        entry = {"tech": "nginx, PHP, Python"}
        self.assertEqual(_extract_tech_from_entry(entry), ["nginx", "PHP", "Python"])

    def test_alt_keys(self):
        entry = {"webserver": "Apache", "server": "nginx"}
        self.assertEqual(_extract_tech_from_entry(entry), ["Apache"])

    def test_empty(self):
        self.assertEqual(_extract_tech_from_entry({}), [])
        self.assertEqual(_extract_tech_from_entry({"tech": ""}), [])
        self.assertEqual(_extract_tech_from_entry({"tech": None}), [])


class AssetsOverviewTests(TestCase):
    """Tests for get_assets_overview."""

    def setUp(self):
        self.program = Program.objects.create(
            name="Test Program",
            description="A test program",
            organization_type=Program.OrganizationType.FINTECH,
        )
        self.scan = Scan.objects.create(
            domain="example.com",
            status=Scan.Status.COMPLETED,
            program=self.program,
            total_subdomains=100,
            live_subdomains=80,
            http_success=60,
            http_failed=20,
            httpx_results=[
                {"url": "https://sub1.example.com", "tech": ["nginx", "PHP"]},
                {"url": "https://sub2.example.com", "tech": ["nginx"]},
            ],
        )

    def test_returns_expected_keys(self):
        overview = get_assets_overview()
        expected_keys = {
            "total_programs", "total_scans", "completed_scans", "running_scans",
            "failed_scans", "pending_scans", "cancelled_scans", "total_targets",
            "total_subdomains", "live_subdomains", "http_success", "http_failed",
        }
        self.assertEqual(set(overview.keys()), expected_keys)

    def test_counts_are_correct(self):
        overview = get_assets_overview()
        self.assertEqual(overview["total_programs"], 1)
        self.assertEqual(overview["total_scans"], 1)
        self.assertEqual(overview["completed_scans"], 1)
        self.assertEqual(overview["total_targets"], 1)
        self.assertEqual(overview["total_subdomains"], 100)
        self.assertEqual(overview["live_subdomains"], 80)
        self.assertEqual(overview["http_success"], 60)
        self.assertEqual(overview["http_failed"], 20)


class TechnologyBreakdownTests(TestCase):
    """Tests for get_technology_breakdown."""

    def setUp(self):
        self.program = Program.objects.create(
            name="Test Program",
            
            organization_type=Program.OrganizationType.FINTECH,
        )
        self.scan1 = Scan.objects.create(
            domain="example.com",
            status=Scan.Status.COMPLETED,
            program=self.program,
            httpx_results=[
                {"url": "https://a.example.com", "tech": ["nginx", "PHP"]},
                {"url": "https://b.example.com", "tech": ["nginx"]},
            ],
        )
        self.scan2 = Scan.objects.create(
            domain="test.org",
            status=Scan.Status.COMPLETED,
            program=self.program,
            httpx_results=[
                {"url": "https://c.test.org", "tech": ["Apache"]},
            ],
        )

    def test_returns_expected_keys(self):
        result = get_technology_breakdown()
        expected_keys = {"tech_page", "total_technologies", "sort_by", "search"}
        self.assertEqual(set(result.keys()), expected_keys)

    def test_alphabetical_sort_default(self):
        result = get_technology_breakdown(sort_by="alpha")
        techs = [item[0] for item in result["tech_page"]]
        self.assertEqual(techs, sorted(techs, key=str.lower))

    def test_count_sort(self):
        result = get_technology_breakdown(sort_by="count")
        techs = list(result["tech_page"])
        # nginx appears in 2 subdomains, PHP in 1, Apache in 1
        nginx_item = next(item for item in techs if item[0] == "nginx")
        self.assertEqual(nginx_item[1], 2)  # subdomain count

    def test_search_filter(self):
        result = get_technology_breakdown(search="nginx")
        techs = [item[0] for item in result["tech_page"]]
        self.assertIn("nginx", techs)
        self.assertNotIn("Apache", techs)
        self.assertNotIn("PHP", techs)

    def test_pagination(self):
        result = get_technology_breakdown(per_page=1)
        self.assertEqual(result["tech_page"].paginator.num_pages, 3)
        self.assertEqual(len(result["tech_page"]), 1)

    def test_total_technologies(self):
        result = get_technology_breakdown()
        # nginx, PHP, Apache = 3 unique technologies
        self.assertEqual(result["total_technologies"], 3)


class ProgramStatisticsTests(TestCase):
    """Tests for get_program_statistics."""

    def setUp(self):
        self.program = Program.objects.create(
            name="Test Program",
            
            organization_type=Program.OrganizationType.FINTECH,
        )
        self.scan1 = Scan.objects.create(
            domain="example.com",
            status=Scan.Status.COMPLETED,
            program=self.program,
            total_subdomains=100,
            live_subdomains=80,
            http_success=60,
            http_failed=20,
        )
        self.scan2 = Scan.objects.create(
            domain="example.com",
            status=Scan.Status.COMPLETED,
            program=self.program,
            total_subdomains=150,
            live_subdomains=120,
            http_success=100,
            http_failed=10,
        )
        self.scan3 = Scan.objects.create(
            domain="test.org",
            status=Scan.Status.RUNNING,
            program=self.program,
        )

    def test_returns_expected_keys(self):
        stats = get_program_statistics(self.program)
        expected_keys = {
            "program", "domain_stats", "total_scans", "total_targets",
            "completed_scans", "running_scans", "failed_scans",
            "pending_scans", "cancelled_scans", "total_subdomains",
            "live_subdomains", "http_success", "http_failed",
            "total_technologies", "last_scanned",
        }
        self.assertEqual(set(stats.keys()), expected_keys)

    def test_domain_deduplication(self):
        stats = get_program_statistics(self.program)
        # example.com scanned twice, test.org once => 2 targets
        self.assertEqual(stats["total_targets"], 2)
        # total_scans counts all 3 scans
        self.assertEqual(stats["total_scans"], 3)
        # MAX subdomains for example.com = 150, test.org = 0 => 150
        self.assertEqual(stats["total_subdomains"], 150)

    def test_status_counts(self):
        stats = get_program_statistics(self.program)
        self.assertEqual(stats["completed_scans"], 2)
        self.assertEqual(stats["running_scans"], 1)


class ProgramsWithStatsTests(TestCase):
    """Tests for get_programs_with_stats."""

    def setUp(self):
        self.program = Program.objects.create(
            name="Test Program",
            
            organization_type=Program.OrganizationType.FINTECH,
        )
        Scan.objects.create(
            domain="example.com",
            status=Scan.Status.COMPLETED,
            program=self.program,
            total_subdomains=50,
            live_subdomains=40,
            http_success=30,
        )

    def test_returns_list_of_dicts(self):
        result = get_programs_with_stats()
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["scan"], self.program)
        self.assertEqual(result[0]["total_subdomains"], 50)


class TechnologySubdomainsTests(TestCase):
    """Tests for get_technology_subdomains."""

    def setUp(self):
        self.program = Program.objects.create(
            name="Test Program",
            
            organization_type=Program.OrganizationType.FINTECH,
        )
        self.scan1 = Scan.objects.create(
            domain="example.com",
            status=Scan.Status.COMPLETED,
            program=self.program,
            httpx_results=[
                {"url": "https://a.example.com", "tech": ["nginx", "PHP"]},
                {"url": "https://b.example.com", "tech": ["nginx"]},
            ],
        )
        self.scan2 = Scan.objects.create(
            domain="test.org",
            status=Scan.Status.COMPLETED,
            program=self.program,
            httpx_results=[
                {"url": "https://c.test.org", "tech": ["Apache"]},
            ],
        )

    def test_returns_expected_keys(self):
        result = get_technology_subdomains("nginx")
        expected_keys = {"technology", "subdomain_page", "total_subdomains", "distinct_programs", "sort_by"}
        self.assertEqual(set(result.keys()), expected_keys)

    def test_nginx_subdomains(self):
        result = get_technology_subdomains("nginx")
        subdomains = [item["subdomain"] for item in result["subdomain_page"].object_list]
        self.assertIn("https://a.example.com", subdomains)
        self.assertIn("https://b.example.com", subdomains)
        self.assertEqual(result["total_subdomains"], 2)

    def test_apache_subdomains(self):
        result = get_technology_subdomains("Apache")
        subdomains = [item["subdomain"] for item in result["subdomain_page"].object_list]
        self.assertIn("https://c.test.org", subdomains)
        self.assertEqual(result["total_subdomains"], 1)

    def test_program_attached(self):
        result = get_technology_subdomains("nginx")
        for item in result["subdomain_page"].object_list:
            self.assertEqual(item["program"], self.program)

    def test_status_code_captured(self):
        result = get_technology_subdomains("nginx")
        items = {item["subdomain"]: item for item in result["subdomain_page"].object_list}
        # The test data doesn't set status-code, so it should default to N/A
        self.assertEqual(items["https://a.example.com"]["status_code"], "N/A")

    def test_status_code_from_httpx(self):
        """Test that status codes from httpx results are captured."""
        Scan.objects.create(
            domain="status.example.com",
            status=Scan.Status.COMPLETED,
            program=self.program,
            httpx_results=[
                {"url": "https://status.example.com", "tech": ["nginx"], "status-code": 200},
            ],
        )
        result = get_technology_subdomains("nginx")
        items = {item["subdomain"]: item for item in result["subdomain_page"].object_list}
        self.assertEqual(items["https://status.example.com"]["status_code"], "200")

    def test_nonexistent_tech(self):
        result = get_technology_subdomains("NonexistentTech")
        self.assertEqual(result["total_subdomains"], 0)
        self.assertEqual(len(result["subdomain_page"]), 0)

    def test_pagination(self):
        # Create many subdomains with nginx
        for i in range(60):
            Scan.objects.create(
                domain=f"scan{i}.com",
                status=Scan.Status.COMPLETED,
                program=self.program,
                httpx_results=[{"url": f"https://tech{i}.example.com", "tech": ["nginx"]}],
            )
        result = get_technology_subdomains("nginx", per_page=10)
        self.assertEqual(result["subdomain_page"].paginator.num_pages, 7)
        self.assertEqual(len(result["subdomain_page"]), 10)


class NewSubdomainTests(TestCase):
    """Tests for new subdomain detection."""

    def setUp(self):
        self.program = Program.objects.create(
            name="Test Program",
            
            organization_type=Program.OrganizationType.FINTECH,
        )

    def test_first_scan_all_new(self):
        """First scan of a domain: all subdomains are new."""
        scan = Scan.objects.create(
            domain="example.com",
            status=Scan.Status.COMPLETED,
            program=self.program,
            httpx_results=[
                {"url": "https://a.example.com", "tech": ["nginx"]},
                {"url": "https://b.example.com", "tech": ["PHP"]},
            ],
        )
        results = mark_new_subdomains(scan, scan.httpx_results)
        self.assertTrue(results[0]["is_new"])
        self.assertTrue(results[1]["is_new"])

    def test_second_scan_no_new(self):
        """Second scan with same subdomains: none are new."""
        scan1 = Scan.objects.create(
            domain="example.com",
            status=Scan.Status.COMPLETED,
            program=self.program,
            httpx_results=[
                {"url": "https://a.example.com", "tech": ["nginx"]},
            ],
        )
        scan2 = Scan.objects.create(
            domain="example.com",
            status=Scan.Status.COMPLETED,
            program=self.program,
            httpx_results=[
                {"url": "https://a.example.com", "tech": ["nginx"]},
            ],
        )
        results = mark_new_subdomains(scan2, scan2.httpx_results)
        self.assertFalse(results[0]["is_new"])

    def test_second_scan_some_new(self):
        """Second scan with one new subdomain: only that one is new."""
        scan1 = Scan.objects.create(
            domain="example.com",
            status=Scan.Status.COMPLETED,
            program=self.program,
            httpx_results=[
                {"url": "https://a.example.com", "tech": ["nginx"]},
            ],
        )
        scan2 = Scan.objects.create(
            domain="example.com",
            status=Scan.Status.COMPLETED,
            program=self.program,
            httpx_results=[
                {"url": "https://a.example.com", "tech": ["nginx"]},
                {"url": "https://b.example.com", "tech": ["PHP"]},
            ],
        )
        results = mark_new_subdomains(scan2, scan2.httpx_results)
        self.assertFalse(results[0]["is_new"])
        self.assertTrue(results[1]["is_new"])

    def test_previous_scan_urls(self):
        """get_previous_scan_urls excludes the current scan."""
        scan1 = Scan.objects.create(
            domain="example.com",
            status=Scan.Status.COMPLETED,
            program=self.program,
            httpx_results=[
                {"url": "https://a.example.com", "tech": ["nginx"]},
            ],
        )
        scan2 = Scan.objects.create(
            domain="example.com",
            status=Scan.Status.COMPLETED,
            program=self.program,
            httpx_results=[
                {"url": "https://b.example.com", "tech": ["PHP"]},
            ],
        )
        from scanner.services import get_previous_scan_urls
        urls_for_scan1 = get_previous_scan_urls(scan1)
        urls_for_scan2 = get_previous_scan_urls(scan2)
        self.assertIn("https://b.example.com", urls_for_scan1)
        self.assertIn("https://a.example.com", urls_for_scan2)
        self.assertNotIn("https://a.example.com", urls_for_scan1)
        self.assertNotIn("https://b.example.com", urls_for_scan2)

