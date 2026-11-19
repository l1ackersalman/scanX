"""
Tests for scanner views, focusing on Assets search/sort/pagination.
"""
from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone

from scanner.models import Scan, Program


class AssetsViewTests(TestCase):
    """Tests for the Assets view."""

    def setUp(self):
        self.client = Client()
        self.program = Program.objects.create(
            name="Test Program",
            title="TP",
            description="A test program",
            platform=Program.Platform.HACKERONE,
            program_type=Program.ProgramType.BBP,
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
                {"url": "https://a.example.com", "tech": ["nginx", "PHP"]},
                {"url": "https://b.example.com", "tech": ["nginx"]},
                {"url": "https://c.example.com", "tech": ["Apache", "PHP"]},
            ],
        )

    def test_assets_page_returns_200(self):
        response = self.client.get(reverse("scanner:assets"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Assets")
        self.assertContains(response, "Overview Statistics")

    def test_overview_stats_in_context(self):
        response = self.client.get(reverse("scanner:assets"))
        self.assertEqual(response.context["total_programs"], 1)
        self.assertEqual(response.context["bbp_programs"], 1)
        self.assertEqual(response.context["total_scans"], 1)
        self.assertEqual(response.context["total_targets"], 1)
        self.assertEqual(response.context["total_subdomains"], 100)

    def test_technologies_breakdown_present(self):
        response = self.client.get(reverse("scanner:assets"))
        self.assertContains(response, "Technologies Breakdown")
        # nginx should appear (2 subdomains: a.example.com, b.example.com)
        self.assertContains(response, "nginx")
        # Apache should appear (1 subdomain: c.example.com)
        self.assertContains(response, "Apache")

    def test_search_filter(self):
        response = self.client.get(reverse("scanner:assets") + "?tech_search=nginx")
        self.assertContains(response, "nginx")
        self.assertNotContains(response, "Apache")
        self.assertEqual(response.context["tech_search"], "nginx")

    def test_search_clear(self):
        response = self.client.get(
            reverse("scanner:assets") + "?tech_search=nginx"
        )
        self.assertContains(response, "nginx")
        # Clear the search
        response = self.client.get(reverse("scanner:assets"))
        self.assertContains(response, "nginx")
        self.assertContains(response, "Apache")

    def test_sort_by_count(self):
        response = self.client.get(reverse("scanner:assets") + "?sort_by=count")
        self.assertEqual(response.context["sort_by"], "count")
        # nginx has 2 subdomains, should be first when sorted by count
        techs = [item[0] for item in response.context["tech_page"]]
        self.assertEqual(techs[0], "nginx")

    def test_sort_by_alpha(self):
        response = self.client.get(reverse("scanner:assets") + "?sort_by=alpha")
        self.assertEqual(response.context["sort_by"], "alpha")
        techs = [item[0] for item in response.context["tech_page"]]
        self.assertEqual(techs, sorted(techs, key=str.lower))

    def test_pagination_preserves_sort(self):
        # Create many technologies to force pagination
        for i in range(60):
            Scan.objects.create(
                domain=f"scan{i}.com",
                status=Scan.Status.COMPLETED,
                program=self.program,
                httpx_results=[{"url": f"https://tech{i}.example.com", "tech": [f"Tech{i}"], }],
            )
        response = self.client.get(reverse("scanner:assets") + "?sort_by=count&page=2")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["sort_by"], "count")
        self.assertEqual(response.context["tech_page"].number, 2)

    def test_pagination_preserves_search(self):
        for i in range(60):
            Scan.objects.create(
                domain=f"scan{i}.com",
                status=Scan.Status.COMPLETED,
                program=self.program,
                httpx_results=[{"url": f"https://tech{i}.example.com", "tech": [f"nginxTech{i}"], }],
            )
        response = self.client.get(
            reverse("scanner:assets") + "?tech_search=nginx&page=2"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["tech_search"], "nginx")
        self.assertEqual(response.context["tech_page"].number, 2)


class ProgramDetailViewTests(TestCase):
    """Tests for program_detail view using service layer."""

    def setUp(self):
        self.client = Client()
        self.program = Program.objects.create(
            name="Test Program",
            platform=Program.Platform.HACKERONE,
            program_type=Program.ProgramType.BBP,
        )
        self.scan = Scan.objects.create(
            domain="example.com",
            status=Scan.Status.COMPLETED,
            program=self.program,
            total_subdomains=100,
            live_subdomains=80,
            http_success=60,
            http_failed=20,
        )

    def test_program_detail_returns_200(self):
        response = self.client.get(reverse("scanner:program_detail", args=[self.program.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test Program")

    def test_program_stats_in_context(self):
        response = self.client.get(reverse("scanner:program_detail", args=[self.program.id]))
        self.assertEqual(response.context["total_scans"], 1)
        self.assertEqual(response.context["total_targets"], 1)
        self.assertEqual(response.context["completed_scans"], 1)


class TechnologyDetailViewTests(TestCase):
    """Tests for the technology_detail view."""

    def setUp(self):
        self.client = Client()
        self.program = Program.objects.create(
            name="Test Program",
            platform=Program.Platform.HACKERONE,
            program_type=Program.ProgramType.BBP,
        )
        self.scan = Scan.objects.create(
            domain="example.com",
            status=Scan.Status.COMPLETED,
            program=self.program,
            httpx_results=[
                {"url": "https://a.example.com", "tech": ["nginx", "PHP"]},
                {"url": "https://b.example.com", "tech": ["nginx"]},
            ],
        )

    def test_technology_detail_returns_200(self):
        response = self.client.get(reverse("scanner:technology_detail") + "?tech=nginx")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "nginx")

    def test_technology_detail_no_tech_redirects(self):
        response = self.client.get(reverse("scanner:technology_detail"))
        self.assertRedirects(response, reverse("scanner:assets"))

    def test_subdomains_listed(self):
        response = self.client.get(reverse("scanner:technology_detail") + "?tech=nginx")
        self.assertContains(response, "https://a.example.com")
        self.assertContains(response, "https://b.example.com")

    def test_program_link_shown(self):
        response = self.client.get(reverse("scanner:technology_detail") + "?tech=nginx")
        self.assertContains(response, "Test Program")
        self.assertContains(response, reverse("scanner:program_detail", args=[self.program.id]))

    def test_platform_and_type_shown(self):
        response = self.client.get(reverse("scanner:technology_detail") + "?tech=nginx")
        self.assertContains(response, "HackerOne")
        self.assertContains(response, "BBP")

    def test_nonexistent_tech_empty(self):
        response = self.client.get(reverse("scanner:technology_detail") + "?tech=nonexistent")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No subdomains found")

    def test_pagination_preserves_tech(self):
        for i in range(60):
            Scan.objects.create(
                domain=f"scan{i}.com",
                status=Scan.Status.COMPLETED,
                program=self.program,
                httpx_results=[{"url": f"https://tech{i}.example.com", "tech": ["nginx"]}],
            )
        response = self.client.get(
            reverse("scanner:technology_detail") + "?tech=nginx&page=2"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["subdomain_page"].number, 2)

