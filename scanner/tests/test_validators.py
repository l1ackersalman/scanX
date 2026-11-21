from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from core.validators import normalize_domain, validate_domain
from scanner.models import Program, Scan


class NormalizeDomainTests(SimpleTestCase):
    def test_strips_url_parts(self):
        cases = {
            "https://yourhonesty.com/": "yourhonesty.com",
            "http://Example.COM": "example.com",
            "  example.com  ": "example.com",
            "example.com/some/path?q=1#frag": "example.com",
            "https://user:pw@sub.example.com:8443/x": "sub.example.com",
            "example.com.": "example.com",
            "www.example.com": "www.example.com",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(normalize_domain(raw), expected)
                validate_domain(normalize_domain(raw))

    def test_dangerous_input_still_rejected(self):
        for raw in ["https://a.com;rm -rf /", "a..b.com", "$(id).com", ""]:
            with self.subTest(raw=raw):
                with self.assertRaises(ValidationError):
                    validate_domain(normalize_domain(raw))


class StartScanUrlInputTests(TestCase):
    def test_url_input_is_trimmed_to_domain(self):
        program = Program.objects.create(
            name="P", organization_type=Program.OrganizationType.FINTECH
        )
        response = self.client.post(
            reverse("scanner:start_scan"),
            {"domain": "https://yourhonesty.com/", "program": program.id},
        )
        scan = Scan.objects.get()
        self.assertEqual(scan.domain, "yourhonesty.com")
        self.assertRedirects(
            response,
            reverse("scanner:scan_detail", kwargs={"scan_id": scan.id}),
            fetch_redirect_response=False,
        )
        # Queued for the worker, not run in the web process
        self.assertEqual(scan.status, Scan.Status.PENDING)

    def test_validation_error_is_plain_text(self):
        program = Program.objects.create(name="P")
        response = self.client.post(
            reverse("scanner:start_scan"),
            {"domain": "bad..domain", "program": program.id},
        )
        self.assertContains(response, "Domain contains path traversal sequences.", status_code=400)
        self.assertNotContains(response, "[&#x27;", status_code=400)
        # The chosen organization stays selected after the error
        self.assertContains(response, f'value="{program.id}" selected', status_code=400)
