"""Tests for the REST API (/api/v1) and the built-in AI analyst (provider calls mocked)."""
import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings
from django.urls import reverse

from scanner import ai_agent, mcp_http
from scanner.models import Program, Report, Scan

NO_KEYS = {"ANTHROPIC_API_KEY": "", "ANTHROPIC_AUTH_TOKEN": "", "OPENAI_API_KEY": "", "NVIDIA_API_KEY": ""}
CLAUDE_KEY = {**NO_KEYS, "ANTHROPIC_API_KEY": "test-key"}
OPENAI_KEY = {**NO_KEYS, "OPENAI_API_KEY": "test-key"}
NVIDIA_KEY = {**NO_KEYS, "NVIDIA_API_KEY": "nvapi-test"}


def _scan(program, **kw):
    return Scan.objects.create(
        domain="acme.test", program=program, status=Scan.Status.COMPLETED,
        httpx_results=[{"url": "https://admin.acme.test", "status": 200, "title": "Admin", "tech": ["nginx"], "ip": "10.0.0.1"}],
        total_subdomains=1, live_subdomains=1, **kw,
    )


class RestApiTests(TestCase):
    def setUp(self):
        self.acme = Program.objects.create(name="Acme")
        self.scan = _scan(self.acme)
        _, self.token = mcp_http.create_token(self.acme, "Script")
        self.auth = {"HTTP_AUTHORIZATION": f"Bearer {self.token}"}

    def test_requires_token(self):
        self.assertEqual(self.client.get("/api/v1/tools").status_code, 401)
        self.assertEqual(self.client.post("/api/v1/tools/list_scans", data="{}", content_type="application/json").status_code, 401)

    def test_tools_list_has_schemas(self):
        data = self.client.get("/api/v1/tools", **self.auth).json()["data"]
        names = {t["name"] for t in data}
        self.assertIn("list_hosts", names)
        self.assertIn("input_schema", data[0])

    def test_call_tool_and_errors(self):
        res = self.client.post("/api/v1/tools/list_scans", data=json.dumps({"status": "completed"}),
                               content_type="application/json", **self.auth)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["data"][0]["scan_id"], str(self.scan.id))
        bad = self.client.post("/api/v1/tools/get_scan", data=json.dumps({"scan_id": "nope"}),
                               content_type="application/json", **self.auth)
        self.assertEqual(bad.status_code, 422)
        self.assertEqual(self.client.post("/api/v1/tools/rm_rf", data="{}", content_type="application/json", **self.auth).status_code, 404)

    def test_save_report_via_api_is_labelled(self):
        self.client.post("/api/v1/tools/save_report", content_type="application/json", **self.auth,
                         data=json.dumps({"scan_id": str(self.scan.id), "title": "T", "content": "Body"}))
        report = Report.objects.get()
        self.assertEqual(report.source, Report.Source.API)
        self.assertEqual(report.generated_by, "Script (REST API)")

    def test_openapi_spec(self):
        spec = self.client.get("/api/v1/openapi.json").json()
        self.assertEqual(spec["openapi"], "3.1.0")
        self.assertIn("/api/v1/tools/save_report", spec["paths"])


class AvailabilityTests(TestCase):
    def setUp(self):
        self.acme = Program.objects.create(name="Acme")
        self.scan = _scan(self.acme)

    @patch.dict(os.environ, NO_KEYS)
    def test_not_configured(self):
        info = ai_agent.availability(self.scan)
        self.assertFalse(info["ok"])
        self.assertIn("isn't configured", info["reason"])

    @patch.dict(os.environ, CLAUDE_KEY)
    @override_settings(AI_PROVIDER="")
    def test_provider_autodetect_and_cooldown(self):
        self.assertEqual(ai_agent.active_provider(), "anthropic")
        self.assertTrue(ai_agent.availability(self.scan)["ok"])
        ai_agent.queue_report(self.scan)
        info = ai_agent.availability(self.scan)
        self.assertFalse(info["ok"])
        self.assertIsNotNone(info["recent_report"])

    @patch.dict(os.environ, OPENAI_KEY)
    @override_settings(AI_PROVIDER="", AI_DAILY_LIMIT=1)
    def test_daily_cap(self):
        self.assertEqual(ai_agent.active_provider(), "openai")
        ai_agent.queue_report(self.scan)
        other = _scan(self.acme)
        self.assertIn("used up", ai_agent.availability(other)["reason"])

    @patch.dict(os.environ, CLAUDE_KEY)
    def test_incomplete_scan_rejected(self):
        running = Scan.objects.create(domain="x.test", program=self.acme, status=Scan.Status.RUNNING)
        self.assertIn("completed", ai_agent.availability(running)["reason"])


def _block(**kw):
    return SimpleNamespace(**kw)


class BuiltinAgentTests(TestCase):
    def setUp(self):
        self.acme = Program.objects.create(name="Acme")
        self.scan = _scan(self.acme)

    @patch.dict(os.environ, CLAUDE_KEY)
    @override_settings(AI_PROVIDER="anthropic")
    def test_create_view_queues_and_redirects(self):
        res = self.client.post(reverse("scanner:ai_report_create"), {"scan": str(self.scan.id)})
        report = Report.objects.get()
        self.assertRedirects(res, reverse("scanner:report_detail", args=[report.id]), fetch_redirect_response=False)
        self.assertEqual(report.status, Report.Status.QUEUED)
        page = self.client.get(reverse("scanner:report_detail", args=[report.id]))
        self.assertContains(page, "Waiting for the AI")
        self.assertEqual(self.client.get(reverse("scanner:report_status", args=[report.id])).json()["status"], "queued")
        # A second click within the cooldown goes to the same report, no new job
        self.client.post(reverse("scanner:ai_report_create"), {"scan": str(self.scan.id)})
        self.assertEqual(Report.objects.count(), 1)

    @patch.dict(os.environ, NO_KEYS)
    def test_create_view_without_key_creates_nothing(self):
        self.client.post(reverse("scanner:ai_report_create"), {"scan": str(self.scan.id)})
        self.assertEqual(Report.objects.count(), 0)

    @patch.dict(os.environ, CLAUDE_KEY)
    @override_settings(AI_PROVIDER="anthropic")
    @patch("anthropic.Anthropic")
    def test_claude_loop_uses_tools_and_submits(self, Anthropic):
        client = Anthropic.return_value
        client.beta.messages.create.side_effect = [
            _block(stop_reason="tool_use", content=[
                _block(type="thinking", thinking=""),
                _block(type="tool_use", id="t1", name="list_hosts", input={"scan_id": str(self.scan.id)}),
            ]),
            _block(stop_reason="tool_use", content=[
                _block(type="tool_use", id="t2", name="submit_report", input={
                    "title": "Acme vectors", "summary": "One admin panel exposed.",
                    "content": "# Report\nadmin.acme.test is exposed.",
                    "findings": {"attack_vectors": [{"name": "Exposed admin", "severity": "High"}]},
                }),
            ]),
        ]
        report = ai_agent.queue_report(self.scan)
        self.assertTrue(ai_agent.process_next_report())
        report.refresh_from_db()
        self.assertEqual(report.status, Report.Status.COMPLETED)
        self.assertEqual(report.title, "Acme vectors")
        self.assertEqual(report.findings["attack_vectors"][0]["severity"], "High")

        # The tool result fed back to Claude contains the real scan data
        second_call = client.beta.messages.create.call_args_list[1].kwargs
        tool_result = second_call["messages"][2]["content"][0]
        self.assertEqual(tool_result["tool_use_id"], "t1")
        self.assertIn("admin.acme.test", tool_result["content"])
        self.assertEqual(second_call["fallbacks"], "default")
        self.assertEqual(second_call["model"], "claude-opus-5-5")
        # The finished report renders with its findings visible
        page = self.client.get(reverse("scanner:report_detail", args=[report.id]))
        self.assertContains(page, "Exposed admin")

    @patch.dict(os.environ, CLAUDE_KEY)
    @override_settings(AI_PROVIDER="anthropic")
    @patch("anthropic.Anthropic")
    def test_claude_api_error_marks_failed_with_reason(self, Anthropic):
        import anthropic
        Anthropic.return_value.beta.messages.create.side_effect = anthropic.APIConnectionError(request=MagicMock())
        report = ai_agent.queue_report(self.scan)
        ai_agent.process_next_report()
        report.refresh_from_db()
        self.assertEqual(report.status, Report.Status.FAILED)
        self.assertIn("Couldn't reach the AI provider", report.content)

    @patch.dict(os.environ, OPENAI_KEY)
    @override_settings(AI_PROVIDER="openai")
    @patch("openai.OpenAI")
    def test_openai_loop(self, OpenAI):
        def call(id_, name, args):
            fn = SimpleNamespace(name=name, arguments=json.dumps(args))
            c = SimpleNamespace(id=id_, function=fn, type="function")
            c.model_dump = lambda: {"id": id_, "type": "function", "function": {"name": name, "arguments": fn.arguments}}
            return c

        def completion(content, calls):
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content, tool_calls=calls))])

        OpenAI.return_value.chat.completions.create.side_effect = [
            completion(None, [call("c1", "get_scan", {})]),
            completion(None, [call("c2", "submit_report", {"title": "OAI", "summary": "s", "content": "Body text"})]),
        ]
        report = ai_agent.queue_report(self.scan)
        ai_agent.process_next_report()
        report.refresh_from_db()
        self.assertEqual(report.status, Report.Status.COMPLETED)
        self.assertEqual(report.title, "OAI")
        msgs = OpenAI.return_value.chat.completions.create.call_args_list[1].kwargs["messages"]
        get_scan_result = next(m for m in msgs if m.get("role") == "tool" and m["tool_call_id"] == "c1")
        self.assertIn(str(self.scan.id), get_scan_result["content"])  # scan_id defaulted to the job's scan

    @patch.dict(os.environ, NVIDIA_KEY)
    @override_settings(AI_PROVIDER="", AI_MODEL_NVIDIA="nvidia/nemotron-test")
    @patch("openai.OpenAI")
    def test_nvidia_nemotron_uses_nim_endpoint(self, OpenAI):
        self.assertEqual(ai_agent.active_provider(), "nvidia")
        fn = SimpleNamespace(name="submit_report", arguments=json.dumps({"title": "NV", "summary": "s", "content": "Body"}))
        call = SimpleNamespace(id="n1", function=fn, type="function")
        call.model_dump = lambda: {"id": "n1", "type": "function", "function": {"name": fn.name, "arguments": fn.arguments}}
        OpenAI.return_value.chat.completions.create.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[call]))])
        report = ai_agent.queue_report(self.scan)
        self.assertIn("nemotron-test", report.generated_by)
        ai_agent.process_next_report()
        report.refresh_from_db()
        self.assertEqual(report.status, Report.Status.COMPLETED)
        client_kwargs = OpenAI.call_args.kwargs
        self.assertEqual(client_kwargs["base_url"], "https://integrate.api.nvidia.com/v1")
        self.assertEqual(client_kwargs["api_key"], "nvapi-test")
        req = OpenAI.return_value.chat.completions.create.call_args.kwargs
        self.assertEqual(req["model"], "nvidia/nemotron-test")
        self.assertIn("max_tokens", req)

    def test_recover_interrupted(self):
        r = Report.objects.create(scan=self.scan, title="x", status=Report.Status.GENERATING, source=Report.Source.BUILTIN_AI)
        ai_agent.recover_interrupted()
        r.refresh_from_db()
        self.assertEqual(r.status, Report.Status.FAILED)


class PagesShowAiTests(TestCase):
    @patch.dict(os.environ, CLAUDE_KEY)
    @override_settings(AI_PROVIDER="anthropic")
    def test_buttons_present(self):
        acme = Program.objects.create(name="Acme")
        scan = _scan(acme)
        self.assertContains(self.client.get(reverse("scanner:scan_detail", args=[scan.id])), "Generate AI report")
        self.assertContains(self.client.get(reverse("scanner:reports")), "New AI report")
        mcp = self.client.get(reverse("scanner:mcp_guide"))
        self.assertContains(mcp, "No AI of your own? Use scanX AI")
        self.assertContains(mcp, "/api/v1/tools")
