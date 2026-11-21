"""Tests for: risk score, live AI progress, AI change analysis, and asking the report questions."""
import json
import os
from types import SimpleNamespace
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse

from scanner import ai_agent
from scanner.models import Program, Report, ReportQuestion, Scan
from scanner.risk import risk_summary

KEYS = {"ANTHROPIC_API_KEY": "test", "ANTHROPIC_AUTH_TOKEN": "", "OPENAI_API_KEY": "", "NVIDIA_API_KEY": "",
        "API_KEY": "", "api_key": "", "AI_API_KEY": "", "ai_api_key": ""}


def _b(**kw):
    return SimpleNamespace(**kw)


def _scan(program, hosts, **kw):
    return Scan.objects.create(domain="acme.test", program=program, status=Scan.Status.COMPLETED,
                               httpx_results=hosts, live_subdomains=len(hosts), total_subdomains=len(hosts), **kw)


class RiskTests(TestCase):
    def test_levels_and_aliases(self):
        f = {"attack_vectors": [{"rating": "High"}, {"severity": "critical"}, {"risk": "Moderate"}, {"severity": "x"}]}
        r = risk_summary(f)
        self.assertEqual(r["level"], "critical")
        self.assertEqual(r["counts"], {"critical": 1, "high": 1, "medium": 1, "low": 0})
        self.assertEqual(risk_summary({"attack_vectors": []})["level"], "none")
        self.assertEqual(risk_summary({})["level"], "")
        self.assertEqual(risk_summary(None)["level"], "")

    def test_report_stores_risk_on_save_and_pages_show_it(self):
        p = Program.objects.create(name="Acme")
        scan = _scan(p, [{"url": "https://a.acme.test"}])
        report = Report.objects.create(scan=scan, title="R", status=Report.Status.COMPLETED,
                                       findings={"attack_vectors": [{"name": "x", "severity": "High"}]})
        self.assertEqual(report.risk_level, "high")
        report.status = Report.Status.FAILED
        report.save(update_fields=["status"])
        report.refresh_from_db()
        self.assertEqual(report.risk_level, "")  # only completed reports carry a risk
        report.status = Report.Status.COMPLETED
        report.save()
        for url in (reverse("scanner:scan_detail", args=[scan.id]), reverse("scanner:reports"),
                    reverse("scanner:overview"), reverse("scanner:report_detail", args=[report.id])):
            self.assertContains(self.client.get(url), "Risk: High")


@patch.dict(os.environ, KEYS)
@override_settings(AI_PROVIDER="anthropic")
class ProgressAndChangeTests(TestCase):
    def setUp(self):
        self.p = Program.objects.create(name="Acme")
        self.prev = _scan(self.p, [{"url": "https://a.acme.test", "status": 200}])
        self.scan = _scan(self.p, [{"url": "https://a.acme.test", "status": 200},
                                   {"url": "https://admin.acme.test", "status": 200, "title": "Admin"}])

    @patch("anthropic.Anthropic")
    def test_progress_steps_recorded(self, Anthropic):
        Anthropic.return_value.beta.messages.create.side_effect = [
            _b(stop_reason="tool_use", content=[_b(type="tool_use", id="1", name="search_hosts", input={"query": "admin"})]),
            _b(stop_reason="tool_use", content=[_b(type="tool_use", id="2", name="submit_report",
                                                   input={"title": "T", "summary": "s", "content": "Body"})]),
        ]
        report = ai_agent.queue_report(self.scan)
        ai_agent.process_next_report()
        report.refresh_from_db()
        texts = [s["text"] for s in report.progress]
        self.assertTrue(texts[0].startswith("Starting Claude"))
        self.assertIn("Thinking…", texts)
        self.assertIn("Searching hosts for “admin”…", texts)
        self.assertIn("Writing the report…", texts)
        status = self.client.get(reverse("scanner:report_status", args=[report.id])).json()
        self.assertEqual(len(status["progress"]), len(texts))

    @patch("anthropic.Anthropic")
    def test_summary_given_up_front_and_bigger_pages(self, Anthropic):
        Anthropic.return_value.beta.messages.create.side_effect = [
            _b(stop_reason="tool_use", content=[_b(type="tool_use", id="1", name="list_hosts", input={})]),
            _b(stop_reason="end_turn", content=[_b(type="text", text="x" * 300)]),
        ]
        ai_agent.queue_report(self.scan)
        ai_agent.process_next_report()
        calls = Anthropic.return_value.beta.messages.create.call_args_list
        first_prompt = calls[0].kwargs["messages"][0]["content"]
        self.assertIn("Scan summary (already fetched", first_prompt)
        self.assertIn('"hosts_with_http_response": 2', first_prompt)
        tool_result = json.loads(calls[1].kwargs["messages"][2]["content"][0]["content"])
        self.assertEqual(tool_result["meta"]["total"], 2)

    def test_change_analysis_needs_previous_scan(self):
        self.assertTrue(ai_agent.availability(self.scan, Report.ReportType.CHANGE_ANALYSIS)["ok"])
        self.assertIn("no earlier", ai_agent.availability(self.prev, Report.ReportType.CHANGE_ANALYSIS)["reason"])
        page = self.client.get(reverse("scanner:scan_detail", args=[self.scan.id]))
        self.assertContains(page, "What changed? (AI)")
        self.assertNotContains(self.client.get(reverse("scanner:scan_detail", args=[self.prev.id])), "What changed? (AI)")

    @patch("anthropic.Anthropic")
    def test_change_analysis_runs_with_change_prompt(self, Anthropic):
        Anthropic.return_value.beta.messages.create.side_effect = [
            _b(stop_reason="tool_use", content=[_b(type="tool_use", id="1", name="diff_scans", input={"scan_id": str(self.scan.id)})]),
            _b(stop_reason="tool_use", content=[_b(type="tool_use", id="2", name="submit_report", input={
                "title": "Changes", "summary": "1 new admin host", "content": "## What changed",
                "findings": {"attack_vectors": [{"name": "New admin panel", "severity": "High"}], "changes": {"added": 1}}})]),
        ]
        res = self.client.post(reverse("scanner:ai_report_create"), {"scan": str(self.scan.id), "type": "change_analysis"})
        report = Report.objects.get()
        self.assertEqual(report.report_type, Report.ReportType.CHANGE_ANALYSIS)
        self.assertEqual(report.title, "AI change analysis — acme.test")
        ai_agent.process_next_report()
        report.refresh_from_db()
        self.assertEqual(report.status, Report.Status.COMPLETED)
        self.assertEqual(report.risk_level, "high")
        calls = Anthropic.return_value.beta.messages.create.call_args_list
        self.assertIn(str(self.prev.id), calls[0].kwargs["messages"][0]["content"])
        diff = json.loads(calls[1].kwargs["messages"][2]["content"][0]["content"])
        self.assertEqual(diff["data"]["counts"]["added"], 1)
        # Both report kinds have their own cooldown
        self.assertTrue(ai_agent.availability(self.scan)["ok"])
        # A change analysis doesn't replace the scan's overall (attack-vector) risk
        Report.objects.create(scan=self.scan, title="AV", status=Report.Status.COMPLETED,
                              report_type=Report.ReportType.ATTACK_VECTOR,
                              findings={"attack_vectors": [{"severity": "Critical"}]},
                              created_at=report.created_at)
        report.save()  # newest report is the change analysis (High)
        page = self.client.get(reverse("scanner:scan_detail", args=[self.scan.id]))
        self.assertContains(page, "Risk: Critical")


@patch.dict(os.environ, KEYS)
@override_settings(AI_PROVIDER="anthropic")
class AskReportTests(TestCase):
    def setUp(self):
        p = Program.objects.create(name="Acme")
        self.scan = _scan(p, [{"url": "https://admin.acme.test", "status": 200, "title": "Admin"}])
        self.report = Report.objects.create(scan=self.scan, title="R", status=Report.Status.COMPLETED,
                                            source=Report.Source.BUILTIN_AI, content="## Findings\nadmin exposed")

    @patch("anthropic.Anthropic")
    def test_ask_and_answer(self, Anthropic):
        Anthropic.return_value.beta.messages.create.side_effect = [
            _b(stop_reason="tool_use", content=[_b(type="tool_use", id="1", name="search_hosts", input={"query": "admin"})]),
            _b(stop_reason="end_turn", content=[_b(type="text", text="Fix **admin.acme.test** first.")]),
        ]
        url = reverse("scanner:report_ask", args=[self.report.id])
        res = self.client.post(url, {"question": "Which host first?"})
        self.assertEqual(res.status_code, 302)
        q = ReportQuestion.objects.get()
        page = self.client.get(reverse("scanner:report_detail", args=[self.report.id]))
        self.assertContains(page, "Thinking…")
        self.assertEqual(self.client.get(reverse("scanner:report_status", args=[self.report.id])).json()["pending_questions"], 1)
        # A second question waits until the first is answered
        self.client.post(url, {"question": "Another?"})
        self.assertEqual(ReportQuestion.objects.count(), 1)

        self.assertTrue(ai_agent.process_next_job())
        q.refresh_from_db()
        self.assertEqual(q.status, ReportQuestion.Status.ANSWERED)
        req = Anthropic.return_value.beta.messages.create.call_args_list[0].kwargs
        self.assertIn("Question: Which host first?", req["messages"][0]["content"])
        self.assertIn("admin exposed", req["messages"][0]["content"])  # report content given as context
        self.assertNotIn("submit_report", [t["name"] for t in req["tools"]])  # read-only for questions
        page = self.client.get(reverse("scanner:report_detail", args=[self.report.id]))
        self.assertContains(page, "<strong>admin.acme.test</strong>")

    def test_question_validation(self):
        url = reverse("scanner:report_ask", args=[self.report.id])
        self.client.post(url, {"question": "   "})
        self.client.post(url, {"question": "x" * 600})
        self.assertEqual(ReportQuestion.objects.count(), 0)
        self.report.status = Report.Status.GENERATING
        self.report.save()
        self.client.post(url, {"question": "ok?"})
        self.assertEqual(ReportQuestion.objects.count(), 0)

    @override_settings(AI_QUESTIONS_PER_REPORT=1)
    def test_per_report_limit(self):
        ReportQuestion.objects.create(report=self.report, question="q", status=ReportQuestion.Status.ANSWERED)
        self.assertIn("limit", ai_agent.question_availability(self.report)["reason"])

    def test_interrupted_question_recovered(self):
        q = ReportQuestion.objects.create(report=self.report, question="q", status=ReportQuestion.Status.ANSWERING)
        ai_agent.recover_interrupted()
        q.refresh_from_db()
        self.assertEqual(q.status, ReportQuestion.Status.FAILED)
