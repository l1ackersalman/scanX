"""Tests for the MCP endpoint (/api/mcp) and the Connect flow on /mcp."""
import json

from django.test import TestCase
from django.urls import reverse

from scanner import mcp_http
from scanner.models import McpToken, Program, Report, Scan

URL = "/api/mcp"


def _hosts(n, prefix="h"):
    return [
        {"url": f"https://{prefix}{i}.acme.test", "status": 200 if i % 2 else 403,
         "title": "Admin login" if i == 0 else "Home", "tech": ["nginx:1.18", "PHP"],
         "ip": "10.0.0.1", "cname": ""}
        for i in range(n)
    ]


class McpEndpointTests(TestCase):
    def setUp(self):
        self.acme = Program.objects.create(name="Acme")
        self.other = Program.objects.create(name="Other")
        self.prev = Scan.objects.create(
            domain="acme.test", program=self.acme, status=Scan.Status.COMPLETED,
            httpx_results=_hosts(3), total_subdomains=3, live_subdomains=3,
        )
        self.scan = Scan.objects.create(
            domain="acme.test", program=self.acme, status=Scan.Status.COMPLETED,
            httpx_results=_hosts(5), total_subdomains=6, live_subdomains=5,
        )
        self.foreign = Scan.objects.create(
            domain="other.test", program=self.other, status=Scan.Status.COMPLETED,
            httpx_results=_hosts(2, "x"),
        )
        self.token_obj, self.token = mcp_http.create_token(self.acme, "Test agent")

    def rpc(self, method, params=None, token=None, msg_id=1):
        body = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if msg_id is not None:
            body["id"] = msg_id
        return self.client.post(
            URL, data=json.dumps(body), content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token or self.token}",
            HTTP_ACCEPT="application/json, text/event-stream",
        )

    def call(self, name, **arguments):
        res = self.rpc("tools/call", {"name": name, "arguments": arguments})
        self.assertEqual(res.status_code, 200)
        return res.json()["result"]

    # --- transport & auth -------------------------------------------------
    def test_requires_token(self):
        res = self.client.post(URL, data="{}", content_type="application/json")
        self.assertEqual(res.status_code, 401)
        self.assertIn("Bearer", res["WWW-Authenticate"])
        self.assertEqual(self.rpc("ping", token="sx_wrong").status_code, 401)

    def test_revoked_token_rejected(self):
        McpToken.objects.filter(pk=self.token_obj.pk).update(revoked_at="2026-01-01T00:00:00Z")
        self.assertEqual(self.rpc("ping").status_code, 401)

    def test_get_not_allowed(self):
        self.assertEqual(self.client.get(URL).status_code, 405)

    def test_initialize_and_notification(self):
        res = self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                      "clientInfo": {"name": "t", "version": "1"}})
        result = res.json()["result"]
        self.assertEqual(result["protocolVersion"], "2025-06-18")
        self.assertIn("tools", result["capabilities"])
        self.assertEqual(self.rpc("notifications/initialized", msg_id=None).status_code, 202)

    def test_unknown_protocol_version_falls_back(self):
        res = self.rpc("initialize", {"protocolVersion": "1999-01-01"})
        self.assertEqual(res.json()["result"]["protocolVersion"], mcp_http.LATEST_PROTOCOL_VERSION)

    def test_tools_list_has_annotations(self):
        tools = {t["name"]: t for t in self.rpc("tools/list").json()["result"]["tools"]}
        self.assertIn("save_report", tools)
        self.assertTrue(tools["list_hosts"]["annotations"]["readOnlyHint"])
        self.assertFalse(tools["save_report"]["annotations"]["readOnlyHint"])

    def test_unknown_method(self):
        self.assertEqual(self.rpc("nope/x").json()["error"]["code"], -32601)

    def test_parse_error(self):
        res = self.client.post(URL, data="{not json", content_type="application/json",
                               HTTP_AUTHORIZATION=f"Bearer {self.token}")
        self.assertEqual(res.json()["error"]["code"], -32700)

    # --- tools ------------------------------------------------------------
    def test_get_organization_counts(self):
        data = self.call("get_organization")["structuredContent"]["data"]
        self.assertEqual(data["name"], "Acme")
        self.assertEqual(data["scan_counts"]["completed"], 2)
        self.assertEqual(data["domains"], ["acme.test"])

    def test_list_scans_scoped_to_org(self):
        env = self.call("list_scans")["structuredContent"]
        ids = {s["scan_id"] for s in env["data"]}
        self.assertEqual(ids, {str(self.scan.id), str(self.prev.id)})

    def test_other_org_scan_is_invisible(self):
        result = self.call("get_scan", scan_id=str(self.foreign.id))
        self.assertTrue(result["isError"])
        self.assertIn("No scan", result["structuredContent"]["meta"]["message"])

    def test_bad_uuid_is_tool_error(self):
        result = self.call("get_scan", scan_id="not-a-uuid")
        self.assertTrue(result["isError"])

    def test_list_hosts_pagination_and_filters(self):
        env = self.call("list_hosts", scan_id=str(self.scan.id), limit=2)["structuredContent"]
        self.assertEqual(env["meta"]["total"], 5)
        self.assertEqual(env["meta"]["count"], 2)
        self.assertEqual(env["meta"]["nextCursor"], "2")
        page2 = self.call("list_hosts", scan_id=str(self.scan.id), limit=2, cursor="2")["structuredContent"]
        self.assertNotEqual(env["data"][0]["url"], page2["data"][0]["url"])
        forbidden = self.call("list_hosts", scan_id=str(self.scan.id), status="403")["structuredContent"]
        self.assertTrue(all(h["status"] == 403 for h in forbidden["data"]))
        new = self.call("list_hosts", scan_id=str(self.scan.id), new_only=True)["structuredContent"]
        self.assertEqual({h["url"] for h in new["data"]}, {"https://h3.acme.test", "https://h4.acme.test"})

    def test_search_and_technologies(self):
        hits = self.call("search_hosts", query="admin")["structuredContent"]["data"]
        self.assertEqual([h["url"] for h in hits], ["https://h0.acme.test"])
        techs = self.call("list_technologies", scan_id=str(self.scan.id))["structuredContent"]["data"]
        self.assertEqual({t["technology"] for t in techs}, {"nginx:1.18", "PHP"})

    def test_diff_scans_defaults_to_previous(self):
        data = self.call("diff_scans", scan_id=str(self.scan.id))["structuredContent"]["data"]
        self.assertEqual(data["previous_scan_id"], str(self.prev.id))
        self.assertEqual(data["counts"]["added"], 2)
        self.assertEqual(data["counts"]["removed"], 0)

    def test_save_report_appears_on_reports_page(self):
        result = self.call(
            "save_report", scan_id=str(self.scan.id), title="Acme attack vectors",
            summary="Two exposed admin panels.", content="# Report\n\n<script>alert(1)</script>",
            findings={"attack_vectors": [{"name": "Exposed admin", "severity": "High"}]},
        )
        self.assertFalse(result["isError"])
        report = Report.objects.get()
        self.assertEqual(report.status, Report.Status.COMPLETED)
        self.assertEqual(report.generated_by, "Test agent (MCP)")
        self.assertIn(str(report.id), result["structuredContent"]["data"]["web_url"])
        self.assertContains(self.client.get(reverse("scanner:reports")), "Acme attack vectors")
        detail = self.client.get(reverse("scanner:report_detail", args=[report.id]))
        self.assertNotContains(detail, "<script>alert(1)</script>")  # agent text is escaped

    def test_save_report_validation(self):
        r = self.call("save_report", scan_id=str(self.scan.id), title="", content="x")
        self.assertTrue(r["isError"])
        r = self.call("save_report", scan_id=str(self.foreign.id), title="t", content="x")
        self.assertTrue(r["isError"])
        self.assertEqual(Report.objects.count(), 0)

    def test_prompt(self):
        prompts = self.rpc("prompts/list").json()["result"]["prompts"]
        self.assertEqual(prompts[0]["name"], "attack_vector_report")
        msg = self.rpc("prompts/get", {"name": "attack_vector_report", "arguments": {}}).json()["result"]
        self.assertIn("Acme", msg["messages"][0]["content"]["text"])


class McpConnectPageTests(TestCase):
    def setUp(self):
        self.acme = Program.objects.create(name="Acme")

    def test_page_renders_docs(self):
        res = self.client.get(reverse("scanner:mcp_guide"))
        self.assertContains(res, "Connect your own agent")
        self.assertContains(res, "/api/mcp")
        self.assertContains(res, "save_report")

    def test_connect_shows_token_once_and_it_works(self):
        res = self.client.post(reverse("scanner:mcp_connect"), {"program": self.acme.id, "label": "My Claude"})
        self.assertEqual(res.status_code, 302)
        page = self.client.get(reverse("scanner:mcp_guide"))
        token = McpToken.objects.get()
        self.assertEqual(token.label, "My Claude")
        plaintext = page.context["new_token"]["token"]
        self.assertTrue(plaintext.startswith("sx_"))
        self.assertContains(page, plaintext)
        self.assertNotContains(self.client.get(reverse("scanner:mcp_guide")), plaintext)  # once only
        self.assertEqual(mcp_http.authenticate(f"Bearer {plaintext}"), token)

    def test_connect_requires_org(self):
        self.client.post(reverse("scanner:mcp_connect"), {"program": ""})
        self.assertEqual(McpToken.objects.count(), 0)

    def test_revoke_only_own_connections(self):
        self.client.post(reverse("scanner:mcp_connect"), {"program": self.acme.id})
        mine = McpToken.objects.get()
        other_browser = self.client_class()
        other_browser.post(reverse("scanner:mcp_revoke", args=[mine.id]))
        mine.refresh_from_db()
        self.assertIsNone(mine.revoked_at)
        self.client.post(reverse("scanner:mcp_revoke", args=[mine.id]))
        mine.refresh_from_db()
        self.assertIsNotNone(mine.revoked_at)
