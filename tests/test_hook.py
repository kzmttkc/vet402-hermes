import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import vet402  # noqa: E402
from vet402 import client  # noqa: E402


def fake(status, url="https://seller.example/api", adverse=("vet402 paid and got nothing back",), **extra):
    base = {"status": status, "url": url, "reasons": ["l1_paid_not_delivered"], "adverse": list(adverse),
            "paid_attempts": 4, "settled": 4, "delivered": 1, "page": "https://vet402.com/observatory/e/x",
            "why": "vet402 has no record of this URL or its host."}
    base.update(extra)
    return base


class Hook(unittest.TestCase):
    def call(self, r, tool="mpp_fetch", url="https://seller.example/api", method=None):
        args = {"url": url} if method is None else {"url": url, "method": method}
        with mock.patch.object(client, "lookup", return_value=r):
            return vet402.before_tool(tool, args, task_id="t")

    def test_block_vetoes_the_call(self):
        d = self.call(fake("BLOCK"))
        self.assertEqual(d["action"], "block")
        self.assertIn("vet402 says BLOCK", d["message"])
        self.assertIn("4 settled, 1 delivered", d["message"])

    def test_warn_with_evidence_asks_the_human(self):
        d = self.call(fake("WARN"))
        self.assertEqual(d["action"], "approve")
        self.assertIn("Why: vet402 paid and got nothing back.", d["message"])

    def test_approval_is_keyed_per_url(self):
        # Hermes keys "allow for this session / always" by rule_key, else by tool name.
        a = self.call(fake("WARN", url="https://a.example/x"), url="https://a.example/x")
        b = self.call(fake("WARN", url="https://b.example/y"), url="https://b.example/y")
        post = self.call(fake("WARN", url="https://a.example/x"), url="https://a.example/x", method="post")
        self.assertNotEqual(a["rule_key"], b["rule_key"])
        self.assertNotEqual(a["rule_key"], post["rule_key"])
        self.assertIn("https://a.example/x", a["rule_key"])

    def test_warn_without_evidence_runs_by_default(self):
        self.assertIsNone(self.call(fake("WARN", adverse=(), paid_attempts=None)))

    def test_allow_runs(self):
        self.assertIsNone(self.call(fake("ALLOW", adverse=())))

    def test_unknown_and_outage_run_by_default(self):
        self.assertIsNone(self.call(fake("unknown")))
        self.assertIsNone(self.call(fake("unavailable")))

    def test_unknown_and_unproven_can_ask_the_human(self):
        with mock.patch.dict(os.environ, {"VET402_UNKNOWN": "approve"}):
            self.assertEqual(self.call(fake("unknown"))["action"], "approve")
            self.assertEqual(self.call(fake("WARN", adverse=()))["action"], "approve")
            self.assertIsNone(self.call(fake("ALLOW", adverse=())))

    def test_other_tools_and_non_http_are_ignored(self):
        with mock.patch.object(client, "lookup", side_effect=AssertionError("must not look up")):
            self.assertIsNone(vet402.before_tool("web_search", {"url": "https://a.example"}))
            self.assertIsNone(vet402.before_tool("mpp_fetch", {"url": "file:///etc/passwd"}))
            self.assertIsNone(vet402.before_tool("mpp_fetch", None))

    def test_guard_list_comes_from_env(self):
        with mock.patch.dict(os.environ, {"VET402_GUARD_TOOLS": "mpp_fetch, x402_fetch"}):
            self.assertEqual(self.call(fake("BLOCK"), tool="x402_fetch")["action"], "block")

    def test_lookup_error_does_not_break_the_agent(self):
        with mock.patch.object(client, "lookup", side_effect=RuntimeError("boom")):
            self.assertIsNone(vet402.before_tool("mpp_fetch", {"url": "https://a.example"}))


class Client(unittest.TestCase):
    def setUp(self):
        client._cache.clear()

    def test_query_and_fragment_are_never_sent(self):
        self.assertEqual(client.bare_url("https://API.Seller.example/v1/q?key=secret&q=x#f"),
                         "https://api.seller.example/v1/q")
        seen = []

        def get(path):
            seen.append(path)
            return {"resource": None, "endpoints": []}

        with mock.patch.object(client, "_get", side_effect=get):
            r = client.lookup("https://seller.example/v1/q?key=secret")
        self.assertEqual(r["status"], "unknown")
        self.assertTrue(all("secret" not in p for p in seen))

    def test_query_variants_share_one_lookup(self):
        calls = []
        with mock.patch.object(client, "_fetch", side_effect=lambda u: calls.append(u) or fake("ALLOW", url=u)):
            client.lookup("https://seller.example/a?x=1")
            client.lookup("https://seller.example/a?x=2")
        self.assertEqual(calls, ["https://seller.example/a"])

    def test_known_host_unknown_path(self):
        with mock.patch.object(client, "_get", return_value={"resource": None, "endpoints": [{}, {}]}):
            r = client.lookup("https://seller.example/new")
        self.assertEqual(r["status"], "unknown")
        self.assertIn("knows other endpoints on this host", r["why"])

    def test_missing_recommendation_is_unavailable_and_not_cached(self):
        answers = iter([
            {"resource": {"resource_id": "r1", "canonical_url": "https://s.example/a", "observatory_id": "o1"}},
            {"error": "not_found"},
            {"resource": {"resource_id": "r1", "canonical_url": "https://s.example/a", "observatory_id": "o1"}},
            {"recommendation": "WARN", "reason_codes": ["l1_latest_failed"], "facts": {"l1": {"n_attempts": 2}}},
        ])
        with mock.patch.object(client, "_get", side_effect=lambda p: next(answers)):
            first = client.lookup("https://s.example/a")
            second = client.lookup("https://s.example/a")
        self.assertEqual(first["status"], "unavailable")
        self.assertIn("vet402 gave no decision", client.describe(first))
        self.assertEqual(second["status"], "WARN")
        self.assertEqual(second["adverse"], ["vet402's latest purchase failed"])
        self.assertEqual(second["page"], client.API + "/observatory/e/o1")

    def test_describe_never_raises(self):
        for r in ({}, {"status": "WARN"}, {"status": "unavailable", "url": "u"}, fake("ALLOW", adverse=())):
            self.assertIsInstance(client.describe(r), str)
        self.assertIn("has not bought from it yet", client.describe({"status": "WARN", "url": "u"}))


class Tool(unittest.TestCase):
    def test_rejects_non_url(self):
        self.assertIn("error", json.loads(vet402.vet402_check({"url": "nope"})))

    def test_returns_lookup(self):
        with mock.patch.object(client, "lookup", return_value=fake("ALLOW", adverse=())):
            self.assertEqual(json.loads(vet402.vet402_check({"url": "https://a.example"}))["status"], "ALLOW")


class Register(unittest.TestCase):
    def test_registers_one_tool_and_one_hook(self):
        ctx = mock.Mock()
        vet402.register(ctx)
        ctx.register_tool.assert_called_once()
        self.assertEqual(ctx.register_tool.call_args.kwargs["name"], "vet402_check")
        ctx.register_hook.assert_called_once_with("pre_tool_call", vet402.before_tool)


if __name__ == "__main__":
    unittest.main()
