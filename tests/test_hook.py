import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import vet402  # noqa: E402
from vet402 import client  # noqa: E402


def fake(status, **extra):
    base = {"status": status, "url": "https://seller.example/api", "reasons": ["l1_paid_not_delivered"],
            "paid_attempts": 4, "settled": 4, "delivered": 1, "page": "https://vet402.com/observatory/e/x",
            "why": "vet402 has no record of this URL."}
    base.update(extra)
    return base


class Hook(unittest.TestCase):
    def call(self, status, tool="mpp_fetch", url="https://seller.example/api"):
        with mock.patch.object(client, "lookup", return_value=fake(status)):
            return vet402.before_tool(tool, {"url": url}, task_id="t")

    def test_block_vetoes_the_call(self):
        d = self.call("BLOCK")
        self.assertEqual(d["action"], "block")
        self.assertIn("vet402 says BLOCK", d["message"])
        self.assertIn("4 settled, 1 delivered", d["message"])

    def test_warn_asks_the_human(self):
        self.assertEqual(self.call("WARN")["action"], "approve")

    def test_allow_runs(self):
        self.assertIsNone(self.call("ALLOW"))

    def test_unknown_and_outage_run_by_default(self):
        self.assertIsNone(self.call("unknown"))
        self.assertIsNone(self.call("unavailable"))

    def test_unknown_can_ask_the_human(self):
        with mock.patch.dict(os.environ, {"VET402_UNKNOWN": "approve"}):
            self.assertEqual(self.call("unknown")["action"], "approve")

    def test_other_tools_and_non_http_are_ignored(self):
        with mock.patch.object(client, "lookup", side_effect=AssertionError("must not look up")):
            self.assertIsNone(vet402.before_tool("web_search", {"url": "https://a.example"}))
            self.assertIsNone(vet402.before_tool("mpp_fetch", {"url": "file:///etc/passwd"}))

    def test_guard_list_comes_from_env(self):
        with mock.patch.dict(os.environ, {"VET402_GUARD_TOOLS": "mpp_fetch, x402_fetch"}):
            self.assertEqual(self.call("BLOCK", tool="x402_fetch")["action"], "block")

    def test_lookup_error_does_not_break_the_agent(self):
        with mock.patch.object(client, "lookup", side_effect=RuntimeError("boom")):
            self.assertIsNone(vet402.before_tool("mpp_fetch", {"url": "https://a.example"}))


class Tool(unittest.TestCase):
    def test_rejects_non_url(self):
        self.assertIn("error", json.loads(vet402.vet402_check({"url": "nope"})))

    def test_returns_lookup(self):
        with mock.patch.object(client, "lookup", return_value=fake("ALLOW")):
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
