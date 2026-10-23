"""Prevention tests for the eight misses in the 2026-10-24 audit.

Expected results come from the audit and from the record fixtures (an amount of
10000 base units with 6 decimals is 0.01). They are not copied from a printed
lookup.
"""

from __future__ import annotations

import json
import math
import os
import re
import socket
import sys
import threading
import time
import unittest
import urllib.parse
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import vet402  # noqa: E402
from vet402 import client  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RID = "ab" * 32
SELLER = "https://seller.example/api"

_ENV = (
    "HERMES_YOLO_MODE",
    "HERMES_CRON_SESSION",
    "HERMES_SINGLE_QUERY_SESSION",
    "HERMES_KANBAN_TASK",
    "HERMES_SESSION_PLATFORM",
    "HERMES_PLATFORM",
    "HERMES_INTERACTIVE",
    "HERMES_GATEWAY_SESSION",
    "HERMES_EXEC_ASK",
    "HERMES_HOME",
    "VET402_UNKNOWN",
    "VET402_GUARD_TOOLS",
    "VET402_API",
    "VET402_TIMEOUT_S",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
)


def fake(status, url=SELLER, adverse=("vet402 paid and got nothing back",), **extra):
    base = {
        "status": status,
        "url": url,
        "method": "GET",
        "reasons": ["l1_paid_not_delivered"],
        "adverse": list(adverse),
        "paid_attempts": 4,
        "settled": 4,
        "delivered": 1,
        "page": "https://vet402.com/observatory/e/x",
        "why": "vet402 has no record of this URL or its host.",
        "price": "No verified price is on record, so the amount would be whatever the seller asks.",
    }
    base.update(extra)
    return base


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = {key: values[0] for key, values in urllib.parse.parse_qs(parsed.query).items()}
        self.server.seen.append(self.path)
        self.server.agents.append(self.headers.get("User-Agent"))
        action = self.server.action(parsed.path, query)
        kind = action[0]
        if kind == "sleep":
            time.sleep(action[1])
            self._json(200, action[2])
            return
        if kind == "redirect":
            self.send_response(action[2] if len(action) > 2 else 302)
            self.send_header("Location", action[1])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if kind == "raw":
            raw = action[2] if isinstance(action[2], bytes) else str(action[2]).encode()
            self.send_response(action[1])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        self._json(action[1], action[2])

    def _json(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def resource(method="GET", rid=RID, url=SELLER, obs="obs1", endpoints=None):
    body = {"resource_id": rid, "canonical_url": "https://attacker.example/chosen", "observatory_id": obs}
    if method is not None:
        body["method"] = method
    return {"resource": body, "endpoints": [{}] if endpoints is None else endpoints}


def decision(rec, reasons, attempts=1, delivered=0, terms=None):
    body = {
        "recommendation": rec,
        "reason_codes": reasons,
        "rules_version": "2026-09-29.4",
        "facts": {"l1": {"n_attempts": attempts, "n_settled": attempts, "n_delivered": delivered}},
    }
    if terms is not None:
        body["verified_terms"] = terms
    return body


class Isolated(unittest.TestCase):
    def setUp(self):
        client._cache.clear()
        self._saved_env = {key: os.environ.get(key) for key in _ENV}
        for key in _ENV:
            os.environ.pop(key, None)
        os.environ["NO_PROXY"] = "*"
        os.environ["no_proxy"] = "*"
        self._api = client.API
        self._timeout = client.TIMEOUT_S

    def tearDown(self):
        client.API = self._api
        client.TIMEOUT_S = self._timeout
        client._cache.clear()
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def hook(self, url=SELLER, method=None, tool="mpp_fetch", **extra):
        args = {"url": url}
        if method is not None:
            args["method"] = method
        args.update(extra)
        return vet402.before_tool(tool, args, task_id="t")

    def boot(self, action):
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        httpd.action = action
        httpd.seen = []
        httpd.agents = []
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(httpd.shutdown)
        self.addCleanup(httpd.server_close)
        return httpd

    def use(self, httpd, timeout=1):
        client.API = f"http://127.0.0.1:{httpd.server_address[1]}"
        client.TIMEOUT_S = timeout
        return client.API


class Hook(Isolated):
    def test_block_stops_and_says_nothing_was_paid(self):
        with mock.patch.object(client, "lookup", return_value=fake("BLOCK")):
            outcome = vet402.before_tool("mpp_fetch", {"url": SELLER}, task_id="t")
        self.assertEqual(outcome["action"], "block")
        self.assertIn("vet402 says BLOCK", outcome["message"])
        self.assertIn("4 settled, 1 delivered", outcome["message"])
        self.assertIn("The payment was not made.", outcome["message"])
        self.assertIn(SELLER, outcome["message"])

    def test_a_guarded_tool_that_names_the_url_uri_is_still_checked(self):
        # 2026-10-24 audit, hole 8: the hook read only args["url"], so a guarded tool that passed the paid URL
        # as uri, endpoint or any other key ran with no lookup.
        for key in ("uri", "endpoint", "target_url"):
            with self.subTest(key=key):
                with mock.patch.object(client, "lookup", return_value=fake("BLOCK")) as lookup:
                    outcome = vet402.before_tool("mpp_fetch", {key: SELLER, "method": "POST"}, task_id="t")
                self.assertEqual(outcome["action"], "block")
                lookup.assert_called_once()
                self.assertEqual(lookup.call_args.args[0], SELLER)

    def test_an_uppercase_scheme_is_still_checked(self):
        # 2026-10-24 review: HTTPS://... skipped the hook, and httpx pays it the same as https://.
        for url in ("HTTPS://seller.example/pay", "Http://seller.example/pay"):
            with self.subTest(url=url):
                with mock.patch.object(client, "lookup", return_value=fake("BLOCK")) as lookup:
                    outcome = vet402.before_tool("mpp_fetch", {"url": url}, task_id="t")
                self.assertEqual(outcome["action"], "block")
                self.assertTrue(lookup.call_args.args[0].startswith("http"))

    def test_an_unexpected_error_refuses_instead_of_paying(self):
        with mock.patch.object(vet402, "_check", side_effect=ValueError("bad port")):
            outcome = vet402.before_tool("mpp_fetch", {"url": SELLER}, task_id="t")
        self.assertEqual(outcome["action"], "block")
        self.assertIn("The payment was not made.", outcome["message"])

    def test_always_for_one_warn_does_not_cover_a_different_warn(self):
        os.environ.pop("HERMES_YOLO_MODE", None)
        with mock.patch.object(vet402, "person_can_answer", return_value=True):
            with mock.patch.object(client, "lookup", return_value=fake("WARN", adverse=["l1_stale"])):
                first = vet402.before_tool("mpp_fetch", {"url": SELLER}, task_id="t")
            with mock.patch.object(client, "lookup", return_value=fake("WARN", adverse=["l1_paid_not_delivered"])):
                second = vet402.before_tool("mpp_fetch", {"url": SELLER}, task_id="t")
        self.assertEqual(first["action"], "approve")
        self.assertEqual(second["action"], "approve")
        self.assertNotEqual(first["rule_key"], second["rule_key"])

    def test_an_empty_guard_list_is_logged_once(self):
        os.environ["VET402_GUARD_TOOLS"] = ""
        vet402._warned_empty_guard = False
        with self.assertLogs("vet402", level="WARNING") as logs:
            self.assertIsNone(vet402.before_tool("mpp_fetch", {"url": SELLER}, task_id="t"))
            self.assertIsNone(vet402.before_tool("mpp_fetch", {"url": SELLER}, task_id="t"))
        self.assertEqual(sum("VET402_GUARD_TOOLS is empty" in line for line in logs.output), 1)

    def test_block_still_stops_when_yolo_is_on(self):
        os.environ["HERMES_YOLO_MODE"] = "1"
        with mock.patch.object(client, "lookup", return_value=fake("BLOCK")):
            outcome = self.hook()
        self.assertEqual(outcome["action"], "block")
        self.assertIn("The payment was not made.", outcome["message"])

    def test_allow_runs_including_when_nobody_is_here(self):
        os.environ["HERMES_YOLO_MODE"] = "1"
        with mock.patch.object(client, "lookup", return_value=fake("ALLOW", adverse=(), reasons=["l0_pass"])):
            self.assertIsNone(self.hook())

    def test_warn_with_evidence_asks_and_names_the_url(self):
        os.environ["HERMES_INTERACTIVE"] = "1"
        with mock.patch.object(client, "lookup", return_value=fake("WARN", method="POST")):
            outcome = self.hook(method="POST")
        self.assertEqual(outcome["action"], "approve")
        self.assertIn("Why: vet402 paid and got nothing back.", outcome["message"])
        self.assertIn("Refusing pays nothing.", outcome["message"])
        self.assertIn(SELLER, outcome["rule_key"])
        self.assertIn("POST", outcome["rule_key"])
        self.assertTrue(outcome["rule_key"].startswith("vet402:WARN:"))

    def test_approval_is_keyed_per_url_and_method(self):
        os.environ["HERMES_INTERACTIVE"] = "1"
        with mock.patch.object(client, "lookup", side_effect=lambda url, method="GET": fake("WARN", url=client.bare_url(url), method=method)):
            first = self.hook(url="https://a.example/x")
            second = self.hook(url="https://b.example/y")
            posted = self.hook(url="https://a.example/x", method="post")
        self.assertNotEqual(first["rule_key"], second["rule_key"])
        self.assertNotEqual(first["rule_key"], posted["rule_key"])
        self.assertIn("POST", posted["rule_key"])

    def test_only_l1_not_attempted_runs(self):
        os.environ["HERMES_YOLO_MODE"] = "1"
        record = fake("WARN", reasons=["l1_not_attempted"], adverse=(), paid_attempts=None)
        with mock.patch.object(client, "lookup", return_value=record):
            self.assertIsNone(self.hook())

    def test_l1_not_attempted_with_a_clean_extra_code_still_runs(self):
        record = fake(
            "WARN",
            reasons=["l1_not_attempted", "l2_conform"],
            adverse=(),
            paid_attempts=None,
        )
        with mock.patch.object(client, "lookup", return_value=record):
            self.assertIsNone(self.hook())

    def test_empty_warn_reasons_do_not_claim_not_bought(self):
        os.environ["HERMES_INTERACTIVE"] = "1"
        record = fake("WARN", reasons=[], adverse=(), paid_attempts=None)
        with mock.patch.object(client, "lookup", return_value=record):
            outcome = self.hook()
        self.assertEqual(outcome["action"], "approve")
        self.assertNotIn("has not bought", outcome["message"])
        self.assertIn("Refusing pays nothing.", outcome["message"])

    def test_other_tools_non_http_and_null_args_are_ignored(self):
        with mock.patch.object(client, "lookup", side_effect=AssertionError("must not look up")):
            self.assertIsNone(vet402.before_tool("web_search", {"url": "https://a.example"}))
            self.assertIsNone(vet402.before_tool("mpp_fetch", {"url": "file:///etc/passwd"}))
            self.assertIsNone(vet402.before_tool("mpp_fetch", None))

    def test_guard_list_comes_from_env(self):
        os.environ["VET402_GUARD_TOOLS"] = "mpp_fetch, x402_fetch"
        with mock.patch.object(client, "lookup", return_value=fake("BLOCK")):
            self.assertEqual(self.hook(tool="x402_fetch")["action"], "block")

    def test_lookup_exception_asks_or_denies_and_hides_the_exception_text(self):
        with mock.patch.object(client, "lookup", side_effect=RuntimeError("boom-secret")):
            outcome = vet402.before_tool("mpp_fetch", {"url": "https://a.example"}, task_id="t")
        self.assertEqual(outcome["action"], "block")
        self.assertNotIn("boom-secret", outcome["message"])
        self.assertIn("The payment was not made.", outcome["message"])

    def test_explicit_allow_skips_only_unknown_and_unavailable(self):
        os.environ["VET402_UNKNOWN"] = "allow"
        with mock.patch.object(client, "lookup", return_value=fake("unknown")):
            self.assertIsNone(self.hook())
        with mock.patch.object(client, "lookup", return_value=fake("unavailable")):
            self.assertIsNone(self.hook())
        with mock.patch.object(client, "lookup", return_value=fake("WARN")):
            self.assertEqual(self.hook()["action"], "block")
        with mock.patch.object(client, "lookup", return_value=fake("BLOCK")):
            self.assertEqual(self.hook()["action"], "block")
        with mock.patch.object(client, "lookup", return_value=fake("block", reasons=[], adverse=())):
            self.assertIsNotNone(self.hook())
        with mock.patch.object(client, "lookup", return_value=fake("rejected", reasons=[], adverse=())):
            self.assertIsNotNone(self.hook())

    def test_approve_is_not_the_allow_switch(self):
        os.environ["VET402_UNKNOWN"] = "APPROVE"
        os.environ["HERMES_INTERACTIVE"] = "1"
        with mock.patch.object(client, "lookup", return_value=fake("unknown", reasons=[], adverse=())):
            outcome = self.hook()
        self.assertEqual(outcome["action"], "approve")


class NobodyHome(Isolated):
    def _warn(self):
        with mock.patch.object(client, "lookup", return_value=fake("WARN", method="POST")):
            return self.hook(method="POST")

    def test_default_with_no_flags_denies(self):
        outcome = self._warn()
        self.assertEqual(outcome["action"], "block")
        self.assertIn("Nobody is here to approve a payment.", outcome["message"])
        self.assertIn("The payment was not made.", outcome["message"])
        self.assertNotIn("Refusing pays nothing.", outcome["message"])

    def test_yolo_denies_warn(self):
        os.environ["HERMES_YOLO_MODE"] = "1"
        os.environ["HERMES_INTERACTIVE"] = "1"
        outcome = self._warn()
        self.assertEqual(outcome["action"], "block")
        self.assertIn("HERMES_YOLO_MODE is on, so a prompt would be skipped.", outcome["message"])
        self.assertIn("The payment was not made.", outcome["message"])

    def test_loaded_yolo_that_throws_denies_without_the_exception_text(self):
        import types

        module = types.ModuleType("tools.approval")

        def boom():
            raise RuntimeError("yolo-secret")

        module._yolo_active = boom
        sys.modules["tools.approval"] = module
        self.addCleanup(lambda: sys.modules.pop("tools.approval", None))
        os.environ["HERMES_INTERACTIVE"] = "1"
        outcome = self._warn()
        self.assertEqual(outcome["action"], "block")
        self.assertNotIn("yolo-secret", outcome["message"])

    def test_approvals_off_in_config_denies_even_if_interactive(self):
        os.environ["HERMES_INTERACTIVE"] = "1"
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.yaml").write_text("approvals:\n  mode: \"off\" # comment\n", encoding="utf-8")
            os.environ["HERMES_HOME"] = str(root)
            outcome = self._warn()
        self.assertEqual(outcome["action"], "block")
        self.assertIn("Approvals are off, so a prompt would be skipped.", outcome["message"])

    def test_cron_denies(self):
        os.environ["HERMES_CRON_SESSION"] = "1"
        os.environ["HERMES_INTERACTIVE"] = "1"
        outcome = self._warn()
        self.assertEqual(outcome["action"], "block")
        self.assertIn("This is a cron session, so nobody is here to approve it.", outcome["message"])

    def test_single_query_denies_even_though_interactive_is_set(self):
        os.environ["HERMES_SINGLE_QUERY_SESSION"] = "1"
        os.environ["HERMES_INTERACTIVE"] = "1"
        outcome = self._warn()
        self.assertEqual(outcome["action"], "block")
        self.assertIn("single query", outcome["message"])

    def test_kanban_denies(self):
        os.environ["HERMES_KANBAN_TASK"] = "task-1"
        os.environ["HERMES_INTERACTIVE"] = "1"
        outcome = self._warn()
        self.assertEqual(outcome["action"], "block")
        self.assertIn("kanban", outcome["message"])

    def test_unattended_platforms_deny(self):
        os.environ["HERMES_INTERACTIVE"] = "1"
        for name in ("webhook", "msgraph_webhook", "api_server"):
            os.environ["HERMES_SESSION_PLATFORM"] = name
            outcome = self._warn()
            self.assertEqual(outcome["action"], "block", name)
            self.assertIn("no person", outcome["message"])
        os.environ.pop("HERMES_SESSION_PLATFORM", None)
        os.environ["HERMES_PLATFORM"] = "api_server"
        self.assertEqual(self._warn()["action"], "block")

    def test_a_gateway_platform_can_be_asked(self):
        os.environ["HERMES_SESSION_PLATFORM"] = "discord"
        outcome = self._warn()
        self.assertEqual(outcome["action"], "approve")
        self.assertIn("Refusing pays nothing.", outcome["message"])

    def test_exec_ask_can_be_asked(self):
        os.environ["HERMES_EXEC_ASK"] = "1"
        self.assertEqual(self._warn()["action"], "approve")


class ConfigFile(Isolated):
    def test_unset_home_does_not_open_the_default_home(self):
        with mock.patch.object(Path, "home", side_effect=AssertionError("default home")):
            self.assertEqual(vet402._approval_mode_from_home(), "")

    def test_symlink_outside_the_home_is_not_a_mode(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            home.mkdir()
            outside = root / "outside.yaml"
            outside.write_text("approvals:\n  mode: off\n", encoding="utf-8")
            (home / "config.yaml").symlink_to(outside)
            os.environ["HERMES_HOME"] = str(home)
            self.assertEqual(vet402._approval_mode(), "")

    def test_inline_false_and_tabs(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yaml"
            os.environ["HERMES_HOME"] = tmp
            path.write_text("approvals: {mode: off}\n", encoding="utf-8")
            self.assertEqual(vet402._approval_mode(), "off")
            path.write_text("approvals:\n  mode: false\n", encoding="utf-8")
            self.assertEqual(vet402._approval_mode(), "off")
            path.write_text("approvals:\n\tmode: no\n", encoding="utf-8")
            self.assertEqual(vet402._approval_mode(), "off")
            path.write_text("mode: off\n", encoding="utf-8")
            self.assertEqual(vet402._approval_mode(), "")
            path.write_text("approvals:\n  cron_mode: off\n  mode: manual\n", encoding="utf-8")
            self.assertEqual(vet402._approval_mode(), "manual")

    def test_plugin_does_not_import_hermes(self):
        source = (ROOT / "vet402" / "__init__.py").read_text(encoding="utf-8")
        self.assertNotIn("import hermes", source)
        self.assertNotIn("Path.home", source)


class ClientLookup(Isolated):
    def test_query_and_userinfo_never_leave(self):
        self.assertEqual(
            client.bare_url("https://API.Seller.example/v1/q?key=secret&q=x#f"),
            "https://api.seller.example/v1/q",
        )
        self.assertEqual(
            client.bare_url("https://user:sk_live_x@API.example.com:8443/p?q=1#f"),
            "https://api.example.com:8443/p",
        )
        seen = []

        def get(path):
            seen.append(path)
            return {"resource": None, "endpoints": []}

        with mock.patch.object(client, "_get", side_effect=get):
            found = client.lookup("https://seller.example/v1/q?key=secret")
        self.assertEqual(found["status"], "unknown")
        self.assertTrue(all("secret" not in path for path in seen))
        self.assertIn("method=GET", seen[0])

    def test_query_variants_share_one_lookup(self):
        calls = []

        def fetch(url, method):
            calls.append((url, method))
            return fake("ALLOW", url=url, method=method, adverse=(), reasons=["l0_pass"])

        with mock.patch.object(client, "_fetch", side_effect=fetch):
            client.lookup("https://seller.example/a?x=1")
            client.lookup("https://seller.example/a?x=2")
        self.assertEqual(calls, [("https://seller.example/a", "GET")])

    def test_known_host_unknown_path(self):
        with mock.patch.object(client, "_get", return_value={"resource": None, "endpoints": [{}, {}]}):
            found = client.lookup("https://seller.example/new")
        self.assertEqual(found["status"], "unknown")
        self.assertIn("knows other endpoints on this host", found["why"])

    def test_missing_recommendation_is_unavailable_and_not_cached(self):
        answers = iter([
            resource(),
            {"error": "not_found"},
            resource(),
            decision("WARN", ["l1_latest_failed"], attempts=2),
        ])
        with mock.patch.object(client, "_get", side_effect=lambda path: next(answers)):
            first = client.lookup("https://s.example/a")
            second = client.lookup("https://s.example/a")
        self.assertEqual(first["status"], "unavailable")
        self.assertIn("vet402 gave no decision", client.describe(first))
        self.assertEqual(second["status"], "WARN")
        self.assertEqual(second["adverse"], ["vet402's latest purchase failed"])
        self.assertEqual(second["page"], client.API + "/observatory/e/obs1")

    def test_bad_resource_id_is_unknown_and_does_not_fetch_a_decision(self):
        seen = []

        def get(path):
            seen.append(path)
            return resource(rid="not-a-real-id")

        with mock.patch.object(client, "_get", side_effect=get):
            found = client.lookup(SELLER, "GET")
        self.assertEqual(found["status"], "unknown")
        self.assertTrue(all("/decision" not in path for path in seen))

    def test_invalid_method_does_not_call_the_api(self):
        with mock.patch.object(client, "_get", side_effect=AssertionError("must not call")):
            found = client.lookup(SELLER, "BAD METHOD")
        self.assertEqual(found["status"], "unknown")
        self.assertIn("not a name vet402 can record", found["why"])

    def test_attacker_canonical_is_not_the_shown_url(self):
        with mock.patch.object(client, "_get", side_effect=lambda path: resource() if "resolve" in path else decision("BLOCK", ["l0_fail"])):
            found = client.lookup("https://seller.example/pay?token=sek", "GET")
        self.assertEqual(found["url"], "https://seller.example/pay")
        self.assertNotIn("attacker.example", client.describe(found))
        self.assertNotIn("sek", client.describe(found))

    def test_price_uses_integer_base_units(self):
        self.assertEqual(client._format_amount("10000", 6), "0.01")
        unreadable = client._price_sentence({"amount": "10000", "decimals": 99})
        self.assertNotIn("10000", unreadable)
        self.assertNotIn("0.01", unreadable)
        invented = client._price_sentence({"amount": True, "decimals": 6})
        self.assertNotRegex(invented, r"\d")

    def test_describe_never_raises_and_names_not_bought_only_for_that_code(self):
        for record in ({}, {"status": "WARN"}, {"status": "unavailable", "url": "u"}, fake("ALLOW", adverse=())):
            self.assertIsInstance(client.describe(record), str)
        self.assertNotIn("has not bought", client.describe({"status": "WARN", "url": "u"}))
        named = client.describe({"status": "WARN", "url": "u", "reasons": ["l1_not_attempted"], "adverse": []})
        self.assertIn("has not bought from it yet", named)

    def test_lowercase_block_is_not_cached_and_not_allow(self):
        answers = iter([
            resource(),
            decision("block", ["l0_fail"]),
            resource(),
            decision("ALLOW", ["l0_pass"]),
        ])
        with mock.patch.object(client, "_get", side_effect=lambda path: next(answers)):
            first = client.lookup(SELLER)
            second = client.lookup(SELLER)
        self.assertEqual(first["status"], "block")
        self.assertNotEqual(first["status"], "unavailable")
        self.assertEqual(second["status"], "ALLOW")


class Wire(Isolated):
    def test_post_does_not_pass_on_a_get_record(self):
        def action(path, query):
            if path.startswith("/api/v1/resolve"):
                self.assertIn("method", query)
                if query.get("method") == "POST":
                    return ("json", 200, resource(method="POST"))
                return ("json", 200, resource(method="GET"))
            self.assertIn("method", query)
            if query.get("method") == "POST":
                return ("json", 200, decision("BLOCK", ["l1_paid_not_delivered"], attempts=4, delivered=1))
            return ("json", 200, decision("ALLOW", ["l0_pass"], attempts=1))

        httpd = self.boot(action)
        self.use(httpd)
        self.assertIsNone(self.hook("https://seller.example/split", method="GET"))
        blocked = self.hook("https://seller.example/split", method="POST")
        self.assertEqual(blocked["action"], "block")
        self.assertIn("The payment was not made.", blocked["message"])
        self.assertTrue(httpd.seen)
        self.assertTrue(all("method=" in path for path in httpd.seen))
        self.assertNotIn("method=&", "".join(httpd.seen))
        self.assertIn("vet402-hermes/0.2.0", httpd.agents)

    def test_untagged_record_is_get_only(self):
        def action(path, query):
            if path.startswith("/api/v1/resolve"):
                return ("json", 200, resource(method=None))
            return ("json", 200, decision("ALLOW", ["l0_pass"]))

        httpd = self.boot(action)
        self.use(httpd)
        self.assertIsNone(self.hook("https://seller.example/legacy"))
        httpd.seen.clear()
        client._cache.clear()
        outcome = self.hook("https://seller.example/legacy-post", method="POST")
        self.assertEqual(outcome["action"], "block")
        self.assertIn("no POST record", outcome["message"])
        self.assertTrue(all("/decision" not in path for path in httpd.seen))
        self.assertTrue(all("method=POST" in path for path in httpd.seen))

    def test_method_mismatch_card_and_allow_switch(self):
        def action(path, query):
            if "/decision" in path:
                return ("json", 200, decision("ALLOW", ["l0_pass"]))
            return ("json", 200, resource(method="GET"))

        httpd = self.boot(action)
        self.use(httpd)
        os.environ["HERMES_INTERACTIVE"] = "1"
        asked = self.hook("https://seller.example/api", method="POST")
        self.assertEqual(
            asked["message"],
            "About to pay POST https://seller.example/api. "
            "No verified price is on record, so the amount would be whatever the seller asks. "
            "vet402 has no POST record for this URL. Refusing pays nothing.",
        )
        self.assertTrue(all("/decision" not in path for path in httpd.seen))
        os.environ["VET402_UNKNOWN"] = "allow"
        client._cache.clear()
        self.assertIsNone(self.hook("https://seller.example/other", method="POST"))

    def test_old_api_400_is_not_a_grant_even_with_allow(self):
        httpd = self.boot(lambda path, query: ("json", 400, {"error": "invalid_method"}))
        self.use(httpd)
        os.environ["VET402_UNKNOWN"] = "allow"
        outcome = self.hook("https://seller.example/old", method="POST")
        self.assertEqual(outcome["action"], "block")
        self.assertIn("HTTP 400", outcome["message"])
        self.assertNotIn("ALLOW", outcome["message"])

    def test_redirect_to_another_host_is_not_followed_even_with_allow(self):
        evil = self.boot(lambda path, query: ("json", 200, decision("ALLOW", ["l0_pass"])))
        token = "picked-by-attacker"

        def action(path, query):
            return ("redirect", f"http://127.0.0.1:{evil.server_address[1]}/api/v1/resolve?q={token}", 302)

        api = self.boot(action)
        self.use(api)
        os.environ["VET402_UNKNOWN"] = "allow"
        os.environ["HERMES_INTERACTIVE"] = "1"
        outcome = self.hook("https://evil-seller.example/pay", method="POST")
        self.assertEqual(outcome["action"], "approve")
        self.assertIn("redirect", outcome["message"].lower())
        self.assertIn("Refusing pays nothing.", outcome["message"])
        self.assertNotIn(token, outcome["message"])
        self.assertEqual(evil.seen, [])
        self.assertEqual(len(api.seen), 1)

    def test_every_redirect_code_stays_on_the_configured_host(self):
        evil = self.boot(lambda path, query: ("json", 200, decision("ALLOW", ["l0_pass"])))
        codes = {"code": 302}

        def action(path, query):
            return ("redirect", f"http://127.0.0.1:{evil.server_address[1]}/x", codes["code"])

        api = self.boot(action)
        self.use(api)
        for code in (301, 302, 303, 307, 308):
            codes["code"] = code
            client._cache.clear()
            outcome = self.hook(f"https://seller.example/red/{code}")
            self.assertEqual(outcome["action"], "block", code)
        self.assertEqual(evil.seen, [])

    def test_same_host_redirect_is_not_followed(self):
        api_box = {}

        def action(path, query):
            if path.startswith("/api/v1/resolve"):
                return ("redirect", api_box["base"] + f"/api/v1/resources/{RID}/decision?role=payer&method=GET", 302)
            return ("json", 200, decision("ALLOW", ["l0_pass"]))

        httpd = self.boot(action)
        api_box["base"] = self.use(httpd)
        outcome = self.hook("https://seller.example/same-host")
        self.assertEqual(outcome["action"], "block")
        self.assertEqual(len(httpd.seen), 1)


class Hole2(Isolated):
    """The eleven misses. With nobody present, each one refuses. None of them is a pass."""

    def _block(self, url, action, method=None):
        httpd = self.boot(action)
        self.use(httpd, timeout=0.4)
        outcome = self.hook(url, method=method)
        self.assertIsNotNone(outcome, url)
        self.assertEqual(outcome["action"], "block")
        self.assertIn("The payment was not made.", outcome["message"])
        return outcome

    def test_unknown(self):
        outcome = self._block(
            "https://seller.example/missing",
            lambda path, query: ("json", 200, {"resource": None, "endpoints": []}),
        )
        self.assertIn("no record", outcome["message"])

    def test_path_param(self):
        outcome = self._block(
            "https://seller.example/1/quote",
            lambda path, query: ("json", 200, {"resource": None, "endpoints": [{}, {}]}),
        )
        self.assertIn("other endpoints", outcome["message"])

    def test_resolve_404(self):
        outcome = self._block(
            "https://seller.example/nope",
            lambda path, query: ("json", 404, {"error": "not_found"}),
        )
        self.assertNotIn('"action": null', json.dumps(outcome))

    def test_decision_500(self):
        def action(path, query):
            if path.startswith("/api/v1/resolve"):
                return ("json", 200, resource())
            return ("json", 500, {"error": "decision_unavailable"})

        outcome = self._block("https://seller.example/down", action)
        self.assertIn("HTTP 500", outcome["message"])

    def test_decision_429(self):
        def action(path, query):
            if path.startswith("/api/v1/resolve"):
                return ("json", 200, resource())
            return ("json", 429, {"error": "rate_limited"})

        outcome = self._block("https://seller.example/rate", action)
        self.assertIn("HTTP 429", outcome["message"])

    def test_bad_json(self):
        def action(path, query):
            if path.startswith("/api/v1/resolve"):
                return ("json", 200, resource())
            return ("raw", 200, b"not-json")

        outcome = self._block("https://seller.example/badjson", action)
        self.assertIn("not JSON", outcome["message"])

    def test_http_url_rejected_by_the_api(self):
        outcome = self._block(
            "http://seller.example/api",
            lambda path, query: ("json", 400, {"error": "invalid_query"}),
        )
        self.assertIn("HTTP 400", outcome["message"])

    def test_missing_recommendation(self):
        def action(path, query):
            if path.startswith("/api/v1/resolve"):
                return ("json", 200, resource())
            return ("json", 200, {"error": "not_found"})

        outcome = self._block("https://seller.example/norec", action)
        self.assertIn("no decision", outcome["message"])

    def test_lowercase_block(self):
        def action(path, query):
            if path.startswith("/api/v1/resolve"):
                return ("json", 200, resource())
            return ("json", 200, decision("block", ["l0_fail"], attempts=2))

        outcome = self._block("https://seller.example/lower", action)
        self.assertIn("block", outcome["message"])
        os.environ["VET402_UNKNOWN"] = "allow"
        client._cache.clear()
        again = self.hook("https://seller.example/lower")
        self.assertEqual(again["action"], "block")

    def test_timeout(self):
        outcome = self._block(
            "https://seller.example/slow",
            lambda path, query: ("sleep", 2, {"resource": None, "endpoints": []}),
        )
        self.assertIn("timeout", outcome["message"])

    def test_connection_refused(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        client.API = f"http://127.0.0.1:{port}"
        client.TIMEOUT_S = 1
        outcome = self.hook("https://seller.example/closed")
        self.assertEqual(outcome["action"], "block")
        self.assertIn("refused", outcome["message"])

    def test_outage_asks_when_a_person_is_here_and_allow_can_skip_it(self):
        def action(path, query):
            if path.startswith("/api/v1/resolve"):
                return ("json", 200, resource())
            return ("json", 500, {"error": "down"})

        httpd = self.boot(action)
        self.use(httpd)
        os.environ["HERMES_INTERACTIVE"] = "1"
        asked = self.hook("https://seller.example/ask500")
        self.assertEqual(asked["action"], "approve")
        self.assertIn("HTTP 500", asked["message"])
        self.assertIn("Refusing pays nothing.", asked["message"])
        os.environ["VET402_UNKNOWN"] = "allow"
        client._cache.clear()
        self.assertIsNone(self.hook("https://seller.example/allow500"))


class WarnCodes(Isolated):
    def _warn(self, reasons, attempts=2):
        def action(path, query):
            if path.startswith("/api/v1/resolve"):
                return ("json", 200, resource(method="GET"))
            return ("json", 200, decision("WARN", reasons, attempts=attempts))

        httpd = self.boot(action)
        self.use(httpd)
        os.environ["HERMES_INTERACTIVE"] = "1"
        return self.hook(f"https://seller.example/{'-'.join(reasons)}")

    def test_each_named_warn_code_asks_with_the_url(self):
        for code in ("l1_stale", "l0_unverified", "l2_not_checked"):
            client._cache.clear()
            outcome = self._warn([code])
            self.assertEqual(outcome["action"], "approve", code)
            self.assertIn("https://seller.example/", outcome["rule_key"])
            self.assertIn(code, outcome["rule_key"])
            self.assertIn("Refusing pays nothing.", outcome["message"])

    def test_sibling_warn_codes_also_ask(self):
        for code in (
            "l1_inconclusive",
            "l2_mismatch",
            "offer_drifting",
            "dialect_mismatch",
            "data_thin",
            "l0_unverified_partial",
        ):
            client._cache.clear()
            outcome = self._warn([code])
            self.assertEqual(outcome["action"], "approve", code)

    def test_l1_not_attempted_alone_is_a_pass(self):
        def action(path, query):
            if path.startswith("/api/v1/resolve"):
                return ("json", 200, resource(method="GET"))
            return ("json", 200, decision("WARN", ["l1_not_attempted"], attempts=0))

        httpd = self.boot(action)
        self.use(httpd)
        os.environ["HERMES_YOLO_MODE"] = "1"
        self.assertIsNone(self.hook("https://seller.example/not-bought"))

    def test_not_bought_plus_stale_still_asks(self):
        outcome = self._warn(["l1_not_attempted", "l1_stale"])
        self.assertEqual(outcome["action"], "approve")

    def test_delivered_alone_is_not_the_not_bought_pass(self):
        outcome = self._warn(["l1_delivered"])
        self.assertEqual(outcome["action"], "approve")

    def test_warn_card_shows_the_verified_price(self):
        terms = {"amount": "10000", "decimals": 6, "asset": "USDC", "network": "base", "pay_to": "0xabc"}

        def action(path, query):
            if path.startswith("/api/v1/resolve"):
                return ("json", 200, resource(method="POST"))
            return ("json", 200, decision("WARN", ["l1_stale"], attempts=2, delivered=2, terms=terms))

        httpd = self.boot(action)
        api = self.use(httpd)
        os.environ["HERMES_INTERACTIVE"] = "1"
        outcome = self.hook("https://seller.example/priced?token=sekret", method="POST")
        self.assertEqual(outcome["action"], "approve")
        self.assertIn("POST https://seller.example/priced", outcome["message"])
        self.assertIn("The last price vet402 verified was 0.01 of asset USDC on base.", outcome["message"])
        self.assertIn("older than 30 days", outcome["message"])
        self.assertIn("Refusing pays nothing.", outcome["message"])
        self.assertNotIn("sekret", outcome["message"])
        self.assertNotIn("10000", outcome["message"])
        self.assertNotIn("0xabc", outcome["message"])
        self.assertNotIn("attacker.example", outcome["message"])
        self.assertIn(f"{api}/observatory/e/obs1", outcome["message"])


class SecretsOnTheWire(Isolated):
    def test_approval_message_and_request_omit_query_and_userinfo(self):
        def action(path, query):
            if path.startswith("/api/v1/resolve"):
                return ("json", 200, resource(method="GET"))
            return ("json", 200, decision("BLOCK", ["l0_fail"]))

        httpd = self.boot(action)
        self.use(httpd)
        outcome = self.hook("https://user:sk_live_x@Seller.Example/pay?token=sekret#frag")
        self.assertEqual(outcome["action"], "block")
        blob = outcome["message"] + json.dumps(httpd.seen)
        self.assertNotIn("sekret", blob)
        self.assertNotIn("sk_live_x", blob)
        self.assertIn("https://seller.example/pay", outcome["message"])

    def test_uri_alone_is_checked_and_url_wins_when_both_exist(self):
        # Was: uri alone was not checked (2026-10-24 audit, hole 8). A guarded tool's paid URL is looked up
        # whatever key carries it.
        def action(path, query):
            return ("json", 200, resource(method="GET"))

        httpd = self.boot(action)
        self.use(httpd)
        vet402.before_tool("mpp_fetch", {"uri": "https://seller.example/via-uri"}, task_id="t")
        self.assertTrue(any("via-uri" in str(hit) for hit in httpd.seen))
        httpd.seen.clear()
        # decision is BLOCK only after resolve. Make the next response a block.
        def blocking(path, query):
            if path.startswith("/api/v1/resolve"):
                target = query.get("q", "")
                self.assertIn("seller.example/via-url", target)
                self.assertNotIn("via-uri", target)
                return ("json", 200, resource(method="GET"))
            return ("json", 200, decision("BLOCK", ["l0_fail"]))

        httpd.action = blocking
        outcome = vet402.before_tool(
            "mpp_fetch",
            {"url": "https://seller.example/via-url", "uri": "https://seller.example/via-uri"},
            task_id="t",
        )
        self.assertEqual(outcome["action"], "block")
        self.assertIn("via-url", outcome["message"])
        self.assertNotIn("via-uri", outcome["message"])


class ToolAndRegister(Isolated):
    def test_rejects_non_url(self):
        self.assertIn("error", json.loads(vet402.vet402_check({"url": "nope"})))

    def test_returns_lookup(self):
        with mock.patch.object(client, "lookup", return_value=fake("ALLOW", adverse=(), reasons=["l0_pass"])):
            self.assertEqual(json.loads(vet402.vet402_check({"url": "https://a.example"}))["status"], "ALLOW")

    def test_registers_tool_hook_and_skill(self):
        ctx = mock.Mock()
        vet402.register(ctx)
        ctx.register_tool.assert_called_once()
        self.assertEqual(ctx.register_tool.call_args.kwargs["name"], "vet402_check")
        ctx.register_hook.assert_called_once_with("pre_tool_call", vet402.before_tool)
        ctx.register_skill.assert_called_once()
        self.assertEqual(ctx.register_skill.call_args.args[0], "vet402")

    def test_register_without_register_skill_still_works(self):
        ctx = mock.Mock(spec=["register_tool", "register_hook"])
        vet402.register(ctx)
        ctx.register_tool.assert_called_once()


class Words(unittest.TestCase):
    def test_tool_description_opens_with_ordinary_words(self):
        description = vet402.SCHEMA["description"]
        first = description.split(".", 1)[0]
        lowered = first.lower()
        tokens = set(re.findall(r"[A-Za-z0-9]+", lowered))
        for word in ("pay", "buy", "seller", "delivered", "should"):
            self.assertIn(word, tokens)
        self.assertIn("before paying", lowered)
        self.assertIn("call a paid api", lowered)

    def test_three_ordinary_requests_rank_in_the_top_five(self):
        catalog = _catalog()
        self.assertGreater(len(catalog), 1)
        self.assertTrue(any(entry[0] == "mpp_fetch" for entry in catalog))
        queries = (
            "Should I pay this API?",
            "Has this seller delivered after I paid?",
            "Look up this paid URL before paying",
        )
        for query in queries:
            names = [entry[0] for entry in _search(catalog, query, limit=5)]
            self.assertIn("vet402_check", names, query)
            self.assertLessEqual(len(names), 5)

    def test_skill_and_readme_say_what_the_audit_required(self):
        skill = (ROOT / "vet402" / "SKILL.md").read_text(encoding="utf-8")
        readme = (ROOT / "vet402" / "README.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("Should I pay this API?", skill)
        self.assertIn("Has this seller delivered after I paid?", skill)
        self.assertIn("Write all of the following", skill)
        for word in ("URL", "method", "verdict", "reason", "evidence"):
            self.assertIn(word, skill)
        front = skill.split("---", 2)[1]
        description = next(line.split(":", 1)[1].strip() for line in front.splitlines() if line.startswith("description:"))
        self.assertEqual(description, vet402._SKILL_DESCRIPTION)
        self.assertLessEqual(len(description), 223)
        lead = readme[:500]
        self.assertIn("HTTPX", lead)
        self.assertIn("MPP_ALLOWED_ORIGINS", lead)
        self.assertIn("l1_not_attempted", readme)
        self.assertIn("HERMES_YOLO_MODE", readme)
        self.assertIn("approvals.mode", readme)
        self.assertIn("cron", readme)
        self.assertIn("tool name", readme)
        self.assertIn("server name", readme)
        self.assertIn("Refusing pays nothing.", readme)
        self.assertIn("VET402_GUARD_TOOLS", readme)
        self.assertIn("any other URL argument", readme)
        self.assertIn("`uri`", readme)
        self.assertIn("&method=", readme)
        self.assertIn("VET402_UNKNOWN=allow", readme)
        self.assertIn("skips the check", readme)
        self.assertNotIn("fails open", readme.lower())
        self.assertIn("l1_not_attempted", changelog)
        self.assertIn("VET402_UNKNOWN=allow", changelog)
        self.assertNotIn("fails open", changelog.lower())
        manifest = (ROOT / "vet402" / "plugin.yaml").read_text(encoding="utf-8")
        self.assertIn("version: 0.2.0", manifest)
        self.assertIn('requires_hermes: ">=0.19.0"', manifest)

    def test_user_facing_english_has_no_forbidden_marks(self):
        for path in (
            ROOT / "README.md",
            ROOT / "CHANGELOG.md",
            ROOT / "vet402" / "README.md",
            ROOT / "vet402" / "SKILL.md",
        ):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(";", text, path.name)
            self.assertNotIn("\u2014", text, path.name)
            self.assertNotIn("\u2013", text, path.name)
            self.assertIsNone(re.search(r"\b(we|our|us)\b", text, re.I), path.name)


def _tokenize(text):
    return re.findall(r"[A-Za-z0-9]+", text.lower())


def _catalog():
    """More than one tool, with common words spread wider than the intent words.

    The gate is the rarest query token. A one-tool catalog would make every
    query rank first, so the fillers are here on purpose.
    """
    fillers = [
        ("mpp_fetch", "Send HTTP requests with the MPP wallet. I use this for HTTP APIs and purchases. Look up a URL before paying it. It handles a 402 automatically."),
        ("web_search", "Search the web. I look up this query and return links and a URL."),
        ("refund_review", "Should you refund this seller if the order has not delivered after I paid? Look up the URL before paying a refund."),
        ("calendar", "I look up this calendar and read what is on it today."),
        ("notes", "I look up this note and read it back from the URL."),
        ("pay_invoice", "Pay this invoice before paying the vendor. I look up the URL and the API."),
        ("api_status", "I check this API status page and look up the URL."),
        ("mailbox", "Has this mailbox delivered after I paid? Look up this URL."),
        ("weather", "I look up this forecast for the week."),
        ("maps", "I look up this place and the route."),
    ]
    description = vet402.SCHEMA["description"]
    return [("vet402_check", description)] + fillers


def _search(catalog, query, limit=5):
    docs = [(name, _tokenize(text)) for name, text in catalog]
    doc_freq = Counter(token for _name, tokens in docs for token in set(tokens))
    n_docs = len(docs)
    query_tokens = _tokenize(query)
    if not query_tokens:
        return []

    def idf(token):
        df = doc_freq.get(token, 0)
        return math.log(1 + (n_docs - df + 0.5) / (df + 0.5))

    gate = max(query_tokens, key=idf)
    answerable = [token for token in query_tokens if doc_freq.get(token, 0) > 0]
    required = 1 if len(answerable) < 4 else math.ceil(len(answerable) * 0.5)
    avg_dl = sum(len(tokens) for _name, tokens in docs) / n_docs
    scored = []
    for name, tokens in docs:
        present = set(tokens)
        if gate not in present:
            continue
        if sum(1 for token in answerable if token in present) < required:
            continue
        tf = Counter(tokens)
        score = 0.0
        dl = len(tokens)
        for token in query_tokens:
            df = doc_freq.get(token, 0)
            freq = tf.get(token, 0)
            if df and freq:
                weight = math.log(1 + (n_docs - df + 0.5) / (df + 0.5))
                score += weight * freq * 2.5 / (freq + 1.5 * (0.25 + 0.75 * dl / max(avg_dl, 1.0)))
        scored.append((score, name))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [(name, score) for score, name in scored[:limit]]


if __name__ == "__main__":
    unittest.main()
