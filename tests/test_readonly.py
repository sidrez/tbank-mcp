"""Read-only boundary tests. No bank credentials or network required."""
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_TMP = tempfile.TemporaryDirectory()
for name, filename in {
    "TBANK_SESSION": "session.json", "TBANK_CA_BUNDLE": "bundle.pem",
    "TBANK_TRACE_FILE": "calls.jsonl", "TBANK_EVENTS": "events.jsonl",
    "TBANK_ATTEMPTS": "attempts.jsonl",
}.items():
    os.environ[name] = str(Path(_TMP.name) / filename)
os.environ["TBANK_TRACE"] = "0"

import requests
from requests.adapters import BaseAdapter
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from tbank_mcp import server
from tbank_mcp.client import MobileSession, TbankApiError
from tbank_mcp.endpoints import BUILTIN_ENDPOINTS
from tbank_mcp.readonly import (
    READONLY_SECTIONS, READONLY_TOOLS, ReadOnlyHTTP, ReadOnlyMobileSession,
)


class FakeBank(BaseAdapter):
    def __init__(self, payload=None, redirect=None):
        self.sent = []
        self.payload = payload if payload is not None else {"resultCode": "OK", "payload": []}
        self.redirect = redirect

    def send(self, request, **kwargs):
        self.sent.append(request)
        r = requests.Response()
        r.request, r.url = request, request.url
        r.status_code = 302 if self.redirect else 200
        r._content = json.dumps(self.payload).encode()
        if self.redirect:
            r.headers["Location"] = self.redirect
        return r

    def close(self):
        pass


class ReadonlyTests(unittest.TestCase):
    def session(self, payload=None):
        s = ReadOnlyMobileSession(mobile_sessionid="TEST", refresh_token="TEST")
        s._minted_at = time.time()
        bank = FakeBank(payload)
        s._http.mount("https://", bank)
        return s, bank

    def test_registry_is_exact_and_annotated(self):
        tools = {t.name: t for t in server.mcp._tool_manager.list_tools()}
        self.assertEqual(set(tools), READONLY_TOOLS)
        self.assertEqual(len(tools), 17)
        for tool in tools.values():
            self.assertTrue(tool.annotations.readOnlyHint)
            self.assertFalse(tool.annotations.destructiveHint)

    def test_new_tool_is_not_published(self):
        @server.mcp.tool()
        def accidentally_added_write():
            return "must not be reachable"
        self.assertNotIn("accidentally_added_write", {t.name for t in server.mcp._tool_manager.list_tools()})

    def test_load_always_installs_guard(self):
        Path(server._SESSION_FILE).write_text(json.dumps({
            "mobile_sessionid": "TEST", "refresh_token": "TEST",
        }), encoding="utf-8")
        s = server._load_session()
        self.assertIsInstance(s, ReadOnlyMobileSession)
        self.assertIsInstance(s._http, ReadOnlyHTTP)

    def test_accounts_use_real_parser_and_guarded_transport(self):
        s, bank = self.session({"resultCode": "OK", "payload": [{"id": "ACC", "name": "Test"}]})
        self.assertEqual(s.list_accounts()[0]["id"], "ACC")
        self.assertEqual(len(bank.sent), 1)

    def test_every_get_data_section_has_allowed_route(self):
        s, bank = self.session()
        # CLIENT-level checks are tested separately; no mock of transport/parser.
        s.ensure_client_session = lambda: "CLIENT"
        for section in READONLY_SECTIONS:
            s.get_data(section, "ACC")
        self.assertEqual(len(bank.sent), len(READONLY_SECTIONS))

    def test_nonfinancial_post_and_token_rotation(self):
        s, bank = self.session({"access_token": "NEW", "refresh_token": "ROTATED", "mobile": {"sessionid": "NEW-SID"}})
        persisted = []
        s._on_persist = lambda: persisted.append(s.refresh_token)
        s.refresh()
        self.assertEqual(persisted, ["ROTATED"])
        s.keepalive()
        self.assertEqual(len(bank.sent), 2)

    def test_pay_cancel_and_arbitrary_methods_never_reach_wire(self):
        s, bank = self.session()
        for method, url in [
            ("POST", "https://api.t-bank-app.ru/v1/pay"),
            ("POST", "https://api.t-bank-app.ru/v1/confirm"),
            ("GET", "https://api.t-bank-app.ru/v1/sign_out"),
            ("PUT", "https://api.t-bank-app.ru/v1/accounts_light"),
            ("DELETE", "https://api.t-bank-app.ru/v1/accounts_light"),
            ("GET", "https://example.com/v1/accounts_light"),
            ("GET", "http://api.t-bank-app.ru/v1/accounts_light"),
            ("GET", "https://api.t-bank-app.ru:8443/v1/accounts_light"),
            ("GET", "https://api.t-bank-app.ru/v1/card_credentials"),
        ]:
            with self.subTest(method=method, url=url), self.assertRaises(TbankApiError):
                s._http.request(method, url)
        self.assertEqual(bank.sent, [])

    def test_redirect_is_checked_before_second_send(self):
        http = ReadOnlyHTTP()
        bank = FakeBank(redirect="https://api.t-bank-app.ru/v1/sign_out?sessionid=SECRET")
        http.mount("https://", bank)
        with self.assertRaises(TbankApiError) as error:
            http.get("https://api.t-bank-app.ru/v1/accounts_light")
        self.assertNotIn("SECRET", str(error.exception))
        self.assertEqual(len(bank.sent), 1)

    def test_auth_code_grant_and_untrusted_token_url_blocked(self):
        s, bank = self.session()
        with self.assertRaises(TbankApiError):
            s._http.post(s.token_url, data={"grant_type": "authorization_code"})
        s.token_url = "https://example.com/token"
        with self.assertRaises(TbankApiError):
            s.refresh()
        self.assertEqual(bank.sent, [])

    def test_template_mutation_cannot_bypass_policy(self):
        s, bank = self.session()
        with patch.dict(BUILTIN_ENDPOINTS, {"accounts_light": {
            "host": "https://api.t-bank-app.ru", "method": "POST", "path": "/v1/pay", "params": {},
        }}):
            with self.assertRaises(TbankApiError):
                s.list_accounts()
        self.assertEqual(bank.sent, [])

    def test_forbidden_get_data_before_session_or_http(self):
        s, bank = self.session()
        for section in ["v1_pay", "grocery_cart_set", "order_cancel", "profile", "requisites"]:
            with self.assertRaises(TbankApiError):
                s.get_data(section)
            with patch.object(server, "_require", side_effect=AssertionError("must not load")):
                self.assertIn("READ_ONLY_SECTION", server.get_data(section))
        self.assertEqual(bank.sent, [])

    def test_new_auth_jar_and_signed_calls_blocked(self):
        s, bank = self.session()
        for action in [s._fresh_jar, lambda: s._call_signed("v1_pay", "{}"), s.silent_relogin]:
            with self.assertRaises(TbankApiError):
                action()
        self.assertEqual(bank.sent, [])

    def test_expired_refresh_does_not_silent_login(self):
        s, bank = self.session()
        s._minted_at = 0
        with patch.object(s, "refresh", side_effect=TbankApiError("expired", "expired")), patch.object(s, "silent_relogin") as silent:
            with self.assertRaises(TbankApiError):
                s.ensure_fresh()
            silent.assert_not_called()

    def test_interactive_cli_still_uses_separate_login_client(self):
        self.assertIs(type(server._blank_session()), MobileSession)

    def test_real_stdio_mcp_discovery_and_unknown_tools(self):
        async def probe():
            params = StdioServerParameters(
                command=sys.executable, args=["-m", "tbank_mcp.server"], env=dict(os.environ),
            )
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    self.assertEqual({t.name for t in tools.tools}, READONLY_TOOLS)
                    for name in ["transfer", "pay_bill", "confirm_payment", "login", "messenger_send"]:
                        result = await session.call_tool(name, {})
                        self.assertTrue(result.isError, name)
                    result = await session.call_tool("flows", {})
                    self.assertFalse(result.isError)
                    result = await session.call_tool("get_data", {"section": "v1_pay"})
                    self.assertIn("READ_ONLY_SECTION", str(result.content))
        asyncio.run(probe())


if __name__ == "__main__":
    unittest.main()
