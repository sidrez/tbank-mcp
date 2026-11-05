"""Exercise public HTTP OAuth/PKCE and MCP without live bank data."""
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.fernet import Fernet
from starlette.testclient import TestClient
from tbank_mcp.http_server import create_app


class OAuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "oauth.sqlite"
        self.key = Fernet.generate_key()
        self.issuer = "https://bank.example"
        self.password = "TEST-" + "x" * 40
        self.app = create_app(self.issuer, self.password, self.key, self.path)
        self.client = TestClient(self.app, base_url=self.issuer)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        self.addCleanup(self.tmp.cleanup)
        self.verifier = "v" * 64
        self.challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).decode().rstrip("=")
        r = self.client.post("/register", json={"redirect_uris": ["https://chatgpt.com/connector/oauth/test-callback"],
            "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"], "scope": "bank:read"})
        self.assertEqual(r.status_code, 201, r.text)
        self.client_id = r.json()["client_id"]

    def authorize(self, password=None, resource=None, csrf=True):
        r = self.client.get("/authorize", params={"client_id": self.client_id, "redirect_uri": "https://chatgpt.com/connector/oauth/test-callback",
            "response_type": "code", "code_challenge": self.challenge, "code_challenge_method": "S256", "scope": "bank:read",
            "state": "test-state", "resource": resource or self.issuer + "/mcp"}, follow_redirects=False)
        if r.status_code != 302:
            return r
        if "error=" in r.headers["location"]:
            return r
        consent = self.client.get(r.headers["location"])
        nonce = parse_qs(urlsplit(r.headers["location"]).query)["request"][0]
        token = re.search(r'name="csrf" value="([^"]+)"', consent.text).group(1)
        return self.client.post("/consent", data={"request": nonce, "csrf": token if csrf else "wrong", "password": password or self.password}, follow_redirects=False)

    def token(self, code, verifier=None):
        return self.client.post("/token", data={"grant_type": "authorization_code", "client_id": self.client_id,
            "code": code, "redirect_uri": "https://chatgpt.com/connector/oauth/test-callback", "code_verifier": verifier or self.verifier,
            "resource": self.issuer + "/mcp"})

    def linked(self):
        r = self.authorize()
        self.assertEqual(r.status_code, 303, r.text)
        q = parse_qs(urlsplit(r.headers["location"]).query)
        self.assertEqual(q["state"], ["test-state"])
        r = self.token(q["code"][0])
        self.assertEqual(r.status_code, 200, r.text)
        return r.json(), q["code"][0]

    def mcp(self, access):
        return self.client.post("/mcp", headers={"Authorization": "Bearer " + access,
            "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})

    def test_metadata_and_unauthenticated_rejection(self):
        r = self.client.post("/mcp", json={})
        self.assertEqual(r.status_code, 401)
        self.assertIn("resource_metadata=", r.headers["www-authenticate"])
        auth = self.client.get("/.well-known/oauth-authorization-server").json()
        self.assertEqual(auth["issuer"].rstrip("/"), self.issuer)
        self.assertIn("S256", auth["code_challenge_methods_supported"])
        self.assertEqual(self.client.get("/.well-known/oauth-protected-resource/mcp").json()["resource"], self.issuer + "/mcp")

    def test_full_link_and_exact_readonly_tools(self):
        tok, _ = self.linked()
        r = self.mcp(tok["access_token"])
        self.assertEqual(r.status_code, 200, r.text)
        tools = r.json()["result"]["tools"]
        self.assertEqual(len(tools), 17)
        self.assertNotIn("transfer", {t["name"] for t in tools})

    def test_password_csrf_and_audience(self):
        self.assertEqual(self.authorize(password="wrong").status_code, 403)
        self.assertEqual(self.authorize(csrf=False).status_code, 400)
        self.assertIn("error=invalid_request", self.authorize(resource="https://attacker.example").headers["location"])

    def test_pkce_and_code_replay(self):
        r = self.authorize()
        code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
        self.assertEqual(self.token(code, "wrong").status_code, 400)
        self.assertEqual(self.token(code).status_code, 200)
        self.assertEqual(self.token(code).status_code, 400)

    def test_refresh_rotation_and_revoke(self):
        tok, _ = self.linked()
        args = {"grant_type": "refresh_token", "client_id": self.client_id, "refresh_token": tok["refresh_token"], "resource": self.issuer + "/mcp"}
        r = self.client.post("/token", data=args)
        self.assertEqual(r.status_code, 200, r.text)
        new = r.json()
        self.assertEqual(self.client.post("/token", data=args).status_code, 400)
        self.assertEqual(self.mcp(tok["access_token"]).status_code, 401)
        self.assertEqual(self.mcp(new["access_token"]).status_code, 200)
        revoked = self.client.post("/revoke", data={"client_id": self.client_id, "token": new["refresh_token"], "token_type_hint": "refresh_token"})
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertEqual(self.mcp(new["access_token"]).status_code, 401)

    def test_redirect_allowlist_and_encrypted_persistence(self):
        r = self.client.post("/register", json={"redirect_uris": ["https://attacker.example"], "token_endpoint_auth_method": "none"})
        self.assertEqual(r.status_code, 400)
        tok, _ = self.linked()
        content = self.path.read_bytes()
        self.assertNotIn(tok["access_token"].encode(), content)
        self.assertNotIn(tok["refresh_token"].encode(), content)
        # A restart keeps the same client and tokens, given the same vault key.
        app = create_app(self.issuer, self.password, self.key, self.path)
        with TestClient(app, base_url=self.issuer) as other:
            self.assertEqual(other.get("/healthz").status_code, 200)
            r = other.post("/token", data={"grant_type": "refresh_token", "client_id": self.client_id,
                "refresh_token": tok["refresh_token"], "resource": self.issuer + "/mcp"})
            self.assertEqual(r.status_code, 200, r.text)


if __name__ == "__main__":
    unittest.main()
