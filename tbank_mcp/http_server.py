"""Single-owner HTTPS deployment: OAuth + PKCE, no OpenAI API or tunnel.

TLS is terminated by nginx; this process binds only to loopback. The owner
password and state encryption key must be supplied by the deployment vault.
"""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
import hmac
import html
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
from urllib.parse import urlencode, urlsplit

from cryptography.fernet import Fernet
from mcp.server.auth.provider import (
    AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError,
    RefreshToken, RegistrationError, TokenError,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
import uvicorn

from . import server

SCOPE = "bank:read"


def allowed_redirect(uri):
    u = urlsplit(str(uri))
    return (u.scheme == "https" and u.netloc == "chatgpt.com" and not u.query and not u.fragment
            and (u.path == "/connector_platform_oauth_redirect"
                 or re.fullmatch(r"/connector/oauth/[A-Za-z0-9_-]+", u.path) is not None))


class Store:
    def __init__(self, path, key):
        self.path = str(path)
        self.cipher = Fernet(key.encode() if isinstance(key, str) else key)
        self.lock = threading.RLock()
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT, value BLOB, expires REAL, family TEXT, PRIMARY KEY(kind,id))")
        os.chmod(path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=20)
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def digest(value):
        return hashlib.sha256(value.encode()).hexdigest()

    def put(self, kind, identifier, value, expires, family=""):
        encrypted = self.cipher.encrypt(json.dumps(value).encode())
        with self.lock, self.connect() as db:
            db.execute("DELETE FROM records WHERE expires < ?", (time.time(),))
            db.execute("INSERT OR REPLACE INTO records VALUES (?,?,?,?,?)",
                       (kind, self.digest(identifier), encrypted, expires, family))

    def get(self, kind, identifier, consume=False):
        with self.lock, self.connect() as db:
            row = db.execute("SELECT value,expires,family FROM records WHERE kind=? AND id=?",
                             (kind, self.digest(identifier))).fetchone()
            if consume and row:
                db.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, self.digest(identifier)))
            if not row or row[1] <= time.time():
                return None
            return json.loads(self.cipher.decrypt(row[0])), row[2]

    def revoke(self, kind, identifier):
        with self.lock, self.connect() as db:
            row = db.execute("SELECT family FROM records WHERE kind=? AND id=?", (kind, self.digest(identifier))).fetchone()
            if row:
                db.execute("DELETE FROM records WHERE family=? AND family<>''", (row[0],))


class OwnerOAuth:
    def __init__(self, store, issuer, password, hermes_token=""):
        if len(password) < 32:
            raise ValueError("TBANK_MCP_OWNER_PASSWORD must contain at least 32 characters")
        self.store, self.issuer = store, issuer.rstrip("/")
        self.resource = self.issuer + "/mcp"
        self.password_hash = hashlib.sha256(password.encode()).digest()
        self.failed_logins = []
        self.hermes_token = hermes_token
        self.scopes = [SCOPE] + (["bank:transfer-own"] if os.environ.get("TBANK_ENABLE_OWN_TRANSFERS") == "1" else [])

    async def get_client(self, client_id):
        row = self.store.get("client", client_id)
        return OAuthClientInformationFull.model_validate(row[0]) if row else None

    async def register_client(self, client_info):
        if not client_info.redirect_uris or not all(allowed_redirect(u) for u in client_info.redirect_uris):
            raise RegistrationError("invalid_redirect_uri", "Only ChatGPT callback URIs are allowed")
        self.store.put("client", client_info.client_id, client_info.model_dump(mode="json"), time.time() + 10 * 365 * 86400)

    async def authorize(self, client, params):
        if not allowed_redirect(params.redirect_uri) or params.resource != self.resource:
            raise AuthorizeError("invalid_request", "Invalid redirect URI or resource")
        if SCOPE not in (params.scopes or [SCOPE]) or not set(params.scopes or [SCOPE]).issubset(self.scopes):
            raise AuthorizeError("invalid_scope", "Unsupported bank scope")
        nonce = secrets.token_urlsafe(32)
        self.store.put("pending", nonce, {"client_id": client.client_id, "params": params.model_dump(mode="json")}, time.time() + 600)
        return self.issuer + "/consent?" + urlencode({"request": nonce})

    async def load_authorization_code(self, client, authorization_code):
        row = self.store.get("code", authorization_code)
        if row and row[0]["client_id"] == client.client_id:
            return AuthorizationCode.model_validate(row[0])
        return None

    def issue_tokens(self, client_id, scopes, resource, family):
        now = int(time.time())
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        self.store.put("access", access, AccessToken(token=access, client_id=client_id, scopes=scopes,
            expires_at=now + 3600, resource=resource, subject="owner").model_dump(mode="json"), now + 3600, family)
        self.store.put("refresh", refresh, RefreshToken(token=refresh, client_id=client_id, scopes=scopes,
            expires_at=now + 30 * 86400, resource=resource, subject="owner").model_dump(mode="json"), now + 30 * 86400, family)
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=3600, refresh_token=refresh, scope=" ".join(scopes))

    async def exchange_authorization_code(self, client, authorization_code):
        row = self.store.get("code", authorization_code.code, consume=True)
        if not row or row[0]["client_id"] != client.client_id:
            raise TokenError("invalid_grant", "Authorization code already used or expired")
        return self.issue_tokens(client.client_id, authorization_code.scopes, authorization_code.resource, secrets.token_hex(16))

    async def load_refresh_token(self, client, refresh_token):
        row = self.store.get("refresh", refresh_token)
        return RefreshToken.model_validate(row[0]) if row and row[0]["client_id"] == client.client_id else None

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        with self.store.lock:
            row = self.store.get("refresh", refresh_token.token)
            if not row or row[0]["client_id"] != client.client_id or not set(scopes).issubset(refresh_token.scopes):
                raise TokenError("invalid_grant", "Refresh token expired or already rotated")
            self.store.revoke("refresh", refresh_token.token)
            return self.issue_tokens(client.client_id, scopes, refresh_token.resource, row[1])

    async def load_access_token(self, token):
        if self.hermes_token and hmac.compare_digest(token, self.hermes_token):
            return AccessToken(token=token, client_id="hermes-local", scopes=self.scopes,
                               resource=self.resource, subject="owner")
        row = self.store.get("access", token)
        return AccessToken.model_validate(row[0]) if row else None

    async def revoke_token(self, token):
        self.store.revoke("refresh" if isinstance(token, RefreshToken) else "access", token.token)

    async def consent(self, request):
        nonce = request.query_params.get("request", "")
        pending = self.store.get("pending", nonce)
        if not pending:
            return HTMLResponse("Запрос истёк. Повторите подключение в ChatGPT.", status_code=400)
        own = "bank:transfer-own" in (pending[0]["params"].get("scopes") or [SCOPE])
        title = "Чтение и переводы между своими счетами" if own else "Только чтение"
        if own:
            from .own_transfers import execution_policy
            policy = ("Доступны переводы между своими текущими и накопительными RUB-счетами без комиссии. "
                      + ("Прямая команда в чате разрешает реальное исполнение без дополнительной формы подтверждения. "
                         if execution_policy() == 'chat' else
                         "Каждый перевод потребует подтверждения кнопкой в клиенте MCP. "))
        else:
            policy = "Переводы и оплаты недоступны. "
        csrf = secrets.token_urlsafe(32)
        self.store.put("csrf", csrf, {"nonce": nonce}, time.time() + 600)
        page = ('<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
                f'<title>Т-Банк — разрешение доступа</title><h1>Т-Банк: {title}</h1>'
                '<p>Вы разрешаете выбранному аккаунту ChatGPT читать счета, операции и инвестиции владельца этого сервера.</p>'
                f'<p>{policy}Введите код подключения из Infisical TBANK_MCP_OWNER_PASSWORD. '
                'Пароль банка, PIN и SMS-код здесь не нужны.</p><form method="post" action="consent">'
                f'<input type="hidden" name="request" value="{html.escape(nonce)}">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                '<label>Код подключения <input type="password" name="password" required autocomplete="off"></label>'
                '<button type="submit">Разрешить указанный доступ</button></form></html>')
        # Chromium проверяет form-action также для OAuth redirect после POST.
        response = HTMLResponse(page, headers={"Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; form-action 'self' https://chatgpt.com; frame-ancestors 'none'; base-uri 'none'", "Referrer-Policy": "no-referrer"})
        response.set_cookie("tbank_csrf", csrf, secure=True, httponly=True, samesite="lax", max_age=600, path=urlsplit(self.issuer).path or "/")
        return response

    async def approve(self, request):
        form = await request.form()
        csrf = str(form.get("csrf", ""))
        row = self.store.get("csrf", csrf, consume=True)
        nonce = str(form.get("request", ""))
        if not row or row[0]["nonce"] != nonce or not hmac.compare_digest(request.cookies.get("tbank_csrf", ""), csrf):
            return HTMLResponse("Недействительный запрос. Повторите подключение.", status_code=400)
        now = time.time()
        self.failed_logins = [t for t in self.failed_logins if now - t < 60]
        if len(self.failed_logins) >= 5:
            return HTMLResponse("Слишком много попыток. Подождите минуту.", status_code=429)
        if not hmac.compare_digest(hashlib.sha256(str(form.get("password", "")).encode()).digest(), self.password_hash):
            self.failed_logins.append(now)
            return HTMLResponse("Неверный код. Повторите подключение в ChatGPT.", status_code=403)
        pending = self.store.get("pending", nonce, consume=True)
        if not pending:
            return HTMLResponse("Запрос истёк.", status_code=400)
        params = AuthorizationParams.model_validate(pending[0]["params"])
        code = secrets.token_urlsafe(32)
        record = AuthorizationCode(code=code, client_id=pending[0]["client_id"], scopes=params.scopes or [SCOPE],
            expires_at=now + 120, code_challenge=params.code_challenge, redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly, resource=params.resource, subject="owner")
        self.store.put("code", code, record.model_dump(mode="json"), record.expires_at)
        values = {"code": code}
        if params.state is not None:
            values["state"] = params.state
        response = RedirectResponse(str(params.redirect_uri) + "?" + urlencode(values), status_code=303)
        response.delete_cookie("tbank_csrf", path=urlsplit(self.issuer).path or "/")
        response.headers["Cache-Control"] = "no-store"
        return response


def private_hermes_token():
    filename = os.environ.get("TBANK_MCP_HERMES_TOKEN_FILE")
    if not filename:
        return ""
    path = Path(filename)
    if path.is_symlink():
        raise ValueError("Hermes token must be a regular private file")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        token = path.read_text(encoding="utf-8").strip()
    else:
        token = "hermes_" + secrets.token_urlsafe(32)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(token)
            file.flush()
            os.fsync(file.fileno())
    if not re.fullmatch(r"hermes_[A-Za-z0-9_-]{43}", token):
        raise ValueError("Invalid private Hermes token")
    os.chmod(path, 0o600)
    return token


def create_app(issuer=None, password=None, key=None, state_path=None):
    issuer = issuer or os.environ["TBANK_MCP_PUBLIC_URL"]
    if urlsplit(issuer).scheme != "https":
        raise ValueError("Public issuer must use HTTPS")
    provider = OwnerOAuth(Store(state_path or os.environ["TBANK_MCP_OAUTH_DB"], key or os.environ["TBANK_MCP_STATE_KEY"]),
                          issuer, password or os.environ["TBANK_MCP_OWNER_PASSWORD"], private_hermes_token())
    own_enabled = os.environ.get("TBANK_ENABLE_OWN_TRANSFERS") == "1"
    if own_enabled:
        from .own_transfers import execution_policy
        chat_execution = execution_policy() == 'chat'
    instructions = ("Т-Банк: чтение счетов/операций и переводы только между своими Current/Saving RUB-счетами. "
                    + ("Для прямой команды перевести: list_accounts → prepare_own_transfer → execute_own_transfer. "
                       "Исполнение реальное, без отдельной формы. Если пользователь просит только подготовку, "
                       "проверку или расчёт, execute_own_transfer НЕ вызывать. Сумма и оба счёта должны быть явно "
                       "выбраны пользователем; при неопределённости уточнить, не подставлять старые значения. "
                       if chat_execution else
                       "Для перевода: list_accounts → prepare_own_transfer → confirm_own_transfer. "
                       "Последний инструмент показывает штатный диалог пользователю в клиенте MCP. "
                       "Текстовое да и аргументы модели не заменяют кнопку. ") +
                    "Пароль, PIN и SMS-код никогда не запрашивать в чате. "
                    "При unknown/posting/checking/bank_confirmation "
                    "не создавать повторный перевод; сверить операции в банке. Чужие переводы и оплаты недоступны."
                    if own_enabled else server.mcp.instructions)
    mcp = FastMCP("tbank-mcp" if own_enabled else "tbank-readonly", instructions=instructions,
        auth_server_provider=provider, auth=AuthSettings(issuer_url=AnyHttpUrl(provider.issuer),
            resource_server_url=AnyHttpUrl(provider.resource), validate_token_resource=True,
            required_scopes=[SCOPE], client_registration_options=ClientRegistrationOptions(enabled=True,
                valid_scopes=provider.scopes, default_scopes=provider.scopes), revocation_options=RevocationOptions(enabled=True)),
        stateless_http=len(provider.scopes) == 1, json_response=len(provider.scopes) == 1, max_request_body_size=16384,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
            allowed_hosts=[urlsplit(issuer).netloc, "127.0.0.1:*", "localhost:*"],
            allowed_origins=["https://chatgpt.com", issuer]))
    for tool in server.mcp._tool_manager.list_tools():
        if own_enabled and tool.name == "flows":
            continue
        mcp.add_tool(tool.fn, name=tool.name, title=tool.title, description=tool.description, annotations=tool.annotations)
    if own_enabled:
        from .own_transfers import install
        install(mcp, provider, server._require)

        @mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
        def flows(topic: str = "") -> str:
            """Справка по чтению, выбранному режиму исполнения и собственным RUB-переводам."""
            reading = server.flows(topic).replace('# T-Bank — только чтение', '# Т-Банк — чтение и собственные RUB-переводы', 1)
            reading = reading.replace('Оплаты, переводы, бронирования, сообщения и любые изменения недоступны.',
                'Другие переводы, оплаты, бронирования, сообщения и изменения недоступны. Собственные RUB-переводы — по правилам выше.')
            return instructions + "\n" + reading
    mcp.custom_route("/consent", methods=["GET"])(provider.consent)
    mcp.custom_route("/consent", methods=["POST"])(provider.approve)

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(request):
        payload = {"status": "ok", "mode": "read-and-own-transfers" if own_enabled else "read-only",
                   "tools": len(mcp._tool_manager.list_tools())}
        if own_enabled:
            payload['execution_policy'] = 'chat' if chat_execution else 'native'
        return JSONResponse(payload)

    app = mcp.streamable_http_app()
    if own_enabled:
        # В metadata публикуем все поддержанные scopes, но для чтения по-прежнему
        # достаточно bank:read. Проверка переводов выполняется внутри tool.
        from mcp.server.auth.routes import create_protected_resource_routes
        resource_routes = create_protected_resource_routes(AnyHttpUrl(provider.resource),
            [AnyHttpUrl(provider.issuer)], scopes_supported=provider.scopes)
        replacements = {r.path: r for r in resource_routes}
        app.router.routes = [replacements.get(getattr(r, 'path', ''), r) for r in app.router.routes]
    # SDK 1.30's revocation model incorrectly requires client_secret even for
    # public PKCE clients. Keep SDK client authentication, accept its omission.
    async def revoke(request):
        try:
            client = await ClientAuthenticator(provider).authenticate_request(request)
        except AuthenticationError:
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        form = await request.form()
        value = str(form.get("token", ""))
        token = await provider.load_access_token(value) or await provider.load_refresh_token(client, value)
        if token and token.client_id == client.client_id:
            await provider.revoke_token(token)
        return Response(status_code=200, headers={"Cache-Control": "no-store"})
    app.router.routes = [Route("/revoke", revoke, methods=["POST"]) if getattr(r, "path", "") == "/revoke" else r
                         for r in app.router.routes]
    app.state.oauth = provider
    return app


def main():
    uvicorn.run(create_app(), host="127.0.0.1", port=int(os.environ.get("TBANK_MCP_PORT", "8954")), access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
