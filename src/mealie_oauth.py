"""OAuth 2.1 authorization server that authenticates users against Mealie.

MCP clients (ChatGPT, claude.ai, ...) discover this server through the standard
OAuth metadata endpoints and register themselves dynamically. During the
authorization step the user signs in on a page served here with their Mealie
username and password. The password is only forwarded to Mealie to obtain a
short-lived JWT, which is used once to mint a long-lived Mealie API token for
that user. The password and JWT are never stored; the API token is stored
encrypted and used for that user's Mealie requests. Revoking the OAuth grant
deletes the Mealie API token.
"""

import base64
import hashlib
import html
import logging
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastmcp.server.auth.auth import (
    AccessToken,
    ClientRegistrationOptions,
    OAuthProvider,
    RevocationOptions,
)
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

logger = logging.getLogger("mealie_mcp.oauth")

AUTH_CODE_TTL = 5 * 60
TXN_TTL = 10 * 60
ACCESS_TOKEN_TTL = 60 * 60
REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60
MAX_LOGIN_ATTEMPTS_PER_TXN = 5
MAX_FAILURES_PER_USER = 5
FAILURE_WINDOW = 15 * 60
MAX_CLIENTS = 1000
MAX_FORM_BYTES = 8192
MEALIE_TIMEOUT = 15.0

CLAIM_MEALIE_TOKEN = "mealie_api_token"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _build_fernet(data_dir: Optional[Path], secret: Optional[str]) -> Fernet:
    """Fernet key from MCP_SECRET_KEY, else a key file in the data dir, else ephemeral."""
    if secret:
        return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest()))
    if data_dir is None:
        return Fernet(Fernet.generate_key())
    key_file = data_dir / "secret.key"
    if key_file.exists():
        return Fernet(key_file.read_bytes().strip())
    key = Fernet.generate_key()
    # Created 0600 atomically so the key is never readable by others, even briefly
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return Fernet(key)


class _Store:
    """SQLite persistence for OAuth clients, grants and tokens."""

    def __init__(self, path: str):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS clients (
                    client_id TEXT PRIMARY KEY, data TEXT NOT NULL, created_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS grants (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, client_id TEXT NOT NULL,
                    username TEXT NOT NULL, mealie_token TEXT NOT NULL,
                    mealie_token_id INTEGER, created_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS tokens (
                    hash TEXT PRIMARY KEY, kind TEXT NOT NULL,
                    grant_id INTEGER NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
                    scopes TEXT NOT NULL, resource TEXT, expires_at REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS tokens_grant ON tokens(grant_id);
                """
            )
            self._db.execute("PRAGMA foreign_keys = ON")
            self._db.commit()

    def _run(self, sql: str, args: tuple = (), fetch: str = "") -> Any:
        with self._lock:
            cur = self._db.execute(sql, args)
            result = cur.fetchone() if fetch == "one" else cur.fetchall() if fetch == "all" else cur.lastrowid
            self._db.commit()
            return result

    def save_client(self, client_id: str, data: str) -> None:
        self._run(
            "INSERT OR REPLACE INTO clients VALUES (?, ?, ?)", (client_id, data, time.time())
        )

    def get_client(self, client_id: str) -> Optional[str]:
        row = self._run("SELECT data FROM clients WHERE client_id = ?", (client_id,), "one")
        return row["data"] if row else None

    def prune_clients(self) -> int:
        """Drop clients with no grants and return how many clients remain."""
        self._run(
            "DELETE FROM clients WHERE client_id NOT IN (SELECT client_id FROM grants)"
        )
        return self._run("SELECT COUNT(*) AS n FROM clients", (), "one")["n"]

    def count_clients(self) -> int:
        return self._run("SELECT COUNT(*) AS n FROM clients", (), "one")["n"]

    def add_grant(self, client_id: str, username: str, mealie_token: str, token_id: Optional[int]) -> int:
        return self._run(
            "INSERT INTO grants (client_id, username, mealie_token, mealie_token_id, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (client_id, username, mealie_token, token_id, time.time()),
        )

    def add_token(self, token: str, kind: str, grant_id: int, scopes: list, resource: Optional[str], expires_at: float) -> None:
        self._run(
            "INSERT INTO tokens VALUES (?, ?, ?, ?, ?, ?)",
            (_hash(token), kind, grant_id, " ".join(scopes), resource, expires_at),
        )

    def get_token(self, token: str, kind: str) -> Optional[sqlite3.Row]:
        return self._run(
            "SELECT t.*, g.client_id, g.username, g.mealie_token FROM tokens t"
            " JOIN grants g ON g.id = t.grant_id WHERE t.hash = ? AND t.kind = ?",
            (_hash(token), kind),
            "one",
        )

    def delete_token(self, token: str) -> None:
        self._run("DELETE FROM tokens WHERE hash = ?", (_hash(token),))

    def delete_grant_tokens(self, grant_id: int) -> None:
        self._run("DELETE FROM tokens WHERE grant_id = ?", (grant_id,))

    def pop_grant(self, grant_id: int) -> Optional[sqlite3.Row]:
        row = self._run("SELECT * FROM grants WHERE id = ?", (grant_id,), "one")
        self._run("DELETE FROM tokens WHERE grant_id = ?", (grant_id,))
        self._run("DELETE FROM grants WHERE id = ?", (grant_id,))
        return row

    def pop_dead_grants(self) -> list:
        """Remove expired tokens, then grants left with no tokens; return the grants."""
        self._run("DELETE FROM tokens WHERE expires_at < ?", (time.time(),))
        rows = self._run(
            "SELECT * FROM grants WHERE id NOT IN (SELECT grant_id FROM tokens)", (), "all"
        )
        for row in rows:
            self._run("DELETE FROM grants WHERE id = ?", (row["id"],))
        return rows


@dataclass
class _Txn:
    client: OAuthClientInformationFull
    params: AuthorizationParams
    expires_at: float
    attempts: int = 0


@dataclass
class _PendingCode:
    code: AuthorizationCode
    username: str
    mealie_jwt: str


class MealieOAuthProvider(OAuthProvider):
    """OAuth authorization server whose login step is Mealie's own login."""

    def __init__(
        self,
        *,
        base_url: str,
        mealie_url: str,
        data_dir: Optional[str] = None,
        secret: Optional[str] = None,
    ):
        super().__init__(
            base_url=base_url,
            client_registration_options=ClientRegistrationOptions(enabled=True),
            revocation_options=RevocationOptions(enabled=True),
        )
        self._mealie_url = mealie_url.rstrip("/")
        directory = Path(data_dir) if data_dir else None
        if directory:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            db_file = directory / "oauth.db"
            os.close(os.open(db_file, os.O_RDWR | os.O_CREAT, 0o600))
            db_path = str(db_file)
        else:
            db_path = ":memory:"
            logger.warning(
                "MCP_DATA_DIR is not set: OAuth clients and tokens are kept in memory "
                "and every restart will force users to sign in again."
            )
        self._store = _Store(db_path)
        self._fernet = _build_fernet(directory, secret)
        self._txns: dict[str, _Txn] = {}
        self._codes: dict[str, _PendingCode] = {}
        self._failures: dict[str, list] = {}

    # ----------------------------------------------------------------- clients

    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        data = self._store.get_client(client_id)
        return OAuthClientInformationFull.model_validate_json(data) if data else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if client_info.client_id is None:
            raise ValueError("client_id is required for client registration")
        if self._store.count_clients() >= MAX_CLIENTS and self._store.prune_clients() >= MAX_CLIENTS:
            raise ValueError("Too many registered clients")
        self._store.save_client(client_info.client_id, client_info.model_dump_json(exclude_none=True))

    # --------------------------------------------------------------- authorize

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if client.client_id is None:
            raise AuthorizeError(error="invalid_request", error_description="Client ID is required")
        await self._gc()
        txn_id = secrets.token_urlsafe(32)
        self._txns[txn_id] = _Txn(client, params, time.time() + TXN_TTL)
        return f"{str(self.base_url).rstrip('/')}/login?txn={txn_id}"

    def get_routes(self, mcp_path: Optional[str] = None) -> list:
        routes = super().get_routes(mcp_path)
        routes.append(Route("/login", self._login, methods=["GET", "POST"]))
        return routes

    # ------------------------------------------------------------- login page

    def _get_txn(self, txn_id: str) -> Optional[_Txn]:
        txn = self._txns.get(txn_id)
        if txn and txn.expires_at < time.time():
            del self._txns[txn_id]
            return None
        return txn

    async def _login(self, request: Request) -> Response:
        await self._gc()
        if request.method == "GET":
            txn_id = request.query_params.get("txn", "")
            txn = self._get_txn(txn_id)
            if not txn:
                return _page("Link expired", "<p>This sign-in link is invalid or has expired. Start again from your app.</p>", 400)
            return _login_form(txn_id, txn)

        body = await request.body()
        if len(body) > MAX_FORM_BYTES:
            return _page("Request too large", "<p>Request too large.</p>", 413)
        form = {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace")).items()}
        txn_id = form.get("txn", "")
        txn = self._get_txn(txn_id)
        if not txn:
            return _page("Link expired", "<p>This sign-in link is invalid or has expired. Start again from your app.</p>", 400)

        username = form.get("username", "").strip()
        password = form.get("password", "")
        if not username or not password:
            return _login_form(txn_id, txn, "Enter your username and password.", 400)

        key = username.lower()
        recent = [t for t in self._failures.get(key, []) if t > time.time() - FAILURE_WINDOW]
        if len(recent) >= MAX_FAILURES_PER_USER:
            return _login_form(txn_id, txn, "Too many failed attempts. Try again in 15 minutes.", 429)

        try:
            jwt = await self._mealie_login(username, password)
        except httpx.HTTPError:
            logger.exception("Could not reach Mealie during login")
            return _login_form(txn_id, txn, "Could not reach Mealie. Try again later.", 502)

        if jwt is None:
            self._failures[key] = recent + [time.time()]
            txn.attempts += 1
            if txn.attempts >= MAX_LOGIN_ATTEMPTS_PER_TXN:
                self._txns.pop(txn_id, None)
                return _page("Too many attempts", "<p>Too many failed attempts. Start again from your app.</p>", 429)
            return _login_form(txn_id, txn, "Invalid username or password.", 401)

        self._failures.pop(key, None)
        del self._txns[txn_id]
        params = txn.params
        code = AuthorizationCode(
            code=secrets.token_urlsafe(32),
            client_id=txn.client.client_id,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            scopes=params.scopes or [],
            expires_at=time.time() + AUTH_CODE_TTL,
            code_challenge=params.code_challenge,
            resource=params.resource,
        )
        self._codes[code.code] = _PendingCode(code, username, jwt)
        target = construct_redirect_uri(str(params.redirect_uri), code=code.code, state=params.state)
        return RedirectResponse(target, status_code=303, headers=_NO_STORE)

    # ----------------------------------------------------------------- Mealie

    async def _mealie_login(self, username: str, password: str) -> Optional[str]:
        async with httpx.AsyncClient(timeout=MEALIE_TIMEOUT) as http:
            resp = await http.post(
                f"{self._mealie_url}/api/auth/token",
                data={"username": username, "password": password, "remember_me": "false"},
            )
        if resp.status_code in (401, 403, 422):
            return None
        resp.raise_for_status()
        return resp.json().get("access_token")

    async def _create_mealie_token(self, jwt: str, client_name: str) -> tuple:
        async with httpx.AsyncClient(timeout=MEALIE_TIMEOUT) as http:
            resp = await http.post(
                f"{self._mealie_url}/api/users/api-tokens",
                headers={"Authorization": f"Bearer {jwt}"},
                json={"name": f"mealie-mcp: {client_name} ({date.today().isoformat()})"},
            )
        resp.raise_for_status()
        data = resp.json()
        return data["token"], data.get("id")

    async def _delete_mealie_token(self, encrypted_token: str, token_id: Optional[int]) -> None:
        if token_id is None:
            return
        try:
            token = self._fernet.decrypt(encrypted_token.encode()).decode()
            async with httpx.AsyncClient(timeout=MEALIE_TIMEOUT) as http:
                await http.delete(
                    f"{self._mealie_url}/api/users/api-tokens/{token_id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
        except (httpx.HTTPError, InvalidToken):
            logger.warning("Could not delete Mealie API token %s", token_id)

    # ------------------------------------------------------------ token flows

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> Optional[AuthorizationCode]:
        pending = self._codes.get(authorization_code)
        if not pending or pending.code.client_id != client.client_id:
            return None
        if pending.code.expires_at < time.time():
            del self._codes[authorization_code]
            return None
        return pending.code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        pending = self._codes.pop(authorization_code.code, None)
        if not pending:
            raise TokenError("invalid_grant", "Authorization code not found or already used.")
        try:
            mealie_token, token_id = await self._create_mealie_token(
                pending.mealie_jwt, client.client_name or client.client_id
            )
        except (httpx.HTTPError, KeyError, ValueError):
            logger.exception("Could not create Mealie API token")
            raise TokenError("invalid_grant", "Could not obtain a Mealie API token.")
        grant_id = self._store.add_grant(
            client.client_id,
            pending.username,
            self._fernet.encrypt(mealie_token.encode()).decode(),
            token_id,
        )
        return self._issue_tokens(grant_id, authorization_code.scopes, authorization_code.resource)

    def _issue_tokens(self, grant_id: int, scopes: list, resource: Optional[str]) -> OAuthToken:
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        now = time.time()
        self._store.add_token(access, "access", grant_id, scopes, resource, now + ACCESS_TOKEN_TTL)
        self._store.add_token(refresh, "refresh", grant_id, scopes, resource, now + REFRESH_TOKEN_TTL)
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            refresh_token=refresh,
            scope=" ".join(scopes) or None,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> Optional[RefreshToken]:
        row = self._store.get_token(refresh_token, "refresh")
        if not row or row["client_id"] != client.client_id or row["expires_at"] < time.time():
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=row["client_id"],
            scopes=row["scopes"].split(),
            expires_at=int(row["expires_at"]),
            resource=row["resource"],
            subject=row["username"],
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list
    ) -> OAuthToken:
        row = self._store.get_token(refresh_token.token, "refresh")
        if not row:
            raise TokenError("invalid_grant", "Refresh token not found or already used.")
        if scopes and not set(scopes) <= set(refresh_token.scopes):
            raise TokenError("invalid_scope", "Requested scopes exceed the original grant.")
        self._store.delete_grant_tokens(row["grant_id"])
        return self._issue_tokens(row["grant_id"], scopes or refresh_token.scopes, row["resource"])

    async def load_access_token(self, token: str) -> Optional[AccessToken]:
        row = self._store.get_token(token, "access")
        if not row or row["expires_at"] < time.time():
            return None
        try:
            mealie_token = self._fernet.decrypt(row["mealie_token"].encode()).decode()
        except InvalidToken:
            return None
        return AccessToken(
            token=token,
            client_id=row["client_id"],
            scopes=row["scopes"].split(),
            expires_at=int(row["expires_at"]),
            resource=row["resource"],
            subject=row["username"],
            claims={"username": row["username"], CLAIM_MEALIE_TOKEN: mealie_token},
        )

    async def revoke_token(self, token: object) -> None:
        raw = getattr(token, "token", None)
        if not raw:
            return
        for kind in ("access", "refresh"):
            row = self._store.get_token(raw, kind)
            if row:
                grant = self._store.pop_grant(row["grant_id"])
                if grant:
                    await self._delete_mealie_token(grant["mealie_token"], grant["mealie_token_id"])
                return

    async def _gc(self) -> None:
        now = time.time()
        self._txns = {k: v for k, v in self._txns.items() if v.expires_at >= now}
        self._codes = {k: v for k, v in self._codes.items() if v.code.expires_at >= now}
        self._failures = {
            k: [t for t in v if t > now - FAILURE_WINDOW] for k, v in self._failures.items()
        }
        self._failures = {k: v for k, v in self._failures.items() if v}
        for grant in self._store.pop_dead_grants():
            await self._delete_mealie_token(grant["mealie_token"], grant["mealie_token_id"])


_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_SECURITY_HEADERS = {
    **_NO_STORE,
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
}

_STYLE = """
body{font-family:system-ui,sans-serif;background:#f4f4f5;display:flex;justify-content:center;padding:3rem 1rem;margin:0}
main{background:#fff;border-radius:8px;padding:2rem;max-width:380px;width:100%;box-shadow:0 1px 4px #0002}
h1{font-size:1.3rem;margin-top:0}label{display:block;margin:1rem 0 .25rem;font-size:.9rem}
input{width:100%;box-sizing:border-box;padding:.55rem;font-size:1rem;border:1px solid #bbb;border-radius:4px}
button{margin-top:1.25rem;width:100%;padding:.65rem;font-size:1rem;border:0;border-radius:4px;background:#e58325;color:#fff;cursor:pointer}
.err{color:#b00020;margin:.75rem 0 0}.note{font-size:.85rem;color:#555}
"""


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    doc = (
        f"<!doctype html><html lang=en><meta charset=utf-8><title>{html.escape(title)}</title>"
        f"<meta name=viewport content='width=device-width,initial-scale=1'><style>{_STYLE}</style>"
        f"<main><h1>{html.escape(title)}</h1>{body}</main></html>"
    )
    return HTMLResponse(doc, status_code=status, headers=_SECURITY_HEADERS)


def _login_form(txn_id: str, txn: _Txn, error: str = "", status: int = 200) -> HTMLResponse:
    client_name = html.escape(txn.client.client_name or "An application")
    parsed = urlparse(str(txn.params.redirect_uri))
    destination = html.escape(f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else parsed.scheme + "://")
    error_html = f"<p class=err role=alert>{html.escape(error)}</p>" if error else ""
    body = (
        f"<p><strong>{client_name}</strong> wants to access your Mealie account.</p>"
        f"<p class=note>After you sign in you will be sent to <strong>{destination}</strong>. "
        "Only continue if you started this from an app you trust.</p>"
        f"{error_html}"
        "<form method=post action=/login>"
        f"<input type=hidden name=txn value='{html.escape(txn_id)}'>"
        "<label for=u>Mealie username or email</label>"
        "<input id=u name=username autocomplete=username required autofocus>"
        "<label for=p>Password</label>"
        "<input id=p name=password type=password autocomplete=current-password required>"
        "<button type=submit>Sign in</button></form>"
    )
    return _page("Sign in to Mealie", body, status)
