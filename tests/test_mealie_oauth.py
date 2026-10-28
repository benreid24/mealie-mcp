"""Tests for the Mealie-backed OAuth authorization server."""

import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from fastmcp import FastMCP
from starlette.testclient import TestClient

from src.bearer_auth import build_auth
from src.client import MealieClient
from src.mealie_oauth import MealieOAuthProvider

MEALIE = "http://mealie.test"
PUBLIC = "https://mcp.test"
REDIRECT = "http://localhost/callback"
STATIC_TOKEN = "static-secret"


def _mock_mealie(router, valid_password="pw"):
    def login(request):
        if f"password={valid_password}" in request.content.decode():
            return httpx.Response(200, json={"access_token": "mealie-jwt", "token_type": "bearer"})
        return httpx.Response(401, json={"detail": "Unauthorized"})

    router.post(f"{MEALIE}/api/auth/token").mock(side_effect=login)
    router.post(f"{MEALIE}/api/users/api-tokens").mock(
        return_value=httpx.Response(201, json={"name": "n", "id": 7, "token": "api-token-alice"})
    )
    return router.delete(f"{MEALIE}/api/users/api-tokens/7").mock(return_value=httpx.Response(200))


@pytest.fixture
def mealie():
    with respx.mock(assert_all_called=False) as router:
        router.delete_route = _mock_mealie(router)
        yield router


@pytest.fixture
def http(tmp_path, monkeypatch, mealie):
    monkeypatch.setenv("MEALIE_API_TOKEN", "shared-token")
    mcp = FastMCP(
        "test",
        auth=build_auth(
            "http", STATIC_TOKEN, public_url=PUBLIC, mealie_url=MEALIE, data_dir=str(tmp_path)
        ),
    )

    @mcp.tool()
    def whoami() -> str:
        return MealieClient(base_url=MEALIE).api_token

    app = mcp.http_app(stateless_http=True)
    with TestClient(app, base_url=PUBLIC) as client:
        yield client


def _register(client, name="Test App"):
    resp = client.post(
        "/register",
        json={
            "redirect_uris": [REDIRECT],
            "client_name": name,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["client_id"]


def _start_authorize(client, client_id, verifier):
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    resp = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "xyz",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302, resp.text
    location = resp.headers["location"]
    assert location.startswith(f"{PUBLIC}/login?txn=")
    return parse_qs(urlparse(location).query)["txn"][0]


def _login(client, txn, username="alice", password="pw"):
    return client.post(
        "/login", data={"txn": txn, "username": username, "password": password}, follow_redirects=False
    )


def _full_flow(client, name="Test App"):
    client_id = _register(client, name)
    verifier = secrets.token_urlsafe(48)
    txn = _start_authorize(client, client_id, verifier)
    resp = _login(client, txn)
    assert resp.status_code == 303, resp.text
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["state"] == ["xyz"]
    token_resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "redirect_uri": REDIRECT,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert token_resp.status_code == 200, token_resp.text
    return client_id, token_resp.json()


def _call_tool(client, bearer, name):
    resp = client.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {bearer}",
            "Accept": "application/json, text/event-stream",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": {}}},
    )
    if resp.status_code != 200:
        return resp.status_code, None
    data = next(line[5:] for line in resp.text.splitlines() if line.startswith("data:"))
    return 200, json.loads(data)["result"]["content"][0]["text"]


def test_full_flow_uses_the_users_own_mealie_token(http):
    _, tokens = _full_flow(http)
    assert tokens["token_type"].lower() == "bearer"
    assert _call_tool(http, tokens["access_token"], "whoami") == (200, "api-token-alice")


def test_static_bearer_still_works_with_shared_token(http):
    assert _call_tool(http, STATIC_TOKEN, "whoami") == (200, "shared-token")


def test_mcp_requires_auth_and_advertises_oauth(http):
    assert http.post("/mcp", json={}).status_code == 401
    assert _call_tool(http, "bogus", "whoami")[0] == 401
    meta = http.get("/.well-known/oauth-authorization-server").json()
    assert meta["authorization_endpoint"] == f"{PUBLIC}/authorize"
    assert meta["registration_endpoint"] == f"{PUBLIC}/register"
    assert http.get("/.well-known/oauth-protected-resource/mcp").status_code == 200


def test_wrong_password_is_rejected_and_txn_dies_after_five_tries(http):
    txn = _start_authorize(http, _register(http), "v" * 50)
    for _ in range(4):
        resp = _login(http, txn, password="nope")
        assert resp.status_code == 401
        assert "Invalid username or password" in resp.text
    assert _login(http, txn, password="nope").status_code == 429
    assert _login(http, txn, password="pw").status_code == 400


def test_username_lockout_applies_across_transactions(http):
    client_id = _register(http)
    for _ in range(5):
        txn = _start_authorize(http, client_id, "v" * 50)
        assert _login(http, txn, password="nope").status_code in (401, 429)
    txn = _start_authorize(http, client_id, "v" * 50)
    assert _login(http, txn, password="pw").status_code == 429


def test_login_page_escapes_client_supplied_text(http):
    txn = _start_authorize(http, _register(http, name="<script>alert(1)</script>"), "v" * 50)
    page = http.get("/login", params={"txn": txn})
    assert page.status_code == 200
    assert "<script>alert(1)" not in page.text
    assert "&lt;script&gt;" in page.text
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["x-frame-options"] == "DENY"


def test_unknown_txn_is_rejected(http):
    assert http.get("/login", params={"txn": "nope"}).status_code == 400
    assert _login(http, "nope").status_code == 400


def test_auth_code_is_single_use_and_requires_pkce(http):
    client_id = _register(http)
    txn = _start_authorize(http, client_id, "verifier" * 8)
    code = parse_qs(urlparse(_login(http, txn).headers["location"]).query)["code"][0]
    base = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT, "client_id": client_id}
    assert http.post("/token", data={**base, "code_verifier": "wrong" * 10}).json()["error"] == "invalid_grant"
    ok = http.post("/token", data={**base, "code_verifier": "verifier" * 8})
    assert ok.status_code == 200, ok.text
    reuse = http.post("/token", data={**base, "code_verifier": "verifier" * 8})
    assert reuse.json()["error"] == "invalid_grant"


def test_refresh_rotates_tokens(http):
    client_id, tokens = _full_flow(http)
    resp = http.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": client_id},
    )
    assert resp.status_code == 200, resp.text
    new = resp.json()
    assert new["access_token"] != tokens["access_token"]
    assert _call_tool(http, new["access_token"], "whoami") == (200, "api-token-alice")
    assert _call_tool(http, tokens["access_token"], "whoami")[0] == 401
    replay = http.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": client_id},
    )
    assert replay.json()["error"] == "invalid_grant"


def test_revoke_deletes_the_mealie_api_token(http, mealie):
    client_id, tokens = _full_flow(http)
    resp = http.post("/revoke", data={"token": tokens["access_token"], "client_id": client_id, "client_secret": ""})
    assert resp.status_code == 200
    assert mealie.delete_route.called
    assert mealie.delete_route.calls.last.request.headers["authorization"] == "Bearer api-token-alice"
    assert _call_tool(http, tokens["access_token"], "whoami")[0] == 401
    refresh = http.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": client_id},
    )
    assert refresh.json()["error"] == "invalid_grant"


def test_mealie_token_is_encrypted_at_rest(http, tmp_path):
    _full_flow(http)
    raw = (tmp_path / "oauth.db").read_bytes()
    assert b"api-token-alice" not in raw
    assert b"mealie-jwt" not in raw


async def test_tokens_survive_restart(tmp_path, mealie):
    first = MealieOAuthProvider(base_url=PUBLIC, mealie_url=MEALIE, data_dir=str(tmp_path))
    grant = first._store.add_grant("c1", "alice", first._fernet.encrypt(b"api-token-alice").decode(), 7)
    issued = first._issue_tokens(grant, ["mealie"], None)

    second = MealieOAuthProvider(base_url=PUBLIC, mealie_url=MEALIE, data_dir=str(tmp_path))
    loaded = await second.load_access_token(issued.access_token)
    assert loaded is not None
    assert loaded.claims["mealie_api_token"] == "api-token-alice"
    assert loaded.subject == "alice"


async def test_expired_access_token_is_rejected(tmp_path, mealie):
    provider = MealieOAuthProvider(base_url=PUBLIC, mealie_url=MEALIE, data_dir=str(tmp_path))
    grant = provider._store.add_grant("c1", "alice", provider._fernet.encrypt(b"t").decode(), 7)
    provider._store.add_token("old", "access", grant, [], None, 1.0)
    assert await provider.load_access_token("old") is None
    assert await provider.load_access_token("never-issued") is None


def test_build_auth_requires_some_auth_for_http():
    assert build_auth("stdio", None) is None
    with pytest.raises(RuntimeError, match="MCP_AUTH_TOKEN"):
        build_auth("http", None)
    with pytest.raises(RuntimeError, match="MEALIE_URL"):
        build_auth("http", None, public_url=PUBLIC)
    assert build_auth("http", "t") is not None
