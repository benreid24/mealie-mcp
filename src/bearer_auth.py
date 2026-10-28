"""Authentication setup for the HTTP transport."""

import hmac
from typing import Optional

from fastmcp.server.auth import AccessToken, AuthProvider, MultiAuth, TokenVerifier


class StaticBearerVerifier(TokenVerifier):
    """Accepts requests whose bearer token matches a single shared secret."""

    def __init__(self, token: str):
        super().__init__()
        self._token = token.encode()

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        if hmac.compare_digest(token.encode(), self._token):
            return AccessToken(token=token, client_id="mealie-mcp-client", scopes=[])
        return None


def build_auth(
    transport: str,
    token: Optional[str],
    public_url: Optional[str] = None,
    mealie_url: Optional[str] = None,
    data_dir: Optional[str] = None,
    secret: Optional[str] = None,
) -> Optional[AuthProvider]:
    """Return the auth provider for a transport.

    stdio is a local subprocess and needs no auth. HTTP refuses to start
    without at least one method so the server is never exposed unauthenticated
    by accident:
    - token: a shared bearer token (acts with the server's MEALIE_API_TOKEN)
    - public_url: OAuth, where users sign in with their Mealie account and act
      with their own Mealie permissions. Can be combined with the token.
    """
    if transport == "stdio":
        return None
    if not token and not public_url:
        raise RuntimeError(
            "Set MCP_AUTH_TOKEN and/or MCP_PUBLIC_URL (OAuth) when MCP_TRANSPORT is not 'stdio'. "
            "Generate a token with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )

    static = StaticBearerVerifier(token) if token else None
    if not public_url:
        return static

    if not mealie_url:
        raise RuntimeError("MEALIE_URL must be set to use OAuth (MCP_PUBLIC_URL).")
    try:
        from .mealie_oauth import MealieOAuthProvider
    except ImportError:
        from mealie_oauth import MealieOAuthProvider  # type: ignore[no-redef]

    oauth = MealieOAuthProvider(
        base_url=public_url, mealie_url=mealie_url, data_dir=data_dir, secret=secret
    )
    return MultiAuth(server=oauth, verifiers=[static]) if static else oauth
