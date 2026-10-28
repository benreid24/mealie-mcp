"""Static bearer-token authentication for the HTTP transport."""

import hmac
from typing import Optional

from fastmcp.server.auth import AccessToken, TokenVerifier


class StaticBearerVerifier(TokenVerifier):
    """Accepts requests whose bearer token matches a single shared secret."""

    def __init__(self, token: str):
        super().__init__()
        self._token = token.encode()

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        if hmac.compare_digest(token.encode(), self._token):
            return AccessToken(token=token, client_id="mealie-mcp-client", scopes=[])
        return None


def build_auth(transport: str, token: Optional[str]) -> Optional[StaticBearerVerifier]:
    """Return the auth provider for a transport.

    stdio is a local subprocess and needs no auth. HTTP refuses to start
    without a token so the server is never exposed unauthenticated by accident.
    """
    if transport == "stdio":
        return None
    if not token:
        raise RuntimeError(
            "MCP_AUTH_TOKEN must be set when MCP_TRANSPORT is not 'stdio'. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
    return StaticBearerVerifier(token)
