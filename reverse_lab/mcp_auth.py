"""OAuth resource-server verification with locally pinned public JWKS.

No token issuance, identity discovery fetch, redirect, or confidential data upload.
The owner configures a real OAuth 2.1 provider and pins its public signing keys.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit


def https_url(value: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("OAuth issuer and resource require explicit HTTPS URLs")
    return value


class LocalJWKVerifier:
    def __init__(self, jwks: str | Path, *, issuer: str, resource: str, subject: str):
        self.jwks = Path(jwks).resolve(strict=True)
        self.issuer, self.resource = https_url(issuer), https_url(resource)
        if not subject or len(subject) > 256:
            raise ValueError("configure the single authorized owner subject")
        self.subject = subject

    async def verify_token(self, token: str):
        import jwt
        from mcp.server.auth.provider import AccessToken
        if len(token) > 16384:
            return None
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") not in ("RS256", "ES256"):
                return None
            # Read each time so removing public keys revokes access immediately.
            with self.jwks.open("rb") as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                return None
            keys = json.loads(raw)["keys"]
            matching = [key for key in keys if key.get("kid") == header.get("kid")]
            if len(matching) != 1:
                return None
            key = jwt.PyJWK.from_dict(matching[0], algorithm=header["alg"])
            claims = jwt.decode(
                token, key.key, algorithms=[header["alg"]], audience=self.resource,
                issuer=self.issuer, options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
            if claims["sub"] != self.subject:
                return None
            scope = claims.get("scope", "")
            if not isinstance(scope, str) or len(scope) > 1000:
                return None
            client = claims.get("client_id") or claims.get("azp")
            if not isinstance(client, str) or not client or len(client) > 512:
                return None
            return AccessToken(token=token, client_id=client, subject=claims["sub"],
                               scopes=scope.split(), expires_at=claims["exp"],
                               resource=self.resource, claims={"iss": self.issuer})
        except (ValueError, KeyError, TypeError, OSError, jwt.PyJWTError):
            return None
