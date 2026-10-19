import importlib.util
import json
import tempfile
import time
import unittest
from pathlib import Path


@unittest.skipUnless(importlib.util.find_spec("mcp"), "optional MCP SDK")
class AuthTests(unittest.IsolatedAsyncioTestCase):
    async def test_signature_issuer_audience_subject_expiry_and_revocation(self):
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from reverse_lab.mcp_auth import LocalJWKVerifier
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        jwk["kid"] = "test-key"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "jwks.json"
            path.write_text(json.dumps({"keys": [jwk]}), encoding="utf-8")
            verifier = LocalJWKVerifier(path, issuer="https://issuer.example/",
                                        resource="https://lab.example/mcp", subject="owner")
            claims = {"iss": "https://issuer.example/", "aud": "https://lab.example/mcp",
                      "sub": "owner", "iat": int(time.time()), "exp": int(time.time()) + 300,
                      "client_id": "chatgpt", "scope": "reverse:read reverse:analyze"}
            def token(values):
                return jwt.encode(values, key, algorithm="RS256", headers={"kid": "test-key"})
            self.assertIsNotNone(await verifier.verify_token(token(claims)))
            for update in ({"aud": "other"}, {"iss": "https://evil.example/"},
                           {"sub": "another-user"}, {"exp": 1}):
                self.assertIsNone(await verifier.verify_token(token({**claims, **update})))
            self.assertIsNone(await verifier.verify_token("invalid"))
            path.write_text('{"keys": []}', encoding="utf-8")
            self.assertIsNone(await verifier.verify_token(token(claims)))
