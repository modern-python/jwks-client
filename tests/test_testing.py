import datetime

import jwt
import pytest

from jwks_client import JWTVerifier
from jwks_client.testing import FakeIdentityProvider, StaticTokenVerifier


async def test_fake_identity_provider_tokens_verify_against_its_jwks() -> None:
    idp = FakeIdentityProvider()
    verifier = JWTVerifier(idp.jwks_client(), algorithms=["RS256"], audience="api", issuer=idp.issuer)

    claims = await verifier.verify(idp.issue_token({"sub": "user-1", "aud": "api"}))

    assert claims["sub"] == "user-1"
    assert claims["iss"] == idp.issuer


async def test_fake_identity_provider_issues_expired_tokens() -> None:
    idp = FakeIdentityProvider()
    verifier = JWTVerifier(idp.jwks_client(), algorithms=["RS256"])

    with pytest.raises(jwt.ExpiredSignatureError):
        await verifier.verify(idp.issue_token(expires_in=datetime.timedelta(seconds=-1)))


async def test_fake_identity_provider_headers_override_kid() -> None:
    idp = FakeIdentityProvider(kid="published")
    token = idp.issue_token(headers={"kid": "unpublished"})

    assert jwt.get_unverified_header(token)["kid"] == "unpublished"
    assert [key["kid"] for key in idp.jwks["keys"]] == ["published"]


async def test_static_token_verifier_returns_configured_claims() -> None:
    verifier = StaticTokenVerifier({"local-token": {"sub": "developer"}})

    assert await verifier.verify("local-token") == {"sub": "developer"}
    with pytest.raises(jwt.InvalidTokenError):
        await verifier.verify("other-token")
