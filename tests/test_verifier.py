import typing

import jwt
import pytest

from jwks_client import JWKSClient, JWTVerifier, extract_bearer_token
from tests.conftest import JWKSServer, SigningKey


async def test_verify_applies_configured_policy(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey
) -> None:
    server.serve(signing_key.to_jwk())
    verifier = JWTVerifier(make_client(), algorithms=["RS256"], audience="api", issuer="https://idp.example.test")

    claims = await verifier.verify(signing_key.issue_token({"aud": "api", "iss": "https://idp.example.test"}))

    assert claims["sub"] == "user-1"


@pytest.mark.parametrize(
    ("claims", "error"),
    [
        ({"aud": "other", "iss": "https://idp.example.test"}, jwt.InvalidAudienceError),
        ({"aud": "api", "iss": "https://evil.example.test"}, jwt.InvalidIssuerError),
        ({"aud": "api"}, jwt.MissingRequiredClaimError),
        ({"iss": "https://idp.example.test"}, jwt.MissingRequiredClaimError),
    ],
)
async def test_verify_rejects_tokens_outside_policy(
    make_client: typing.Callable[..., JWKSClient],
    server: JWKSServer,
    signing_key: SigningKey,
    claims: dict[str, str],
    error: type[Exception],
) -> None:
    server.serve(signing_key.to_jwk())
    verifier = JWTVerifier(make_client(), algorithms=["RS256"], audience="api", issuer="https://idp.example.test")

    with pytest.raises(error):
        await verifier.verify(signing_key.issue_token(claims))


def test_jwt_verifier_requires_algorithms(make_client: typing.Callable[..., JWKSClient]) -> None:
    with pytest.raises(ValueError, match="algorithms"):
        JWTVerifier(make_client(), algorithms=[])


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("Bearer abc.def.ghi", "abc.def.ghi"),
        ("bearer abc.def.ghi", "abc.def.ghi"),
        ("BEARER   abc.def.ghi  ", "abc.def.ghi"),
        ("Bearer", None),
        ("Bearer   ", None),
        ("Basic dXNlcjpwYXNz", None),
        ("abc.def.ghi", None),
        ("", None),
        (None, None),
    ],
)
def test_extract_bearer_token(header: str | None, expected: str | None) -> None:
    assert extract_bearer_token(header) == expected
