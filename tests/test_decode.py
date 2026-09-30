import datetime
import typing

import jwt
import pytest

from jwks_client import JWKSClient, KeyNotFoundError
from tests.conftest import JWKSServer, SigningKey


async def test_decode_returns_verified_claims(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey
) -> None:
    server.serve(signing_key.to_jwk(alg="RS256"))
    client = make_client()
    token = signing_key.issue_token({"aud": "api", "iss": "https://idp.example.test"})

    claims = await client.decode(token, algorithms=["RS256"], audience="api", issuer="https://idp.example.test")

    assert claims["sub"] == "user-1"


async def test_decode_rejects_wrong_audience(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey
) -> None:
    server.serve(signing_key.to_jwk())
    client = make_client()

    with pytest.raises(jwt.InvalidAudienceError):
        await client.decode(signing_key.issue_token({"aud": "other"}), algorithms=["RS256"], audience="api")


async def test_decode_rejects_expired_token(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey
) -> None:
    server.serve(signing_key.to_jwk())
    client = make_client()
    expired = datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(minutes=1)

    with pytest.raises(jwt.ExpiredSignatureError):
        await client.decode(signing_key.issue_token({"exp": expired}), algorithms=["RS256"])


async def test_decode_honours_leeway(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey
) -> None:
    server.serve(signing_key.to_jwk())
    client = make_client()
    expired = datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(seconds=10)

    claims = await client.decode(signing_key.issue_token({"exp": expired}), algorithms=["RS256"], leeway=60)

    assert claims["sub"] == "user-1"


async def test_decode_rejects_signature_from_another_key(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey
) -> None:
    impostor = SigningKey(kid="key-1")
    server.serve(signing_key.to_jwk())
    client = make_client()

    with pytest.raises(jwt.InvalidSignatureError):
        await client.decode(impostor.issue_token(), algorithms=["RS256"])


async def test_decode_rejects_algorithm_outside_allow_list_before_fetching(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey
) -> None:
    client = make_client()

    with pytest.raises(jwt.InvalidAlgorithmError):
        await client.decode(signing_key.issue_token(algorithm="PS256"), algorithms=["RS256"])

    assert server.requests == []


async def test_decode_uses_token_algorithm_for_key_without_alg(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey
) -> None:
    server.serve(signing_key.to_jwk())
    client = make_client()

    claims = await client.decode(signing_key.issue_token(algorithm="PS256"), algorithms=["RS256", "PS256"])

    assert claims["sub"] == "user-1"


async def test_decode_rejects_token_algorithm_that_contradicts_key_alg(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey
) -> None:
    server.serve(signing_key.to_jwk(alg="RS256"))
    client = make_client()

    with pytest.raises(jwt.InvalidAlgorithmError):
        await client.decode(signing_key.issue_token(algorithm="PS256"), algorithms=["RS256", "PS256"])


async def test_decode_rejects_algorithm_incompatible_with_key_type(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey
) -> None:
    server.serve(signing_key.to_jwk())
    client = make_client()
    forged = jwt.encode({"sub": "user-1"}, "secret-long-enough-for-hmac-sha256!", headers={"kid": "key-1"})

    with pytest.raises(jwt.InvalidAlgorithmError):
        await client.decode(forged, algorithms=["RS256", "HS256"])


async def test_decode_rejects_unknown_kid(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey
) -> None:
    server.serve(signing_key.to_jwk())
    client = make_client()

    with pytest.raises(KeyNotFoundError):
        await client.decode(SigningKey(kid="other").issue_token(), algorithms=["RS256"])


async def test_decode_rejects_malformed_token(make_client: typing.Callable[..., JWKSClient]) -> None:
    client = make_client()

    with pytest.raises(jwt.DecodeError):
        await client.decode("not-a-jwt", algorithms=["RS256"])


async def test_decode_rejects_unsigned_token_even_when_none_is_allowed(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey
) -> None:
    server.serve(signing_key.to_jwk())
    client = make_client()
    unsigned = jwt.encode({"sub": "user-1"}, "", algorithm="none", headers={"kid": "key-1"})

    with pytest.raises(jwt.InvalidAlgorithmError):
        await client.decode(unsigned, algorithms=["RS256", "none"])
