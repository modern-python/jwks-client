import asyncio
import typing

import jwt
import pytest

from jwks_client import JWKSClient, KeyNotFoundError
from tests.conftest import FakeClock, JWKSServer, SigningKey


async def test_get_signing_key_fetches_once_within_ttl(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey, clock: FakeClock
) -> None:
    server.serve(signing_key.to_jwk())
    client = make_client(ttl=300)

    first = await client.get_signing_key("key-1")
    clock.advance(299)
    second = await client.get_signing_key("key-1")

    assert first.key_id == second.key_id == "key-1"
    assert len(server.requests) == 1


async def test_expired_key_set_is_refetched(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey, clock: FakeClock
) -> None:
    server.serve(signing_key.to_jwk())
    client = make_client(ttl=300)

    await client.get_signing_key("key-1")
    clock.advance(300)
    await client.get_signing_key("key-1")

    assert len(server.requests) == 2


async def test_unknown_kid_refetches_and_finds_rotated_key(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey, clock: FakeClock
) -> None:
    rotated = SigningKey(kid="key-2")
    server.serve(signing_key.to_jwk())
    server.serve(signing_key.to_jwk(), rotated.to_jwk())
    client = make_client(refetch_cooldown=30)

    await client.get_signing_key("key-1")
    clock.advance(30)
    key = await client.get_signing_key("key-2")

    assert key.key_id == "key-2"
    assert len(server.requests) == 2


async def test_unknown_kid_within_cooldown_does_not_refetch(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey, clock: FakeClock
) -> None:
    server.serve(signing_key.to_jwk())
    client = make_client(refetch_cooldown=30)

    await client.get_signing_key("key-1")
    clock.advance(29)
    with pytest.raises(KeyNotFoundError):
        await client.get_signing_key("random-kid")

    assert len(server.requests) == 1


async def test_unknown_kid_refetches_at_most_once_per_cooldown(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey, clock: FakeClock
) -> None:
    server.serve(signing_key.to_jwk())
    client = make_client(refetch_cooldown=30)
    await client.get_signing_key("key-1")
    clock.advance(30)

    for kid in ("random-1", "random-2", "random-3"):
        with pytest.raises(KeyNotFoundError):
            await client.get_signing_key(kid)

    assert len(server.requests) == 2


async def test_concurrent_cold_lookups_share_one_fetch(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey
) -> None:
    server.serve(signing_key.to_jwk())
    client = make_client()

    keys = await asyncio.gather(*(client.get_signing_key("key-1") for _ in range(10)))

    assert {key.key_id for key in keys} == {"key-1"}
    assert len(server.requests) == 1


async def test_refresh_prefetches_keys(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey
) -> None:
    server.serve(signing_key.to_jwk())
    client = make_client()

    await client.refresh()
    await client.get_signing_key("key-1")

    assert len(server.requests) == 1


async def test_key_set_keeps_only_signing_keys_with_kid(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey
) -> None:
    no_use = SigningKey(kid="no-use")
    no_kid = signing_key.to_jwk()
    del no_kid["kid"]
    server.serve(
        signing_key.to_jwk(use="sig"),
        no_use.to_jwk(),
        SigningKey(kid="enc").to_jwk(use="enc"),
        no_kid,
        {"kty": "unknown", "kid": "broken"},
        "not-a-jwk",  # ty: ignore[invalid-argument-type]
    )
    client = make_client()

    assert (await client.get_signing_key("key-1")).key_id == "key-1"
    assert (await client.get_signing_key("no-use")).key_id == "no-use"
    for kid in ("enc", "broken"):
        with pytest.raises(KeyNotFoundError):
            await client.get_signing_key(kid)


async def test_get_signing_key_from_jwt_reads_kid_header(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey
) -> None:
    server.serve(signing_key.to_jwk())
    client = make_client()

    key = await client.get_signing_key_from_jwt(signing_key.issue_token())

    assert key.key_id == "key-1"


async def test_token_without_kid_is_key_not_found(
    make_client: typing.Callable[..., JWKSClient], signing_key: SigningKey
) -> None:
    token = jwt.encode({"sub": "user-1"}, signing_key.private_key, algorithm="RS256")
    client = make_client()

    with pytest.raises(KeyNotFoundError):
        await client.get_signing_key_from_jwt(token)


def test_key_not_found_is_an_invalid_token_error() -> None:
    assert issubclass(KeyNotFoundError, jwt.InvalidTokenError)
