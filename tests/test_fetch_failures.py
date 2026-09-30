import typing

import httpware
import httpx2
import pytest

from jwks_client import JWKSClient, JWKSFetchError
from tests.conftest import FakeClock, JWKSServer, SigningKey


async def test_cold_start_failure_raises_fetch_error_with_cause(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer
) -> None:
    server.fail(httpx2.Response(500))
    client = make_client()

    with pytest.raises(JWKSFetchError) as exc_info:
        await client.get_signing_key("key-1")

    assert isinstance(exc_info.value.__cause__, httpware.ServerStatusError)


async def test_network_error_raises_fetch_error(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer
) -> None:
    server.fail(httpx2.ConnectError("refused"))
    client = make_client()

    with pytest.raises(JWKSFetchError):
        await client.get_signing_key("key-1")


@pytest.mark.parametrize(
    "response",
    [
        httpx2.Response(200, text="<html>not json</html>"),
        httpx2.Response(200, json=["not", "an", "object"]),
        httpx2.Response(200, json={"keys": []}),
        httpx2.Response(200, json={"keys": "not-a-list"}),
        httpx2.Response(200, json={"keys": [{"kty": "unknown", "kid": "broken"}]}),
    ],
)
async def test_invalid_payload_raises_fetch_error(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, response: httpx2.Response
) -> None:
    server.fail(response)
    client = make_client()

    with pytest.raises(JWKSFetchError):
        await client.get_signing_key("key-1")


async def test_failed_fetch_backs_off_for_cooldown(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey, clock: FakeClock
) -> None:
    server.fail(httpx2.Response(500))
    server.serve(signing_key.to_jwk())
    client = make_client(refetch_cooldown=30)

    with pytest.raises(JWKSFetchError):
        await client.get_signing_key("key-1")
    clock.advance(29)
    with pytest.raises(JWKSFetchError):
        await client.get_signing_key("key-1")
    assert len(server.requests) == 1

    clock.advance(1)
    assert (await client.get_signing_key("key-1")).key_id == "key-1"
    assert len(server.requests) == 2


async def test_stale_keys_are_served_when_refresh_fails(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey, clock: FakeClock
) -> None:
    server.serve(signing_key.to_jwk())
    server.fail(httpx2.Response(503))
    client = make_client(ttl=300, stale_if_error=600)

    await client.get_signing_key("key-1")
    clock.advance(300 + 599)
    key = await client.get_signing_key("key-1")

    assert key.key_id == "key-1"
    assert len(server.requests) == 2


async def test_stale_keys_expire_after_stale_if_error(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey, clock: FakeClock
) -> None:
    server.serve(signing_key.to_jwk())
    server.fail(httpx2.Response(503))
    client = make_client(ttl=300, stale_if_error=600)

    await client.get_signing_key("key-1")
    clock.advance(300 + 600)

    with pytest.raises(JWKSFetchError):
        await client.get_signing_key("key-1")


async def test_failed_unknown_kid_refetch_keeps_current_keys(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey, clock: FakeClock
) -> None:
    server.serve(signing_key.to_jwk())
    server.fail(httpx2.Response(503))
    client = make_client(refetch_cooldown=30)

    await client.get_signing_key("key-1")
    clock.advance(30)
    with pytest.raises(JWKSFetchError):
        await client.get_signing_key("key-2")

    assert (await client.get_signing_key("key-1")).key_id == "key-1"


async def test_refresh_propagates_fetch_error(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer
) -> None:
    server.fail(httpx2.Response(500))
    client = make_client()

    with pytest.raises(JWKSFetchError):
        await client.refresh()


async def test_stale_keys_are_served_without_refetch_during_cooldown(
    make_client: typing.Callable[..., JWKSClient], server: JWKSServer, signing_key: SigningKey, clock: FakeClock
) -> None:
    server.serve(signing_key.to_jwk())
    server.fail(httpx2.Response(503))
    client = make_client(ttl=300, refetch_cooldown=30)

    await client.get_signing_key("key-1")
    clock.advance(300)
    await client.get_signing_key("key-1")
    clock.advance(29)
    key = await client.get_signing_key("key-1")

    assert key.key_id == "key-1"
    assert len(server.requests) == 2
