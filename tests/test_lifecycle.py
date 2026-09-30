import typing
from http import HTTPStatus

import httpware
import pytest

from jwks_client import JWKSClient, JWKSFetchError
from tests.conftest import JWKS_URI, JWKSServer, SigningKey


async def test_injected_http_client_is_left_open(
    http_client: httpware.AsyncClient, server: JWKSServer, signing_key: SigningKey
) -> None:
    server.serve(signing_key.to_jwk())

    async with JWKSClient(JWKS_URI, http_client=http_client):
        pass

    response = await http_client.get(JWKS_URI)
    assert response.status_code == HTTPStatus.OK


async def test_owned_http_client_is_closed() -> None:
    client = JWKSClient(JWKS_URI)
    await client.aclose()

    with pytest.raises(JWKSFetchError):
        await client.refresh()


@pytest.mark.parametrize("uri", ["file:///etc/passwd", "ftp://idp.example.test/jwks.json", "idp.example.test"])
def test_rejects_non_http_uri(uri: str) -> None:
    with pytest.raises(ValueError, match="http"):
        JWKSClient(uri)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ttl": 0},
        {"ttl": float("inf")},
        {"refetch_cooldown": -1},
        {"refetch_cooldown": float("nan")},
        {"stale_if_error": -1},
        {"stale_if_error": float("inf")},
    ],
)
def test_rejects_invalid_durations(make_client: typing.Callable[..., JWKSClient], kwargs: dict[str, float]) -> None:
    with pytest.raises(ValueError, match="must be"):
        make_client(**kwargs)
