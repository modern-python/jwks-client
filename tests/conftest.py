import asyncio
import dataclasses
import datetime as dt
import json
import typing

import httpware
import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from jwks_client import JWKSClient


JWKS_URI: typing.Final = "https://idp.example.test/.well-known/jwks.json"


@dataclasses.dataclass
class SigningKey:
    kid: str
    private_key: rsa.RSAPrivateKey = dataclasses.field(
        default_factory=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )

    def to_jwk(self, **extra: str) -> dict[str, typing.Any]:
        data: dict[str, typing.Any] = json.loads(RSAAlgorithm.to_jwk(self.private_key.public_key()))
        return data | {"kid": self.kid} | extra

    def issue_token(
        self, claims: dict[str, typing.Any] | None = None, *, algorithm: str = "RS256", **headers: str
    ) -> str:
        payload = {"sub": "user-1", "exp": dt.datetime.now(tz=dt.UTC) + dt.timedelta(minutes=5)}
        return jwt.encode(
            payload | (claims or {}), self.private_key, algorithm=algorithm, headers={"kid": self.kid} | headers
        )


@dataclasses.dataclass
class FakeClock:
    now: float = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclasses.dataclass
class JWKSServer:
    responses: list[httpx2.Response | Exception] = dataclasses.field(default_factory=list)
    requests: list[httpx2.Request] = dataclasses.field(default_factory=list)

    def serve(self, *keys: dict[str, typing.Any]) -> None:
        self.responses.append(httpx2.Response(200, json={"keys": list(keys)}))

    def fail(self, response_or_error: httpx2.Response | Exception) -> None:
        self.responses.append(response_or_error)

    async def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        await asyncio.sleep(0)
        result = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(result, Exception):
            raise result
        return result


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def server() -> JWKSServer:
    return JWKSServer()


@pytest.fixture
def signing_key() -> SigningKey:
    return SigningKey(kid="key-1")


@pytest.fixture
def http_client(server: JWKSServer) -> httpware.AsyncClient:
    return httpware.AsyncClient(transport=httpx2.MockTransport(server.handle))


@pytest.fixture
def make_client(http_client: httpware.AsyncClient, clock: FakeClock) -> typing.Callable[..., JWKSClient]:
    def create_client(**kwargs: float) -> JWKSClient:
        return JWKSClient(JWKS_URI, http_client=http_client, clock=clock, **kwargs)

    return create_client
