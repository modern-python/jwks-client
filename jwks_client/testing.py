import datetime as dt
import json
import typing
from collections.abc import Mapping

import httpware
import httpx2
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from jwks_client.client import JWKSClient


DEFAULT_TOKEN_LIFETIME: typing.Final = dt.timedelta(minutes=5)


class FakeIdentityProvider:
    def __init__(self, *, issuer: str = "https://idp.test", kid: str = "test-key") -> None:
        self.issuer: typing.Final = issuer
        self.kid: typing.Final = kid
        self.jwks_uri: typing.Final = f"{issuer}/.well-known/jwks.json"
        self._private_key: typing.Final = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk: typing.Final = json.loads(RSAAlgorithm.to_jwk(self._private_key.public_key()))
        self.jwks: typing.Final[dict[str, typing.Any]] = {"keys": [jwk | {"kid": kid, "use": "sig", "alg": "RS256"}]}

    def issue_token(
        self,
        claims: Mapping[str, typing.Any] | None = None,
        *,
        expires_in: dt.timedelta = DEFAULT_TOKEN_LIFETIME,
        headers: Mapping[str, typing.Any] | None = None,
    ) -> str:
        now: typing.Final = dt.datetime.now(tz=dt.UTC)
        payload: typing.Final = {"iss": self.issuer, "iat": now, "exp": now + expires_in} | dict(claims or {})
        return jwt.encode(
            payload, self._private_key, algorithm="RS256", headers={"kid": self.kid} | dict(headers or {})
        )

    def create_jwks_client(self) -> JWKSClient:
        transport: typing.Final = httpx2.MockTransport(lambda _: httpx2.Response(200, json=self.jwks))
        return JWKSClient(self.jwks_uri, http_client=httpware.AsyncClient(transport=transport))


class StaticTokenVerifier:
    def __init__(self, tokens: Mapping[str, Mapping[str, typing.Any]]) -> None:
        self._tokens: typing.Final = tokens

    async def verify(self, token: str) -> dict[str, typing.Any]:
        try:
            return dict(self._tokens[token])
        except KeyError:
            msg = "Unknown token"
            raise jwt.InvalidTokenError(msg) from None
