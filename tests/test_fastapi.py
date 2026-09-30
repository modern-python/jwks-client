import dataclasses
import typing
from http import HTTPStatus

import fastapi
import httpware
import httpx2
import pytest

from jwks_client import JWKSClient, JWTVerifier, TokenVerifier
from jwks_client.fastapi import JWKSBearer
from jwks_client.testing import FakeIdentityProvider


@dataclasses.dataclass(frozen=True)
class User:
    name: str


def build_app(bearer: JWKSBearer) -> fastapi.FastAPI:
    app = fastapi.FastAPI()

    @app.get("/me")
    async def me(user: typing.Annotated[typing.Any, fastapi.Security(bearer)]) -> typing.Any:  # noqa: ANN401
        return user if isinstance(user, dict) else {"name": user.name}

    return app


async def call(app: fastapi.FastAPI, token: str | None = None) -> httpx2.Response:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://test") as client:
        return await client.get("/me", headers=headers)


@pytest.fixture
def idp() -> FakeIdentityProvider:
    return FakeIdentityProvider()


@pytest.fixture
def verifier(idp: FakeIdentityProvider) -> JWTVerifier:
    return JWTVerifier(idp.jwks_client(), algorithms=["RS256"], audience="api")


async def test_valid_token_returns_claims(idp: FakeIdentityProvider, verifier: JWTVerifier) -> None:
    response = await call(build_app(JWKSBearer(verifier)), idp.issue_token({"sub": "u1", "aud": "api"}))

    assert response.status_code == HTTPStatus.OK
    assert response.json()["sub"] == "u1"


async def test_user_parser_result_is_returned(idp: FakeIdentityProvider, verifier: JWTVerifier) -> None:
    bearer = JWKSBearer(verifier, user_parser=lambda claims: User(name=claims["sub"]))

    response = await call(build_app(bearer), idp.issue_token({"sub": "u1", "aud": "api"}))

    assert response.json() == {"name": "u1"}


async def test_user_parser_rejecting_claims_is_unauthorized(idp: FakeIdentityProvider, verifier: JWTVerifier) -> None:
    response = await call(build_app(JWKSBearer(verifier, user_parser=lambda _: None)), idp.issue_token({"aud": "api"}))

    assert response.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.parametrize("token", [None, "not-a-jwt"])
async def test_missing_or_invalid_token_is_unauthorized(verifier: JWTVerifier, token: str | None) -> None:
    response = await call(build_app(JWKSBearer(verifier)), token)

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.headers["www-authenticate"] == "Bearer"


async def test_unreachable_identity_provider_is_service_unavailable(idp: FakeIdentityProvider) -> None:
    transport = httpx2.MockTransport(lambda _: httpx2.Response(HTTPStatus.BAD_GATEWAY))
    jwks = JWKSClient(
        idp.jwks_uri, http_client=httpware.AsyncClient(httpx2_client=httpx2.AsyncClient(transport=transport))
    )

    response = await call(build_app(JWKSBearer(JWTVerifier(jwks, algorithms=["RS256"]))), idp.issue_token())

    assert response.status_code == HTTPStatus.SERVICE_UNAVAILABLE


async def test_verifier_can_be_resolved_per_request(idp: FakeIdentityProvider, verifier: JWTVerifier) -> None:
    async def get_verifier() -> TokenVerifier:
        return verifier

    response = await call(build_app(JWKSBearer(get_verifier)), idp.issue_token({"aud": "api"}))

    assert response.status_code == HTTPStatus.OK


def test_openapi_declares_bearer_scheme(verifier: JWTVerifier) -> None:
    schema = build_app(JWKSBearer(verifier)).openapi()

    assert schema["components"]["securitySchemes"] == {
        "Bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
    }
    assert schema["paths"]["/me"]["get"]["security"] == [{"Bearer": []}]


def test_openapi_declares_openid_connect_when_given_discovery_url(verifier: JWTVerifier) -> None:
    discovery_url = "https://idp.test/.well-known/openid-configuration"

    schema = build_app(JWKSBearer(verifier, openid_configuration_url=discovery_url)).openapi()

    assert schema["components"]["securitySchemes"] == {
        "OpenIdConnect": {"type": "openIdConnect", "openIdConnectUrl": discovery_url}
    }
