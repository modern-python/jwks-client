import dataclasses
import typing
from http import HTTPStatus

import httpware
import httpx2
import litestar
import pytest
from litestar.middleware import DefineMiddleware
from litestar.openapi.config import OpenAPIConfig
from litestar.testing import AsyncTestClient

from jwks_client import JWKSClient, JWTVerifier, TokenVerifier
from jwks_client.litestar import JWKSAuthMiddleware, openapi_security_config
from jwks_client.testing import FakeIdentityProvider


@dataclasses.dataclass(frozen=True)
class User:
    name: str


@litestar.get("/claims")
async def read_claims(request: litestar.Request[typing.Any, typing.Any, typing.Any]) -> dict[str, typing.Any]:
    return {"user": request.user, "auth": request.auth}


@litestar.get("/user")
async def read_user(request: litestar.Request[User, typing.Any, typing.Any]) -> str:
    return request.user.name


@litestar.get("/health")
async def health() -> str:
    return "ok"


def build_app(verifier: object, **middleware_kwargs: typing.Any) -> litestar.Litestar:  # noqa: ANN401
    return litestar.Litestar(
        route_handlers=[read_claims, read_user, health],
        middleware=[DefineMiddleware(JWKSAuthMiddleware, verifier=verifier, **middleware_kwargs)],
    )


@pytest.fixture
def idp() -> FakeIdentityProvider:
    return FakeIdentityProvider()


@pytest.fixture
def verifier(idp: FakeIdentityProvider) -> JWTVerifier:
    return JWTVerifier(idp.jwks_client(), algorithms=["RS256"], audience="api")


async def test_valid_token_exposes_claims_as_user_and_auth(idp: FakeIdentityProvider, verifier: JWTVerifier) -> None:
    async with AsyncTestClient(build_app(verifier)) as client:
        response = await client.get(
            "/claims", headers={"Authorization": f"Bearer {idp.issue_token({'sub': 'u1', 'aud': 'api'})}"}
        )

    assert response.status_code == HTTPStatus.OK
    assert response.json()["user"]["sub"] == "u1"
    assert response.json()["auth"]["sub"] == "u1"


async def test_user_parser_result_becomes_user(idp: FakeIdentityProvider, verifier: JWTVerifier) -> None:
    app = build_app(verifier, user_parser=lambda claims: User(name=claims["sub"]))
    async with AsyncTestClient(app) as client:
        response = await client.get(
            "/user", headers={"Authorization": f"Bearer {idp.issue_token({'sub': 'u1', 'aud': 'api'})}"}
        )

    assert response.status_code == HTTPStatus.OK
    assert response.text == "u1"


async def test_user_parser_rejecting_claims_is_unauthorized(idp: FakeIdentityProvider, verifier: JWTVerifier) -> None:
    app = build_app(verifier, user_parser=lambda _: None)
    async with AsyncTestClient(app) as client:
        response = await client.get(
            "/user", headers={"Authorization": f"Bearer {idp.issue_token({'sub': 'u1', 'aud': 'api'})}"}
        )

    assert response.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.parametrize("authorization", [None, "Basic dXNlcjpwYXNz", "Bearer not-a-jwt"])
async def test_missing_or_invalid_token_is_unauthorized(verifier: JWTVerifier, authorization: str | None) -> None:
    headers = {"Authorization": authorization} if authorization else {}
    async with AsyncTestClient(build_app(verifier)) as client:
        response = await client.get("/claims", headers=headers)

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.headers["www-authenticate"] == "Bearer"


async def test_token_outside_policy_is_unauthorized(idp: FakeIdentityProvider, verifier: JWTVerifier) -> None:
    async with AsyncTestClient(build_app(verifier)) as client:
        response = await client.get("/claims", headers={"Authorization": f"Bearer {idp.issue_token({'aud': 'other'})}"})

    assert response.status_code == HTTPStatus.UNAUTHORIZED


async def test_unreachable_identity_provider_is_service_unavailable(idp: FakeIdentityProvider) -> None:
    transport = httpx2.MockTransport(lambda _: httpx2.Response(HTTPStatus.BAD_GATEWAY))
    jwks = JWKSClient(
        idp.jwks_uri, http_client=httpware.AsyncClient(httpx2_client=httpx2.AsyncClient(transport=transport))
    )
    async with AsyncTestClient(build_app(JWTVerifier(jwks, algorithms=["RS256"]))) as client:
        response = await client.get("/claims", headers={"Authorization": f"Bearer {idp.issue_token()}"})

    assert response.status_code == HTTPStatus.SERVICE_UNAVAILABLE


async def test_excluded_path_skips_authentication(verifier: JWTVerifier) -> None:
    async with AsyncTestClient(build_app(verifier, exclude=["/health"])) as client:
        response = await client.get("/health")

    assert response.status_code == HTTPStatus.OK


async def test_verifier_can_be_resolved_per_request(idp: FakeIdentityProvider, verifier: JWTVerifier) -> None:
    async def get_verifier() -> TokenVerifier:
        return verifier

    async with AsyncTestClient(build_app(get_verifier)) as client:
        response = await client.get(
            "/claims", headers={"Authorization": f"Bearer {idp.issue_token({'sub': 'u1', 'aud': 'api'})}"}
        )

    assert response.status_code == HTTPStatus.OK


def test_openapi_security_config_declares_bearer_scheme() -> None:
    config = OpenAPIConfig(title="api", version="1", **openapi_security_config())

    schema = litestar.Litestar(route_handlers=[health], openapi_config=config).openapi_schema.to_schema()

    assert schema["components"]["securitySchemes"] == {
        "Bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
    }
    assert schema["security"] == [{"Bearer": []}]


def test_openapi_security_config_adds_openid_connect_when_given_discovery_url() -> None:
    discovery_url = "https://idp.test/.well-known/openid-configuration"
    config = OpenAPIConfig(title="api", version="1", **openapi_security_config(discovery_url))

    schema = litestar.Litestar(route_handlers=[health], openapi_config=config).openapi_schema.to_schema()

    assert schema["components"]["securitySchemes"]["OpenIdConnect"] == {
        "type": "openIdConnect",
        "openIdConnectUrl": discovery_url,
    }
    assert schema["security"] == [{"Bearer": []}, {"OpenIdConnect": []}]
