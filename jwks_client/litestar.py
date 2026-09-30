import typing
from collections.abc import Sequence

import jwt
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException, ServiceUnavailableException
from litestar.middleware import AbstractAuthenticationMiddleware, AuthenticationResult
from litestar.openapi.spec import Components, SecurityRequirement, SecurityScheme
from litestar.types import ASGIApp, Method, Scopes

from jwks_client._integration import UserParser, VerifierSource, resolve_verifier
from jwks_client.errors import JWKSFetchError
from jwks_client.verifier import extract_bearer_token


UNAUTHORIZED_HEADERS: typing.Final = {"WWW-Authenticate": "Bearer"}


class JWKSAuthMiddleware(AbstractAuthenticationMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        *,
        verifier: VerifierSource,
        user_parser: UserParser | None = None,
        exclude: str | list[str] | None = None,
        exclude_from_auth_key: str = "exclude_from_auth",
        exclude_http_methods: Sequence[Method] | None = None,
        scopes: "Scopes | None" = None,
    ) -> None:
        super().__init__(app, exclude, exclude_from_auth_key, exclude_http_methods, scopes)
        self.verifier: typing.Final = verifier
        self.user_parser: typing.Final = user_parser

    async def authenticate_request(
        self, connection: ASGIConnection[typing.Any, typing.Any, typing.Any, typing.Any]
    ) -> AuthenticationResult:
        token: typing.Final = extract_bearer_token(connection.headers.get("Authorization"))
        if token is None:
            raise NotAuthorizedException(headers=UNAUTHORIZED_HEADERS)
        try:
            claims: typing.Final = await (await resolve_verifier(self.verifier)).verify(token)
        except jwt.InvalidTokenError as exc:
            raise NotAuthorizedException(headers=UNAUTHORIZED_HEADERS) from exc
        except JWKSFetchError as exc:
            raise ServiceUnavailableException from exc

        user: typing.Final = claims if self.user_parser is None else self.user_parser(claims)
        if user is None:
            raise NotAuthorizedException(headers=UNAUTHORIZED_HEADERS)
        return AuthenticationResult(user=user, auth=claims)


class OpenAPISecurityConfig(typing.TypedDict):
    components: Components
    security: list[SecurityRequirement]


def openapi_security_config(openid_configuration_url: str | None = None) -> OpenAPISecurityConfig:
    schemes: typing.Final[dict[str, SecurityScheme]] = {
        "Bearer": SecurityScheme(type="http", scheme="bearer", bearer_format="JWT"),
    }
    if openid_configuration_url is not None:
        schemes["OpenIdConnect"] = SecurityScheme(type="openIdConnect", open_id_connect_url=openid_configuration_url)
    return {
        "components": Components(security_schemes=dict(schemes)),
        "security": [{name: []} for name in schemes],
    }
