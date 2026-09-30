import typing

import jwt

from jwks_client.errors import JWKSFetchError
from jwks_client.verifier import TokenVerifier, UserParser, extract_bearer_token


try:
    from fastapi import HTTPException, Request, status
    from fastapi.openapi.models import HTTPBearer, OpenIdConnect
    from fastapi.security.base import SecurityBase
except ImportError as exc:
    msg = "jwks_client.fastapi requires the fastapi extra: pip install 'jwks-client[fastapi]'"
    raise ImportError(msg) from exc


UNAUTHORIZED_HEADERS: typing.Final = {"WWW-Authenticate": "Bearer"}


def _create_unauthorized_error() -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated", headers=UNAUTHORIZED_HEADERS)


class JWKSBearer(SecurityBase):
    def __init__(
        self,
        verifier: TokenVerifier,
        *,
        user_parser: UserParser | None = None,
        openid_configuration_url: str | None = None,
    ) -> None:
        self.verifier: typing.Final = verifier
        self.user_parser: typing.Final = user_parser
        if openid_configuration_url is None:
            self.model = HTTPBearer(bearerFormat="JWT")
            self.scheme_name = "Bearer"
        else:
            self.model = OpenIdConnect(openIdConnectUrl=openid_configuration_url)
            self.scheme_name = "OpenIdConnect"

    async def __call__(self, request: Request) -> typing.Any:  # noqa: ANN401
        token: typing.Final = extract_bearer_token(request.headers.get("Authorization"))
        if token is None:
            raise _create_unauthorized_error()
        try:
            claims: typing.Final = await self.verifier.verify(token)
        except jwt.InvalidTokenError as exc:
            raise _create_unauthorized_error() from exc
        except JWKSFetchError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="Identity provider unavailable") from exc

        user: typing.Final = claims if self.user_parser is None else self.user_parser(claims)
        if user is None:
            raise _create_unauthorized_error()
        return user
