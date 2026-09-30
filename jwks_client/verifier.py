import datetime
import typing
from collections.abc import Container, Iterable, Sequence

from jwt.types import Options

from jwks_client.client import JWKSClient


BEARER_SCHEME: typing.Final = "bearer"


@typing.runtime_checkable
class TokenVerifier(typing.Protocol):
    async def verify(self, token: str) -> dict[str, typing.Any]: ...


class JWTVerifier:
    def __init__(  # noqa: PLR0913
        self,
        jwks: JWKSClient,
        *,
        algorithms: Sequence[str],
        audience: str | Iterable[str] | None = None,
        issuer: str | Container[str] | None = None,
        leeway: float | datetime.timedelta = 0,
        options: Options | None = None,
    ) -> None:
        if not algorithms:
            msg = "algorithms must name at least one signing algorithm"
            raise ValueError(msg)
        self.jwks: typing.Final = jwks
        self.algorithms: typing.Final = tuple(algorithms)
        self.audience: typing.Final = audience
        self.issuer: typing.Final = issuer
        self.leeway: typing.Final = leeway
        self.options: typing.Final = options

    async def verify(self, token: str) -> dict[str, typing.Any]:
        return await self.jwks.decode(
            token,
            algorithms=self.algorithms,
            audience=self.audience,
            issuer=self.issuer,
            leeway=self.leeway,
            options=self.options,
        )


def extract_bearer_token(authorization: str | None) -> str | None:
    scheme, _, token = (authorization or "").strip().partition(" ")
    token = token.strip()
    if scheme.lower() != BEARER_SCHEME or not token:
        return None
    return token
