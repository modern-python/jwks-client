import typing
from collections.abc import Awaitable, Callable

from jwks_client.verifier import TokenVerifier


VerifierSource = TokenVerifier | Callable[[], Awaitable[TokenVerifier]]
UserParser = Callable[[dict[str, typing.Any]], typing.Any]


async def resolve_verifier(source: VerifierSource) -> TokenVerifier:
    if isinstance(source, TokenVerifier):
        return source
    return await source()
