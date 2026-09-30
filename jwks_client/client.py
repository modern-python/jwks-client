import asyncio
import dataclasses
import datetime
import logging
import math
import time
import typing
import urllib.parse
from collections.abc import Callable, Container, Iterable, Sequence

import httpware
import jwt
from jwt.types import Options

from jwks_client.errors import JWKSFetchError, KeyNotFoundError


LOGGER: typing.Final = logging.getLogger("jwks_client")
DEFAULT_TTL: typing.Final = 300.0
DEFAULT_REFETCH_COOLDOWN: typing.Final = 30.0
DEFAULT_STALE_IF_ERROR: typing.Final = 3600.0
DEFAULT_TIMEOUT: typing.Final = 10.0
DEFAULT_MAX_RESPONSE_BODY_BYTES: typing.Final = 1024 * 1024


@dataclasses.dataclass(frozen=True, slots=True)
class _Key:
    jwk: dict[str, typing.Any]
    key: jwt.PyJWK


def _parse_key_set(payload: object) -> dict[str, _Key]:
    if not isinstance(payload, dict):
        msg = "The JWKS endpoint did not return a JSON object"
        raise JWKSFetchError(msg)
    raw_keys: typing.Final = payload.get("keys")
    if not isinstance(raw_keys, list):
        msg = "The JWKS endpoint did not return a 'keys' list"
        raise JWKSFetchError(msg)

    keys: typing.Final[dict[str, _Key]] = {}
    for jwk in raw_keys:
        if not isinstance(jwk, dict) or not isinstance(jwk.get("kid"), str) or jwk.get("use", "sig") != "sig":
            continue
        try:
            keys.setdefault(jwk["kid"], _Key(jwk=jwk, key=jwt.PyJWK(jwk)))
        except jwt.PyJWTError:
            LOGGER.debug("skipping unusable JWK %r", jwk["kid"], exc_info=True)

    if not keys:
        msg = "The JWKS endpoint did not contain any usable signing key"
        raise JWKSFetchError(msg)
    return keys


def _require_duration(name: str, value: float, *, allow_zero: bool) -> None:
    if not math.isfinite(value) or value < 0 or (value == 0 and not allow_zero):
        bound: typing.Final = ">= 0" if allow_zero else "> 0"
        msg = f"{name} must be finite and {bound}, got {value!r}"
        raise ValueError(msg)


def _default_http_client() -> httpware.AsyncClient:
    return httpware.AsyncClient(
        timeout=DEFAULT_TIMEOUT,
        max_response_body_bytes=DEFAULT_MAX_RESPONSE_BODY_BYTES,
        middleware=[httpware.AsyncCircuitBreaker(), httpware.AsyncRetry()],
    )


class JWKSClient:
    def __init__(  # noqa: PLR0913
        self,
        uri: str,
        *,
        http_client: httpware.AsyncClient | None = None,
        ttl: float = DEFAULT_TTL,
        refetch_cooldown: float = DEFAULT_REFETCH_COOLDOWN,
        stale_if_error: float = DEFAULT_STALE_IF_ERROR,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if urllib.parse.urlsplit(uri).scheme.lower() not in {"http", "https"}:
            msg = f"JWKS URI must use http or https, got {uri!r}"
            raise ValueError(msg)
        _require_duration("ttl", ttl, allow_zero=False)
        _require_duration("refetch_cooldown", refetch_cooldown, allow_zero=True)
        _require_duration("stale_if_error", stale_if_error, allow_zero=True)

        self.uri: typing.Final = uri
        self._owns_http_client: typing.Final = http_client is None
        self._http_client: typing.Final = http_client or _default_http_client()
        self._ttl: typing.Final = ttl
        self._refetch_cooldown: typing.Final = refetch_cooldown
        self._stale_if_error: typing.Final = stale_if_error
        self._clock: typing.Final = clock
        self._lock: typing.Final = asyncio.Lock()
        self._keys: dict[str, _Key] = {}
        self._fetched_at: float | None = None
        self._attempted_at: float | None = None
        self._last_error: JWKSFetchError | None = None

    async def __aenter__(self) -> typing.Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_http_client:
            await self._http_client.aclose()

    async def refresh(self) -> None:
        async with self._lock:
            await self._fetch()

    async def get_signing_key(self, kid: str) -> jwt.PyJWK:
        return (await self._find(kid)).key

    async def get_signing_key_from_jwt(self, token: str | bytes) -> jwt.PyJWK:
        return (await self._find(jwt.get_unverified_header(token).get("kid"))).key

    async def decode(  # noqa: PLR0913
        self,
        token: str | bytes,
        *,
        algorithms: Sequence[str],
        audience: str | Iterable[str] | None = None,
        issuer: str | Container[str] | None = None,
        leeway: float | datetime.timedelta = 0,
        options: Options | None = None,
    ) -> dict[str, typing.Any]:
        header: typing.Final = jwt.get_unverified_header(token)
        algorithm: typing.Final = header.get("alg")
        if not isinstance(algorithm, str) or algorithm not in algorithms:
            msg = "The specified alg value is not allowed"
            raise jwt.InvalidAlgorithmError(msg)

        found: typing.Final = await self._find(header.get("kid"))
        key: typing.Final = found.key if "alg" in found.jwk else self._bind_algorithm(found, algorithm)
        return jwt.decode(
            token,
            key,
            algorithms=list(algorithms),
            audience=audience,
            issuer=issuer,
            leeway=leeway,
            options=options,
        )

    @staticmethod
    def _bind_algorithm(found: _Key, algorithm: str) -> jwt.PyJWK:
        try:
            return jwt.PyJWK(found.jwk, algorithm=algorithm)
        except (jwt.PyJWTError, NotImplementedError) as exc:
            msg = f"Algorithm {algorithm!r} cannot be used with key {found.key.key_id!r}"
            raise jwt.InvalidAlgorithmError(msg) from exc

    async def _find(self, kid: object) -> _Key:
        if not isinstance(kid, str):
            msg = "The token has no 'kid' header"
            raise KeyNotFoundError(msg)
        await self._ensure_fresh()
        if kid not in self._keys:
            await self._refetch_for_unknown(kid)
        try:
            return self._keys[kid]
        except KeyError:
            msg = f"Unable to find a signing key that matches: {kid!r}"
            raise KeyNotFoundError(msg) from None

    def _is_fresh(self) -> bool:
        return self._fetched_at is not None and self._clock() - self._fetched_at < self._ttl

    def _is_cooling_down(self) -> bool:
        return self._attempted_at is not None and self._clock() - self._attempted_at < self._refetch_cooldown

    def _can_serve_stale(self) -> bool:
        return self._fetched_at is not None and self._clock() - self._fetched_at < self._ttl + self._stale_if_error

    async def _ensure_fresh(self) -> None:
        if self._is_fresh():
            return
        async with self._lock:
            if self._is_fresh():
                return
            if self._last_error is not None and self._is_cooling_down():
                if self._can_serve_stale():
                    return
                msg = "The last JWKS fetch failed; not retrying until the cooldown elapses"
                raise JWKSFetchError(msg) from self._last_error
            try:
                await self._fetch()
            except JWKSFetchError:
                if not self._can_serve_stale():
                    raise
                LOGGER.warning("JWKS refresh failed, serving stale keys from %s", self.uri, exc_info=True)

    async def _refetch_for_unknown(self, kid: str) -> None:
        async with self._lock:
            if kid in self._keys or self._is_cooling_down():
                return
            await self._fetch()

    async def _fetch(self) -> None:
        self._attempted_at = self._clock()
        try:
            keys: typing.Final = _parse_key_set(await self._download())
        except JWKSFetchError as exc:
            self._last_error = exc
            raise
        self._keys = keys
        self._fetched_at = self._attempted_at
        self._last_error = None

    async def _download(self) -> object:
        try:
            response: typing.Final = await self._http_client.get(self.uri)
            return response.json()
        except (httpware.ClientError, ValueError) as exc:
            msg = f"Failed to fetch JWKS from {self.uri}: {exc}"
            raise JWKSFetchError(msg) from exc
