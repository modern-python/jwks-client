# jwks-client

An async JWKS client for verifying JWTs, with key caching, resilient fetching over
[httpware](https://github.com/modern-python/httpware), and Litestar and FastAPI integrations. It
fetches an identity provider's JSON Web Key Set, caches it, refetches on key rotation without
letting unknown `kid`s flood the provider, keeps serving the last good keys through an outage, and
verifies tokens with [PyJWT](https://github.com/jpadilla/pyjwt).

```python
from jwks_client import JWKSClient, JWTVerifier


jwks = JWKSClient("https://idp.example.com/.well-known/jwks.json")
verifier = JWTVerifier(jwks, algorithms=["RS256"], audience="my-api", issuer="https://idp.example.com")

claims = await verifier.verify(token)
```

## Install

```bash
pip install jwks-client              # core
pip install jwks-client[litestar]    # + Litestar middleware
pip install jwks-client[fastapi]     # + FastAPI dependency
```

## Verifying tokens

`JWTVerifier` fixes the policy once (`algorithms`, `audience`, `issuer`, `leeway`, `options`), so no
call site can forget a check. `verify()` checks the token's `alg` against `algorithms` before any
network call, finds the key by the token's `kid`, verifies the signature, then validates `exp`,
`nbf`, `aud`, and `iss` through `jwt.decode`. When `audience` or `issuer` is set, a token without
that claim is rejected.

For a key published without an `alg`, the key is bound to the token's `alg`, provided it is in
`algorithms` and fits the key type, so an RSA key can verify `PS256` as well as `RS256`.

The same check is available per call as `JWKSClient.decode(token, algorithms=..., ...)`. To verify
yourself, take the key and call PyJWT directly:

```python
import jwt


key = await jwks.get_signing_key_from_jwt(token)  # or get_signing_key(kid)
claims = jwt.decode(token, key, algorithms=["RS256"], audience="my-api")
```

## Errors

| Raised | When | Integrations answer |
|---|---|---|
| `jwt.InvalidTokenError` subclasses | The token is malformed, expired, badly signed, or its claims fail | 401 |
| `KeyNotFoundError` (also a `jwt.InvalidTokenError`) | No key in the set matches the token's `kid` | 401 |
| `JWKSFetchError` | The JWKS endpoint failed and no usable cached keys remain; `__cause__` holds the httpware error | 503 |

All of the package's own errors inherit `JWKSError`.

## Litestar

```python
import litestar
from litestar.middleware import DefineMiddleware
from litestar.openapi.config import OpenAPIConfig

from jwks_client.litestar import JWKSAuthMiddleware, openapi_security_config


app = litestar.Litestar(
    route_handlers=[...],
    middleware=[
        DefineMiddleware(
            JWKSAuthMiddleware,
            verifier=verifier,
            user_parser=lambda claims: User.model_validate(claims),  # optional
            exclude=["/health", "/docs"],
        ),
    ],
    openapi_config=OpenAPIConfig(title="my-api", version="1", **openapi_security_config()),
)
```

`request.auth` holds the verified claims. `request.user` holds `user_parser(claims)`, or the claims
when no parser is given; a parser returning `None` rejects the request with 401. `exclude`,
`exclude_from_auth_key`, `exclude_http_methods`, and `scopes` are Litestar's own
`AbstractAuthenticationMiddleware` options.

## FastAPI

```python
import typing

import fastapi

from jwks_client.fastapi import JWKSBearer


bearer = JWKSBearer(verifier, user_parser=lambda claims: User.model_validate(claims))


@app.get("/me")
async def me(user: typing.Annotated[User, fastapi.Security(bearer)]) -> User:
    return user
```

The dependency returns `user_parser(claims)`, or the claims when no parser is given, and adds a
`Bearer` security scheme to the OpenAPI schema.

## OpenAPI and OpenID Connect

Both integrations declare an HTTP `Bearer` scheme. Pass `openid_configuration_url`, the provider's
discovery document at `/.well-known/openid-configuration` rather than its JWKS URL, to declare an
`OpenIdConnect` scheme as well (Litestar) or instead (FastAPI).

## Resolving the verifier per request

Both integrations take either a `TokenVerifier` or an async function returning one, so a verifier
can come from a DI container:

```python
async def get_verifier() -> TokenVerifier:
    return container.resolve(Verifier)


DefineMiddleware(JWKSAuthMiddleware, verifier=get_verifier)
```

The container must hand back the same verifier every time: a new `JWKSClient` per request starts
with no keys and fetches the key set on every request.

## Caching

| Parameter | Default | Effect |
|---|---|---|
| `ttl` | `300` s | How long a fetched key set is used before it is refetched. |
| `refetch_cooldown` | `30` s | Minimum time between fetches triggered by an unknown `kid`, and between retries after a failed fetch. |
| `stale_if_error` | `3600` s | How long past `ttl` the last good key set keeps being served while refetches fail. |

Concurrent callers share one fetch. Call `await jwks.refresh()` at startup to fetch keys before the
first request.

## HTTP client

Without `http_client=`, the client builds and owns an `httpware.AsyncClient` with a 10 s timeout, a
1 MiB response cap, a circuit breaker, and retries, and closes it in `aclose()` (or on leaving
`async with`). Pass your own `httpware.AsyncClient` to choose the middleware; the client never
closes one it did not create:

```python
import httpware


http_client = httpware.AsyncClient(
    timeout=5.0,
    max_response_body_bytes=1024 * 1024,
    middleware=[httpware.AsyncCircuitBreaker(failure_threshold=3), httpware.AsyncRetry(max_attempts=2)],
)
jwks = JWKSClient("https://idp.example.com/.well-known/jwks.json", http_client=http_client)
```

A `JWKSClient` belongs to one event loop. Create one per process and share it across requests.

## Testing

`jwks_client.testing` signs real tokens, so tests exercise the same verification as production:

```python
from jwks_client.testing import FakeIdentityProvider


idp = FakeIdentityProvider()
verifier = JWTVerifier(idp.jwks_client(), algorithms=["RS256"], audience="my-api", issuer=idp.issuer)
token = idp.issue_token({"sub": "user-1", "aud": "my-api"})
```

`StaticTokenVerifier({"dev-token": {"sub": "developer"}})` accepts fixed tokens without any
signature, for local development only.

## 📦 [PyPI](https://pypi.org/project/jwks-client) · 📝 [License](https://github.com/modern-python/jwks-client/blob/main/LICENSE)

## Part of `modern-python`

Browse the full list of templates and libraries in
[`modern-python`](https://github.com/modern-python) — see the org profile for the categorized index.
