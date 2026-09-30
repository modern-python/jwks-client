# jwks-client

An async JWKS client for verifying JWTs, with key caching and resilient fetching over
[httpware](https://github.com/modern-python/httpware). It fetches an identity provider's JSON Web
Key Set, caches it, refetches on key rotation without letting unknown `kid`s flood the provider,
keeps serving the last good keys through an outage, and verifies tokens with
[PyJWT](https://github.com/jpadilla/pyjwt).

```python
from jwks_client import JWKSClient


async with JWKSClient("https://idp.example.com/.well-known/jwks.json") as jwks:
    claims = await jwks.decode(token, algorithms=["RS256"], audience="my-api", issuer="https://idp.example.com")
```

## Install

```bash
pip install jwks-client
```

## Verifying tokens

`decode()` checks the token's `alg` against `algorithms` before any network call, finds the key by
the token's `kid`, verifies the signature, then validates `exp`, `nbf`, `aud`, and `iss` through
`jwt.decode`. `audience`, `issuer`, `leeway`, and `options` mean what they mean there.

For a key published without an `alg`, the key is bound to the token's `alg`, provided it is in
`algorithms` and fits the key type, so an RSA key can verify `PS256` as well as `RS256`.

To verify yourself, take the key and call PyJWT directly:

```python
import jwt


key = await jwks.get_signing_key_from_jwt(token)  # or get_signing_key(kid)
claims = jwt.decode(token, key, algorithms=["RS256"], audience="my-api")
```

## Errors

| Raised | When | Typical response |
|---|---|---|
| `jwt.InvalidTokenError` subclasses | The token is malformed, expired, badly signed, or its claims fail | 401 |
| `KeyNotFoundError` (also a `jwt.InvalidTokenError`) | No key in the set matches the token's `kid` | 401 |
| `JWKSFetchError` | The JWKS endpoint failed and no usable cached keys remain; `__cause__` holds the httpware error | 503 |

All of the package's own errors inherit `JWKSError`.

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
1 MiB response cap, a circuit breaker, and retries, and closes it in `aclose()`. Pass your own
`httpware.AsyncClient` to choose the middleware; the client never closes one it did not create:

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

## 📦 [PyPI](https://pypi.org/project/jwks-client) · 📝 [License](https://github.com/modern-python/jwks-client/blob/main/LICENSE)

## Part of `modern-python`

Browse the full list of templates and libraries in
[`modern-python`](https://github.com/modern-python) — see the org profile for the categorized index.
