# jwks-client

An async client that fetches an identity provider's JSON Web Key Set, caches it, and verifies JWTs
against it.

## Language

A term is listed only when there is a synonym to reject, or a meaning subtle enough that code and
docs must agree on it.

**Key set**:
The signing keys parsed from one JWKS response: every JWK with a string `kid`, a `use` of `sig` or
none, and key material PyJWT can load. Anything else in the response is dropped, not an error.
_Avoid_: cache, as a noun for it. The key set is the data; how long it is trusted is the TTL.

**Unknown kid**:
A token `kid` absent from a fresh key set. It may be a rotated key the set does not have yet, or an
attacker's guess; the client cannot tell which, so it refetches at most once per cooldown.
_Avoid_: missing key, invalid key. The key is not invalid, only not found.

**Cooldown**:
The minimum interval after a fetch attempt before an unknown kid may trigger another, and after a
failed attempt before any request may. `refresh()` ignores it.
_Avoid_: backoff. Nothing grows; the interval is fixed.

**Stale key set**:
A key set past its TTL that is still served because refetching it failed, for at most
`stale_if_error` seconds past the TTL.
_Avoid_: expired key set, which is one past its TTL whose refetch has not been tried yet.
