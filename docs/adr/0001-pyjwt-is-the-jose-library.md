# PyJWT is the JOSE library

The client parses keys and verifies tokens with PyJWT, not joserfc, and returns `jwt.PyJWK` from its
public API, so switching later is a breaking change. PyJWT won on three counts: its `PyJWKSet`
skips a malformed key where joserfc fails the whole set, so one bad key an identity provider
publishes cannot break verification; it is what most Python auth code already depends on, so a
returned `PyJWK` drops into existing `jwt.decode` calls; and its sync `PyJWKClient` is the design
this client ports to async. The cost is PyJWT binding an `alg`-less RSA key to `RS256`, which
`decode()` works around by binding such a key to the token's allowed `alg`. joserfc's stricter
parsing was the rejected trade: it also rejects real tokens, such as Azure's with a `nonce` header.
