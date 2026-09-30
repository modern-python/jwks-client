# One cooldown gates every refetch

A single `refetch_cooldown` bounds both refetches for an unknown kid and retries after a failed
fetch, including the first fetch after startup, so a client with no keys fails fast with
`JWKSFetchError` for up to one cooldown after a failure rather than trying again on every request.
The alternative, retrying a cold start on every request, keeps a service's login path waiting on an
identity provider that is already down, and every request then joins a queue behind the lock.
Transient blips are the HTTP client's job: its retry middleware absorbs them before a fetch is
counted as failed.
