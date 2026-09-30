# Framework integrations ship as extras

The Litestar middleware and the FastAPI dependency live in this package as `jwks_client.litestar`
and `jwks_client.fastapi`, installed through the `[litestar]` and `[fastapi]` extras, not as
separate `jwks-client-litestar` and `jwks-client-fastapi` packages the way `modern-di` splits its
integrations. Each integration is a few dozen lines that only map the core's errors to the
framework's 401 and 503 and has no release cadence of its own, so separate packages would add two
repos, two release pipelines, and version-matching between them for no independence gained. The
trade is that the core's test suite and floors job carry both frameworks. Split an integration out
when it grows a dependency or a release cycle the core does not share.
