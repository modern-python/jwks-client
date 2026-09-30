import jwt


class JWKSError(Exception):
    """Base class for every error jwks-client raises."""


class JWKSFetchError(JWKSError):
    """The JWKS endpoint could not be fetched, or returned no usable signing key."""


class KeyNotFoundError(JWKSError, jwt.InvalidTokenError):
    """No signing key in the JWKS matches the token's ``kid``."""
