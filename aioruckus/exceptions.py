"""Exceptions used in aioruckus."""


class AuthenticationError(Exception):
    """Invalid login."""

class SchemaError(KeyError):
    """Response doesn't contain expected keys"""