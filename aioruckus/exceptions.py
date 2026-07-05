"""Exceptions used in aioruckus."""

class NotDirectorError(Exception):
    """The target device is not ZoneDirector/Unleashed"""

class AuthenticationError(Exception):
    """Invalid login"""

class SchemaError(KeyError):
    """Response doesn't contain expected keys"""

class BusinessRuleError(RuntimeError):
    """Input failed validation"""

class AuthorizationError(RuntimeError):
    """Insufficient permissions"""