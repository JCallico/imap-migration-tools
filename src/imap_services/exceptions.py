"""Exceptions raised by the public IMAP services API."""


class ImapServiceError(Exception):
    """Base class for service-level failures."""


class ConfigurationError(ImapServiceError, ValueError):
    """Raised when a service is configured with invalid values."""


class AuthenticationError(ImapServiceError):
    """Raised when account authentication fails."""


class ConnectionError(ImapServiceError):
    """Raised when an IMAP connection cannot be established."""


class FilesystemError(ImapServiceError):
    """Raised when a required local path cannot be accessed."""


class CallbackError(ImapServiceError):
    """Raised when an event subscriber fails."""


class OperationError(ImapServiceError):
    """Raised when an operation cannot be completed."""
