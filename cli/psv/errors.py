class PSVError(Exception):
    """Base exception for all CLI operations."""
    pass


class APIConnectionError(PSVError):
    """Raised when unable to reach the FastAPI backend."""
    pass


class AuthenticationError(PSVError):
    """Raised when token or credentials are invalid."""
    pass


class CommandExecutionError(PSVError):
    """Raised when an API operation fails."""
    pass
