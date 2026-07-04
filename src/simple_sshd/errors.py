"""Package-specific exceptions."""


class SimpleSSHDError(Exception):
    """Base class for simple-sshd exceptions."""


class ConfigurationError(SimpleSSHDError):
    """Raised when configuration cannot be used safely."""


class AuthorizedKeysError(ConfigurationError):
    """Raised when an authorized_keys file cannot be parsed."""
