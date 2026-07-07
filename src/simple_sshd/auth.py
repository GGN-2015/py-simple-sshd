"""Authentication helpers for public keys and password files."""

from __future__ import annotations

import base64
import getpass
import hmac
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import paramiko

from .errors import AuthorizedKeysError, ConfigurationError


_KEY_TYPES = {
    identifier
    for key_class in (
        paramiko.RSAKey,
        getattr(paramiko, "ECDSAKey", None),
        getattr(paramiko, "Ed25519Key", None),
        getattr(paramiko, "DSSKey", None),
    )
    if key_class is not None
    for identifier in key_class.identifiers()
}


@dataclass(frozen=True)
class AuthorizedPublicKey:
    """A parsed authorized_keys entry."""

    key_type: str
    key_blob: str
    line_number: int
    comment: str = ""

    @classmethod
    def from_paramiko_key(
        cls, key: paramiko.PKey, *, line_number: int = 0, comment: str = ""
    ) -> "AuthorizedPublicKey":
        return cls(
            key_type=key.get_name(),
            key_blob=key.get_base64(),
            line_number=line_number,
            comment=comment,
        )

    def matches(self, key: paramiko.PKey) -> bool:
        return self.key_type == key.get_name() and self.key_blob == key.get_base64()


class AuthorizedKeys:
    """In-memory authorized_keys matcher."""

    def __init__(self, keys: Iterable[AuthorizedPublicKey] = ()) -> None:
        self._keys = tuple(keys)

    @classmethod
    def load(cls, path: str | Path | None) -> "AuthorizedKeys":
        if path is None:
            return cls()

        resolved = Path(path).expanduser()
        if not resolved.exists():
            raise AuthorizedKeysError(f"authorized_keys file does not exist: {resolved}")
        if not resolved.is_file():
            raise AuthorizedKeysError(f"authorized_keys path is not a file: {resolved}")

        keys: list[AuthorizedPublicKey] = []
        for line_number, line in enumerate(resolved.read_text(encoding="utf-8").splitlines(), 1):
            key = parse_authorized_key_line(line, line_number=line_number)
            if key is not None:
                keys.append(key)
        return cls(keys)

    def __len__(self) -> int:
        return len(self._keys)

    @property
    def enabled(self) -> bool:
        return bool(self._keys)

    def is_authorized(self, key: paramiko.PKey) -> bool:
        return any(authorized.matches(key) for authorized in self._keys)


def parse_authorized_key_line(
    line: str, *, line_number: int = 0
) -> AuthorizedPublicKey | None:
    """Parse an OpenSSH authorized_keys line.

    The parser accepts comments, blank lines, and leading OpenSSH key options.
    Unsupported key algorithms are ignored by returning None.
    """

    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    fields = stripped.split()
    for index, field in enumerate(fields[:-1]):
        if field not in _KEY_TYPES:
            continue

        key_type = field
        key_blob = fields[index + 1]
        try:
            key_bytes = base64.b64decode(key_blob.encode("ascii"), validate=True)
            key = paramiko.PKey.from_type_string(key_type, key_bytes)
        except Exception as exc:  # Paramiko raises several key-specific errors.
            raise AuthorizedKeysError(
                f"invalid authorized_keys entry at line {line_number}: {exc}"
            ) from exc

        comment = " ".join(fields[index + 2 :])
        return AuthorizedPublicKey.from_paramiko_key(
            key, line_number=line_number, comment=comment
        )

    return None


def load_password_file(path: str | Path | None) -> str | None:
    """Load a password from a text file.

    Trailing CR/LF characters are removed so files created with echo work as
    expected. Other whitespace is preserved.
    """

    if path is None:
        return None

    resolved = Path(path).expanduser()
    if not resolved.exists():
        raise ConfigurationError(f"password file does not exist: {resolved}")
    if not resolved.is_file():
        raise ConfigurationError(f"password path is not a file: {resolved}")

    password = resolved.read_text(encoding="utf-8").rstrip("\r\n")
    if not password:
        raise ConfigurationError("password file must not be empty")
    return password


class Authenticator:
    """Public-key and password authenticator."""

    def __init__(
        self,
        *,
        authorized_keys: AuthorizedKeys | None = None,
        password: str | None = None,
        username: str | None = None,
    ) -> None:
        self.authorized_keys = authorized_keys or AuthorizedKeys()
        self.password = password
        self.username = username if username is not None else getpass.getuser()

    @property
    def publickey_enabled(self) -> bool:
        return self.authorized_keys.enabled

    @property
    def password_enabled(self) -> bool:
        return self.password is not None

    @property
    def enabled(self) -> bool:
        return self.publickey_enabled or self.password_enabled

    def allowed_auths(self) -> str:
        methods: list[str] = []
        if self.publickey_enabled:
            methods.append("publickey")
        if self.password_enabled:
            methods.append("password")
        return ",".join(methods)

    def username_allowed(self, username: str) -> bool:
        return hmac.compare_digest(username, self.username)

    def check_public_key(self, key: paramiko.PKey) -> bool:
        return self.authorized_keys.is_authorized(key)

    def check_password(self, password: str) -> bool:
        if self.password is None:
            return False
        return hmac.compare_digest(password, self.password)
