"""Host key loading and creation."""

from __future__ import annotations

import os
from pathlib import Path

import paramiko

from .errors import ConfigurationError


def default_host_key_path() -> Path:
    return Path.home() / ".simple-sshd" / "ssh_host_rsa_key"


def load_or_create_host_key(path: str | Path | None = None) -> paramiko.PKey:
    resolved = Path(path).expanduser() if path is not None else default_host_key_path()
    if resolved.exists():
        return load_host_key(resolved)

    resolved.parent.mkdir(parents=True, exist_ok=True)
    key = paramiko.RSAKey.generate(bits=3072)
    key.write_private_key_file(str(resolved))
    if os.name != "nt":
        os.chmod(resolved, 0o600)
    return key


def load_host_key(path: str | Path) -> paramiko.PKey:
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        raise ConfigurationError(f"host key path is not a file: {resolved}")

    key_classes = (
        paramiko.RSAKey,
        getattr(paramiko, "ECDSAKey", None),
        getattr(paramiko, "Ed25519Key", None),
    )
    errors: list[str] = []
    for key_class in key_classes:
        if key_class is None:
            continue
        try:
            return key_class.from_private_key_file(str(resolved))
        except Exception as exc:
            errors.append(f"{key_class.__name__}: {exc}")

    detail = "; ".join(errors)
    raise ConfigurationError(f"unable to load host key {resolved}: {detail}")
