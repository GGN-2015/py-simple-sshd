from __future__ import annotations

import pytest
import paramiko

from simple_sshd.auth import (
    Authenticator,
    AuthorizedKeys,
    load_password_file,
    parse_authorized_key_line,
)
from simple_sshd.errors import ConfigurationError


def public_key_line(key: paramiko.PKey, comment: str = "tester") -> str:
    return f"{key.get_name()} {key.get_base64()} {comment}"


def test_authorized_keys_accepts_key_with_options(tmp_path):
    key = paramiko.RSAKey.generate(1024)
    path = tmp_path / "authorized_keys"
    path.write_text(
        f'# comment\ncommand="echo hello world",no-pty {public_key_line(key)}\n',
        encoding="utf-8",
    )

    authorized_keys = AuthorizedKeys.load(path)

    assert len(authorized_keys) == 1
    assert authorized_keys.is_authorized(key)


def test_authorized_keys_rejects_unknown_key(tmp_path):
    allowed = paramiko.RSAKey.generate(1024)
    other = paramiko.RSAKey.generate(1024)
    path = tmp_path / "authorized_keys"
    path.write_text(public_key_line(allowed), encoding="utf-8")

    authorized_keys = AuthorizedKeys.load(path)

    assert not authorized_keys.is_authorized(other)


def test_parse_authorized_key_line_ignores_comments_and_unknown_algorithms():
    assert parse_authorized_key_line("# hello") is None
    assert parse_authorized_key_line("") is None
    assert parse_authorized_key_line("ssh-unknown AAAA comment") is None


def test_password_file_trims_line_endings_but_preserves_other_whitespace(tmp_path):
    path = tmp_path / "password.txt"
    path.write_text("  secret  \r\n", encoding="utf-8")

    assert load_password_file(path) == "  secret  "


def test_empty_password_file_is_rejected(tmp_path):
    path = tmp_path / "password.txt"
    path.write_text("\n", encoding="utf-8")

    with pytest.raises(ConfigurationError):
        load_password_file(path)


def test_authenticator_combines_public_key_and_password(tmp_path):
    key = paramiko.RSAKey.generate(1024)
    path = tmp_path / "authorized_keys"
    path.write_text(public_key_line(key), encoding="utf-8")
    authenticator = Authenticator(
        authorized_keys=AuthorizedKeys.load(path),
        password="s3cr3t",
    )

    assert authenticator.allowed_auths() == "publickey,password"
    assert authenticator.check_public_key(key)
    assert authenticator.check_password("s3cr3t")
    assert not authenticator.check_password("wrong")
