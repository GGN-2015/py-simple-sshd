from __future__ import annotations

import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import paramiko
import pytest

from simple_sshd.server import SSHDConfig, SimpleSSHD


def public_key_line(key: paramiko.PKey) -> str:
    return f"{key.get_name()} {key.get_base64()} integration"


def platform_shell() -> str:
    if os.name == "nt":
        return os.environ.get("COMSPEC", "cmd.exe")
    return "/bin/sh"


def platform_script() -> bytes:
    if os.name == "nt":
        return b"echo SIMPLE_SSHD_OK\r\nexit\r\n"
    return b"echo SIMPLE_SSHD_OK\nexit\n"


@contextmanager
def running_server(
    tmp_path: Path,
    *,
    authorized_key: paramiko.PKey | None = None,
    password: str | None = None,
    shell: str | None = None,
) -> Iterator[SimpleSSHD]:
    authorized_keys = None
    if authorized_key is not None:
        authorized_keys = tmp_path / "authorized_keys"
        authorized_keys.write_text(public_key_line(authorized_key), encoding="utf-8")

    password_file = None
    if password is not None:
        password_file = tmp_path / "password.txt"
        password_file.write_text(password + "\n", encoding="utf-8")

    server = SimpleSSHD(
        SSHDConfig(
            host="127.0.0.1",
            port=0,
            shell=shell or platform_shell(),
            authorized_keys=authorized_keys,
            password_file=password_file,
            host_key=tmp_path / "host_key",
        )
    )
    thread = server.start()
    try:
        yield server
    finally:
        server.close()
        thread.join(timeout=3)


def connect_client(
    server: SimpleSSHD,
    *,
    pkey: paramiko.PKey | None = None,
    password: str | None = None,
) -> paramiko.SSHClient:
    host, port = server.server_address
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username="tester",
        pkey=pkey,
        password=password,
        allow_agent=False,
        look_for_keys=False,
        timeout=5,
        banner_timeout=5,
        auth_timeout=5,
    )
    return client


def read_until(channel: paramiko.Channel, expected: bytes, timeout: float = 10) -> bytes:
    deadline = time.monotonic() + timeout
    output = b""
    while time.monotonic() < deadline:
        if channel.recv_ready():
            output += channel.recv(32768)
            if expected in output:
                return output
        if channel.exit_status_ready() and not channel.recv_ready():
            break
        time.sleep(0.05)
    return output


def read_all(channel: paramiko.Channel, timeout: float = 10) -> bytes:
    deadline = time.monotonic() + timeout
    output = b""
    while time.monotonic() < deadline:
        if channel.recv_ready():
            output += channel.recv(32768)
            continue
        if channel.exit_status_ready():
            while channel.recv_ready():
                output += channel.recv(32768)
            break
        time.sleep(0.05)
    return output


def test_public_key_login_runs_shell(tmp_path):
    client_key = paramiko.RSAKey.generate(1024)
    with running_server(tmp_path, authorized_key=client_key) as server:
        client = connect_client(server, pkey=client_key)
        try:
            channel = client.get_transport().open_session()
            channel.invoke_shell()
            channel.sendall(platform_script())

            output = read_until(channel, b"SIMPLE_SSHD_OK")

            assert b"SIMPLE_SSHD_OK" in output
        finally:
            client.close()


def test_exec_preserves_ansi_escape_sequences(tmp_path):
    client_key = paramiko.RSAKey.generate(1024)
    payload = b"\x1b[31mred\x1b[0m\x1b[1mbold\x1b[0m\x1b[2J\x1b[HESC:\x1b\n"
    command = (
        "import sys; "
        f"sys.stdout.buffer.write({payload!r}); "
        "sys.stdout.flush()"
    )
    with running_server(
        tmp_path, authorized_key=client_key, shell=sys.executable
    ) as server:
        client = connect_client(server, pkey=client_key)
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=10)

            assert stdout.read() == payload
            assert stderr.read() == b""
            assert stdout.channel.recv_exit_status() == 0
        finally:
            client.close()


def test_pty_exec_sets_term_and_preserves_ansi_sequences(tmp_path):
    if os.name == "nt":
        pytest.importorskip("winpty")

    client_key = paramiko.RSAKey.generate(1024)
    ansi = b"\x1b[32mgreen\x1b[0m\x1b[1mbold\x1b[0m\x1b[2J\x1b[H"
    command = (
        "import os, sys; "
        "sys.stdout.buffer.write(os.environ.get('TERM', '').encode() + b'\\n'); "
        f"sys.stdout.buffer.write({ansi!r}); "
        "sys.stdout.flush()"
    )
    with running_server(
        tmp_path, authorized_key=client_key, shell=sys.executable
    ) as server:
        client = connect_client(server, pkey=client_key)
        try:
            transport = client.get_transport()
            assert transport is not None
            channel = transport.open_session()
            channel.get_pty(term="xterm-256color", width=80, height=24)
            channel.exec_command(command)

            output = read_all(channel)

            assert b"xterm-256color" in output
            assert b"\x1b[32m" in output
            assert b"green" in output
            assert b"\x1b[1m" in output
            assert b"bold" in output
            assert b"\x1b[2J" in output
            assert b"\x1b[H" in output
            assert b"\x1b[0m" in output or b"\x1b[m" in output
            assert channel.recv_exit_status() == 0
        finally:
            client.close()


def test_public_key_login_runs_pty_shell(tmp_path):
    if os.name == "nt":
        pytest.importorskip("winpty")

    client_key = paramiko.RSAKey.generate(1024)
    with running_server(tmp_path, authorized_key=client_key) as server:
        client = connect_client(server, pkey=client_key)
        try:
            channel = client.get_transport().open_session()
            channel.get_pty(width=80, height=24)
            channel.invoke_shell()
            channel.sendall(platform_script())

            output = read_until(channel, b"SIMPLE_SSHD_OK")

            assert b"SIMPLE_SSHD_OK" in output
        finally:
            client.close()


def test_password_login_is_enabled_by_password_file(tmp_path):
    with running_server(tmp_path, password="s3cr3t") as server:
        client = connect_client(server, password="s3cr3t")
        client.close()


def test_wrong_password_is_rejected(tmp_path):
    with running_server(tmp_path, password="s3cr3t") as server:
        with pytest.raises(paramiko.AuthenticationException):
            connect_client(server, password="wrong")
