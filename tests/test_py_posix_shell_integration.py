from __future__ import annotations

import os
import shutil
import socket
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import paramiko
import pytest

from simple_sshd.server import SSHDConfig, SimpleSSHD


MARKER = b"SIMPLE_POSIX_SHELL_OK"


@dataclass(frozen=True)
class RunningServer:
    server: SimpleSSHD
    client_key: paramiko.PKey


def py_posix_shell_executable() -> str:
    shell = shutil.which("py-posix-shell") or shutil.which("pysh")
    if shell is None:
        pytest.skip("py-posix-shell executable is not installed")
    return shell


def public_key_line(key: paramiko.PKey) -> str:
    return f"{key.get_name()} {key.get_base64()} py-posix-shell"


@contextmanager
def running_py_posix_shell_server(tmp_path: Path) -> Iterator[RunningServer]:
    key = paramiko.RSAKey.generate(1024)
    authorized_keys = tmp_path / "authorized_keys"
    authorized_keys.write_text(public_key_line(key), encoding="utf-8")

    server = SimpleSSHD(
        SSHDConfig(
            host="127.0.0.1",
            port=0,
            shell=py_posix_shell_executable(),
            authorized_keys=authorized_keys,
            host_key=tmp_path / "host_key",
        )
    )
    thread = server.start()
    try:
        yield RunningServer(server=server, client_key=key)
    finally:
        server.close()
        thread.join(timeout=3)


def connect_client(running: RunningServer) -> paramiko.SSHClient:
    host, port = running.server.server_address
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username="tester",
        pkey=running.client_key,
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


def read_until_closed(channel: paramiko.Channel, timeout: float = 10) -> bytes:
    deadline = time.monotonic() + timeout
    output = b""
    channel.settimeout(0.5)
    while time.monotonic() < deadline:
        try:
            data = channel.recv(32768)
        except socket.timeout:
            if channel.exit_status_ready():
                break
            continue
        if not data:
            break
        output += data
    return output


def test_py_posix_shell_runs_exec_commands(tmp_path):
    with running_py_posix_shell_server(tmp_path) as running:
        client = connect_client(running)
        try:
            stdin, stdout, stderr = client.exec_command(
                "echo SIMPLE_POSIX_SHELL_OK", timeout=10
            )

            assert MARKER in stdout.read()
            assert stderr.read() == b""
            assert stdout.channel.recv_exit_status() == 0
        finally:
            client.close()


def test_py_posix_shell_runs_no_pty_shell(tmp_path):
    with running_py_posix_shell_server(tmp_path) as running:
        client = connect_client(running)
        try:
            transport = client.get_transport()
            assert transport is not None
            channel = transport.open_session()
            channel.invoke_shell()
            channel.sendall(b"echo SIMPLE_POSIX_SHELL_OK\nexit\n")
            channel.shutdown_write()

            output = read_until_closed(channel)

            assert MARKER in output
            assert channel.recv_exit_status() == 0
        finally:
            client.close()


def test_py_posix_shell_runs_interactive_pty_shell(tmp_path):
    if os.name == "nt":
        pytest.importorskip("winpty")

    line_end = b"\r\n" if os.name == "nt" else b"\n"
    with running_py_posix_shell_server(tmp_path) as running:
        client = connect_client(running)
        try:
            transport = client.get_transport()
            assert transport is not None
            channel = transport.open_session()
            channel.get_pty(width=80, height=24)
            channel.invoke_shell()
            channel.sendall(b"echo SIMPLE_POSIX_SHELL_OK" + line_end + b"exit" + line_end)

            output = read_until(channel, MARKER)

            assert MARKER in output
        finally:
            client.close()
