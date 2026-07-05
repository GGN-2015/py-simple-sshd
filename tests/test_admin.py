from __future__ import annotations

import os
import sys
from types import SimpleNamespace

import pytest

from simple_sshd import admin
from simple_sshd import cli
from simple_sshd.errors import ConfigurationError


def test_without_root_flag_removes_only_root_flags():
    assert admin.without_root_flag(["--root", "--port", "22", "--root"]) == [
        "--port",
        "22",
    ]


def test_elevated_command_relaunches_simple_sshd_module():
    command = admin.elevated_command(["--root", "--host", "0.0.0.0"])

    assert command == [
        sys.executable,
        "-m",
        "simple_sshd",
        "--host",
        "0.0.0.0",
    ]


def test_relaunch_as_admin_uses_py_admin_launch(monkeypatch):
    calls: list[tuple[list[str], str | None, bool]] = []

    def fake_launch(command: list[str], *, cwd: str | None, wait: bool):
        calls.append((command, cwd, wait))
        return SimpleNamespace(returncode=7)

    monkeypatch.setattr(admin, "_launch", fake_launch)

    assert admin.relaunch_as_admin(["--root", "--port", "22"]) == 7
    assert calls == [
        (
            [sys.executable, "-m", "simple_sshd", "--port", "22"],
            os.getcwd(),
            True,
        )
    ]


def test_relaunch_as_admin_wraps_launch_errors(monkeypatch):
    def fake_launch(command: list[str], *, cwd: str | None, wait: bool):
        raise OSError("permission denied")

    monkeypatch.setattr(admin, "_launch", fake_launch)

    try:
        admin.relaunch_as_admin(["--root"])
    except ConfigurationError as exc:
        assert "administrator/root" in str(exc)
    else:
        raise AssertionError("ConfigurationError was not raised")


def test_cli_root_relaunches_without_starting_server(monkeypatch):
    calls: list[list[str]] = []

    def fake_relaunch(argv: list[str]) -> int:
        calls.append(argv)
        return 0

    class FailingServer:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("server should not be constructed for --root")

    monkeypatch.setattr(cli, "relaunch_as_admin", fake_relaunch)
    monkeypatch.setattr(cli, "SimpleSSHD", FailingServer)

    assert cli.main(["--root", "--host", "0.0.0.0", "--port", "22"]) == 0
    assert calls == [["--root", "--host", "0.0.0.0", "--port", "22"]]


def test_cli_parse_errors_pause_before_exit_on_windows(monkeypatch, capsys):
    sleeps: list[float] = []
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: sleeps.append(seconds))

    with pytest.raises(SystemExit) as exc:
        cli.main(["--port", "not-a-port"])

    assert exc.value.code == 2
    assert sleeps == [cli.WINDOWS_ERROR_EXIT_DELAY_SECONDS]
    assert "exiting in 5 seconds" in capsys.readouterr().err


def test_cli_parse_error_wait_handles_keyboard_interrupt(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "platform", "win32")

    def interrupted_sleep(seconds: float) -> None:
        assert seconds == cli.WINDOWS_ERROR_EXIT_DELAY_SECONDS
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.time, "sleep", interrupted_sleep)

    with pytest.raises(SystemExit) as exc:
        cli.main(["--port", "not-a-port"])

    assert exc.value.code == 130
    stderr = capsys.readouterr().err
    assert "exiting in 5 seconds" in stderr
    assert "interrupted, exiting" in stderr
    assert "Traceback" not in stderr


def test_cli_unexpected_errors_pause_before_return_on_windows(monkeypatch, capsys):
    sleeps: list[float] = []

    class FailingServer:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def serve_forever(self) -> int:
            raise RuntimeError("boom")

        def close(self) -> None:
            pass

    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: sleeps.append(seconds))
    monkeypatch.setattr(cli, "SimpleSSHD", FailingServer)

    assert cli.main(["--password-file", "unused.txt"]) == 1
    assert sleeps == [cli.WINDOWS_ERROR_EXIT_DELAY_SECONDS]
    assert "simple-sshd: boom" in capsys.readouterr().err


def test_cli_unexpected_error_wait_handles_keyboard_interrupt(monkeypatch, capsys):
    class FailingServer:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def serve_forever(self) -> int:
            raise RuntimeError("boom")

        def close(self) -> None:
            pass

    def interrupted_sleep(seconds: float) -> None:
        assert seconds == cli.WINDOWS_ERROR_EXIT_DELAY_SECONDS
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli.time, "sleep", interrupted_sleep)
    monkeypatch.setattr(cli, "SimpleSSHD", FailingServer)

    with pytest.raises(SystemExit) as exc:
        cli.main(["--password-file", "unused.txt"])

    assert exc.value.code == 130
    stderr = capsys.readouterr().err
    assert "simple-sshd: boom" in stderr
    assert "interrupted, exiting" in stderr
    assert "Traceback" not in stderr
