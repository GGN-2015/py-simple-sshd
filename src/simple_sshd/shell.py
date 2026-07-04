"""Shell process backends."""

from __future__ import annotations

import os
import queue
import select
import shutil
import signal
import socket
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import paramiko

from .errors import ConfigurationError


@dataclass(frozen=True)
class PtyRequest:
    term: str
    width: int
    height: int
    pixelwidth: int = 0
    pixelheight: int = 0


def default_shell() -> str:
    if os.name == "nt":
        return os.environ.get("COMSPEC") or shutil.which("cmd.exe") or "cmd.exe"
    return os.environ.get("SHELL") or "/bin/sh"


def resolve_shell(shell: str | Path | None) -> str:
    candidate = str(shell or default_shell())
    expanded = Path(candidate).expanduser()
    has_path_separator = any(
        separator and separator in candidate for separator in (os.sep, os.altsep)
    )

    if expanded.is_absolute() or has_path_separator:
        if not expanded.exists():
            raise ConfigurationError(f"shell executable does not exist: {expanded}")
        if not expanded.is_file():
            raise ConfigurationError(f"shell path is not a file: {expanded}")
        return str(expanded)

    resolved = shutil.which(candidate)
    if resolved is None:
        raise ConfigurationError(f"shell executable not found on PATH: {candidate}")
    return resolved


def run_shell_session(
    *,
    channel: paramiko.Channel,
    shell: str,
    pty: PtyRequest | None,
    resize_queue: queue.Queue[tuple[int, int]],
    environment: Mapping[str, str] | None = None,
    command: str | None = None,
) -> int:
    if command is not None:
        return _run_pipe_process(
            channel=channel,
            argv=_command_argv(shell, command),
            resize_queue=resize_queue,
            environment=environment,
        )

    if pty is not None:
        if os.name == "nt":
            return _run_windows_pty(
                channel=channel,
                shell=shell,
                pty=pty,
                resize_queue=resize_queue,
                environment=environment,
            )
        return _run_posix_pty(
            channel=channel,
            shell=shell,
            pty=pty,
            resize_queue=resize_queue,
            environment=environment,
        )

    return _run_pipe_process(
        channel=channel,
        argv=[shell],
        resize_queue=resize_queue,
        environment=environment,
    )


def _merged_environment(environment: Mapping[str, str] | None) -> dict[str, str]:
    merged = os.environ.copy()
    if environment:
        merged.update(environment)
    return merged


def _command_argv(shell: str, command: str) -> list[str]:
    name = Path(shell).name.lower()
    if os.name == "nt":
        if name in {"cmd", "cmd.exe"}:
            return [shell, "/D", "/C", command]
        if name in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
            return [shell, "-NoLogo", "-NoProfile", "-Command", command]
    return [shell, "-c", command]


def _run_pipe_process(
    *,
    channel: paramiko.Channel,
    argv: list[str],
    resize_queue: queue.Queue[tuple[int, int]],
    environment: Mapping[str, str] | None,
) -> int:
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=_merged_environment(environment),
    )

    stdout_thread = threading.Thread(
        target=_copy_process_output,
        args=(process, channel),
        name="simple-sshd-pipe-output",
        daemon=True,
    )
    stdout_thread.start()

    channel.settimeout(0.2)
    try:
        while process.poll() is None:
            _drain_resize_queue(resize_queue)
            try:
                data = channel.recv(32768)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            if process.stdin is None:
                break
            try:
                process.stdin.write(data)
                process.stdin.flush()
            except OSError:
                break
    finally:
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass

    try:
        exit_status = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            exit_status = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            exit_status = process.wait()

    stdout_thread.join(timeout=2)
    _send_exit_status(channel, exit_status)
    return exit_status


def _copy_process_output(process: subprocess.Popen[bytes], channel: paramiko.Channel) -> None:
    if process.stdout is None:
        return
    while True:
        try:
            data = process.stdout.read(32768)
        except OSError:
            return
        if not data:
            return
        if not _channel_send(channel, data):
            return


def _run_posix_pty(
    *,
    channel: paramiko.Channel,
    shell: str,
    pty: PtyRequest,
    resize_queue: queue.Queue[tuple[int, int]],
    environment: Mapping[str, str] | None,
) -> int:
    import fcntl
    import pty as posix_pty
    import struct
    import termios

    child_environment = _merged_environment(environment)

    def set_winsize(fd: int, rows: int, cols: int) -> None:
        packed = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, packed)

    pid, master_fd = posix_pty.fork()
    if pid == 0:
        os.environ.clear()
        os.environ.update(child_environment)
        os.execv(shell, [Path(shell).name])

    set_winsize(master_fd, pty.height, pty.width)
    exit_status = 0
    try:
        while True:
            _apply_posix_resizes(resize_queue, master_fd, set_winsize)
            readable, _, _ = select.select([channel, master_fd], [], [], 0.2)

            if channel in readable:
                data = channel.recv(32768)
                if not data:
                    break
                os.write(master_fd, data)

            if master_fd in readable:
                try:
                    data = os.read(master_fd, 32768)
                except OSError:
                    break
                if not data:
                    break
                if not _channel_send(channel, data):
                    break

            waited_pid, status = os.waitpid(pid, os.WNOHANG)
            if waited_pid == pid:
                exit_status = os.waitstatus_to_exitcode(status)
                break
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass
        try:
            waited_pid, status = os.waitpid(pid, os.WNOHANG)
            if waited_pid == pid:
                exit_status = os.waitstatus_to_exitcode(status)
            else:
                os.kill(pid, signal.SIGHUP)
                _, status = os.waitpid(pid, 0)
                exit_status = os.waitstatus_to_exitcode(status)
        except ChildProcessError:
            pass

    _send_exit_status(channel, exit_status)
    return exit_status


def _apply_posix_resizes(
    resize_queue: queue.Queue[tuple[int, int]],
    master_fd: int,
    set_winsize: object,
) -> None:
    while True:
        try:
            rows, cols = resize_queue.get_nowait()
        except queue.Empty:
            return
        try:
            set_winsize(master_fd, rows, cols)  # type: ignore[misc]
        except OSError:
            return


def _run_windows_pty(
    *,
    channel: paramiko.Channel,
    shell: str,
    pty: PtyRequest,
    resize_queue: queue.Queue[tuple[int, int]],
    environment: Mapping[str, str] | None,
) -> int:
    try:
        from winpty import PtyProcess
    except ImportError as exc:
        raise ConfigurationError(
            "PTY shell sessions on Windows require pywinpty to be installed"
        ) from exc

    process = PtyProcess.spawn(
        shell,
        env=_merged_environment(environment),
        dimensions=(pty.height, pty.width),
    )

    reader = threading.Thread(
        target=_copy_winpty_output,
        args=(process, channel),
        name="simple-sshd-winpty-output",
        daemon=True,
    )
    reader.start()

    channel.settimeout(0.2)
    try:
        while _winpty_is_alive(process):
            _apply_winpty_resizes(process, resize_queue)
            try:
                data = channel.recv(32768)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            _winpty_write(process, data)
    finally:
        try:
            process.close()
        except Exception:
            pass

    reader.join(timeout=2)
    exit_status = int(getattr(process, "exitstatus", 0) or 0)
    _send_exit_status(channel, exit_status)
    return exit_status


def _copy_winpty_output(process: object, channel: paramiko.Channel) -> None:
    while _winpty_is_alive(process):
        try:
            data = process.read(32768)  # type: ignore[attr-defined]
        except Exception:
            return
        if not data:
            continue
        if isinstance(data, str):
            payload = data.encode(_console_encoding(), errors="replace")
        else:
            payload = bytes(data)
        if not _channel_send(channel, payload):
            return


def _winpty_write(process: object, data: bytes) -> None:
    text = data.decode(_console_encoding(), errors="replace")
    process.write(text)  # type: ignore[attr-defined]


def _winpty_is_alive(process: object) -> bool:
    isalive = getattr(process, "isalive", None)
    if callable(isalive):
        return bool(isalive())
    return True


def _apply_winpty_resizes(
    process: object, resize_queue: queue.Queue[tuple[int, int]]
) -> None:
    while True:
        try:
            rows, cols = resize_queue.get_nowait()
        except queue.Empty:
            return
        for method_name, args in (
            ("set_size", (cols, rows)),
            ("setwinsize", (rows, cols)),
        ):
            method = getattr(process, method_name, None)
            if callable(method):
                method(*args)
                break


def _drain_resize_queue(resize_queue: queue.Queue[tuple[int, int]]) -> None:
    while True:
        try:
            resize_queue.get_nowait()
        except queue.Empty:
            return


def _channel_send(channel: paramiko.Channel, data: bytes) -> bool:
    try:
        channel.sendall(data)
        return True
    except OSError:
        return False


def _send_exit_status(channel: paramiko.Channel, status: int) -> None:
    try:
        channel.send_exit_status(status)
    except OSError:
        pass


def _console_encoding() -> str:
    return sys.getdefaultencoding() or "utf-8"
