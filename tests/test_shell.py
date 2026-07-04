from __future__ import annotations

import queue
import sys
from types import SimpleNamespace

from simple_sshd import shell
from simple_sshd.shell import PtyRequest


class FakeChannel:
    def __init__(self) -> None:
        self.exit_status: int | None = None
        self.timeout: float | None = None
        self._reads = 0

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def recv(self, size: int) -> bytes:
        self._reads += 1
        if self._reads == 1:
            return b"echo hello\r\n"
        return b""

    def sendall(self, data: bytes) -> None:
        pass

    def send_exit_status(self, status: int) -> None:
        self.exit_status = status


class ClosingPtyProcess:
    spawned: "ClosingPtyProcess | None" = None

    def __init__(self) -> None:
        self.closed = False
        self.exitstatus = 0
        self.write_calls = 0

    @classmethod
    def spawn(cls, *args: object, **kwargs: object) -> "ClosingPtyProcess":
        cls.spawned = cls()
        return cls.spawned

    def isalive(self) -> bool:
        return not self.closed

    def read(self, size: int) -> str:
        raise EOFError("Pty is closed")

    def write(self, text: str) -> None:
        self.write_calls += 1
        raise EOFError("Pty is closed")

    def close(self) -> None:
        self.closed = True


def test_windows_pty_write_eof_closes_process_and_returns_status(monkeypatch):
    fake_winpty = SimpleNamespace(PtyProcess=ClosingPtyProcess)
    monkeypatch.setitem(sys.modules, "winpty", fake_winpty)

    channel = FakeChannel()
    status = shell._run_windows_pty(
        channel=channel,  # type: ignore[arg-type]
        shell="cmd.exe",
        pty=PtyRequest(term="xterm", width=80, height=24),
        resize_queue=queue.Queue(),
        environment=None,
    )

    assert status == 0
    assert channel.exit_status == 0
    assert ClosingPtyProcess.spawned is not None
    assert ClosingPtyProcess.spawned.closed
    assert ClosingPtyProcess.spawned.write_calls == 1
