from __future__ import annotations

import logging
import socket
import threading

from simple_sshd import cli
from simple_sshd import server as server_module
from simple_sshd.server import SSHDConfig, SimpleSSHD


class FlakyListener:
    def __init__(self, sshd: SimpleSSHD) -> None:
        self.sshd = sshd
        self.calls = 0
        self.closed = False

    def getsockname(self) -> tuple[str, int]:
        return ("127.0.0.1", 2222)

    def accept(self) -> tuple[object, object]:
        self.calls += 1
        if self.calls == 1:
            raise OSError("temporary accept failure")
        self.sshd._stop.set()
        raise socket.timeout()

    def close(self) -> None:
        self.closed = True


class ClosingClient:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def make_uninitialized_server() -> SimpleSSHD:
    sshd = object.__new__(SimpleSSHD)
    sshd.config = SSHDConfig()
    sshd._socket = None
    sshd._stop = threading.Event()
    sshd._ready = threading.Event()
    sshd._serve_thread = None
    sshd._startup_error = None
    sshd._transports = set()
    sshd._transports_lock = threading.Lock()
    return sshd


def test_listener_accept_errors_are_logged_and_do_not_stop_daemon(monkeypatch, caplog):
    sshd = make_uninitialized_server()
    listener = FlakyListener(sshd)
    sshd._socket = listener  # type: ignore[assignment]
    monkeypatch.setattr(sshd, "_bind", lambda: None)
    monkeypatch.setattr(server_module, "ACCEPT_ERROR_BACKOFF_SECONDS", 0)

    with caplog.at_level(logging.ERROR, logger="simple_sshd.server"):
        assert sshd.serve_forever() == 0

    assert listener.calls == 2
    assert listener.closed
    assert "listener accept failed; continuing" in caplog.text


def test_transport_construction_errors_are_logged_and_close_client(monkeypatch, caplog):
    sshd = make_uninitialized_server()
    client = ClosingClient()

    def failing_transport(raw_client: object) -> object:
        raise RuntimeError("transport boom")

    monkeypatch.setattr(server_module.paramiko, "Transport", failing_transport)

    with caplog.at_level(logging.ERROR, logger="simple_sshd.server"):
        sshd._handle_client(client, ("127.0.0.1", 12345))  # type: ignore[arg-type]

    assert client.closed
    assert "client session failed" in caplog.text
    assert "transport boom" in caplog.text


def test_configure_logging_writes_tracebacks_to_file_not_console(tmp_path, capsys):
    log_file = tmp_path / "logs" / "simple-sshd.log"
    root_logger = logging.getLogger()
    previous_handlers = list(root_logger.handlers)
    previous_level = root_logger.level

    try:
        cli.configure_logging(logging.INFO, log_file)
        try:
            raise RuntimeError("saved runtime error")
        except RuntimeError:
            logging.getLogger("simple_sshd.test").exception("runtime failed")
        for handler in root_logger.handlers:
            handler.flush()

        log_text = log_file.read_text(encoding="utf-8")
        assert "runtime failed" in log_text
        assert "Traceback" in log_text
        assert "saved runtime error" in log_text

        console_text = capsys.readouterr().err
        assert "runtime failed" in console_text
        assert "Traceback" not in console_text
    finally:
        for handler in root_logger.handlers:
            handler.close()
        root_logger.handlers[:] = previous_handlers
        root_logger.setLevel(previous_level)
