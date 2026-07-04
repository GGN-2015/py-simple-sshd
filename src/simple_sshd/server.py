"""Paramiko SSH server implementation."""

from __future__ import annotations

import logging
import queue
import socket
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

import paramiko

from .auth import Authenticator, AuthorizedKeys, load_password_file
from .errors import ConfigurationError
from .hostkey import load_or_create_host_key
from .shell import PtyRequest, resolve_shell, run_shell_session

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class SSHDConfig:
    host: str = "127.0.0.1"
    port: int = 2222
    shell: str | Path | None = None
    authorized_keys: str | Path | None = None
    password_file: str | Path | None = None
    host_key: str | Path | None = None
    backlog: int = 100
    banner: str = "simple-sshd"


@dataclass
class ChannelState:
    event: threading.Event = field(default_factory=threading.Event)
    pty: PtyRequest | None = None
    request: "SessionRequest | None" = None
    environment: dict[str, str] = field(default_factory=dict)
    resize_queue: queue.Queue[tuple[int, int]] = field(default_factory=queue.Queue)


@dataclass(frozen=True)
class SessionRequest:
    kind: str
    command: str | None = None


class SimpleServerInterface(paramiko.ServerInterface):
    def __init__(self, authenticator: Authenticator, banner: str) -> None:
        self._authenticator = authenticator
        self._banner = banner
        self._lock = threading.Lock()
        self._channels: dict[int, ChannelState] = {}

    def get_banner(self) -> tuple[str, str]:
        return (self._banner, "en-US")

    def get_allowed_auths(self, username: str) -> str:
        return self._authenticator.allowed_auths()

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        if self._authenticator.check_public_key(key):
            LOG.info("accepted public key for user %s", username)
            return paramiko.AUTH_SUCCESSFUL
        LOG.warning("rejected public key for user %s", username)
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username: str, password: str) -> int:
        if self._authenticator.check_password(password):
            LOG.info("accepted password for user %s", username)
            return paramiko.AUTH_SUCCESSFUL
        LOG.warning("rejected password for user %s", username)
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind != "session":
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        self._state(chanid)
        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        state = self._state(channel.get_id())
        state.pty = PtyRequest(
            term=term.decode("utf-8", errors="replace"),
            width=width,
            height=height,
            pixelwidth=pixelwidth,
            pixelheight=pixelheight,
        )
        return True

    def check_channel_env_request(
        self, channel: paramiko.Channel, name: bytes, value: bytes
    ) -> bool:
        state = self._state(channel.get_id())
        decoded_name = name.decode("utf-8", errors="replace")
        decoded_value = value.decode("utf-8", errors="replace")
        state.environment[decoded_name] = decoded_value
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        state = self._state(channel.get_id())
        state.request = SessionRequest(kind="shell")
        state.event.set()
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        state = self._state(channel.get_id())
        state.request = SessionRequest(
            kind="exec",
            command=command.decode("utf-8", errors="replace"),
        )
        state.event.set()
        return True

    def check_channel_window_change_request(
        self,
        channel: paramiko.Channel,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
    ) -> bool:
        state = self._state(channel.get_id())
        state.resize_queue.put((height, width))
        return True

    def wait_for_request(
        self, channel: paramiko.Channel, timeout: float
    ) -> (
        tuple[
            SessionRequest,
            PtyRequest | None,
            Mapping[str, str],
            queue.Queue[tuple[int, int]],
        ]
        | None
    ):
        state = self._state(channel.get_id())
        if not state.event.wait(timeout):
            return None
        if state.request is None:
            return None
        return state.request, state.pty, state.environment, state.resize_queue

    def cleanup_channel(self, channel: paramiko.Channel) -> None:
        with self._lock:
            self._channels.pop(channel.get_id(), None)

    def _state(self, chanid: int) -> ChannelState:
        with self._lock:
            state = self._channels.get(chanid)
            if state is None:
                state = ChannelState()
                self._channels[chanid] = state
            return state


class SimpleSSHD:
    """A thread-per-connection SSH daemon."""

    def __init__(self, config: SSHDConfig) -> None:
        self.config = config
        self._socket: socket.socket | None = None
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._serve_thread: threading.Thread | None = None
        self._startup_error: BaseException | None = None
        self._transports: set[paramiko.Transport] = set()
        self._transports_lock = threading.Lock()

        self.shell = resolve_shell(config.shell)
        self.host_key = load_or_create_host_key(config.host_key)
        self.authenticator = Authenticator(
            authorized_keys=AuthorizedKeys.load(config.authorized_keys),
            password=load_password_file(config.password_file),
        )
        if not self.authenticator.enabled:
            raise ConfigurationError(
                "no authentication method configured; provide authorized_keys, password_file, or both"
            )

    @property
    def server_address(self) -> tuple[str, int]:
        if self._socket is None:
            return (self.config.host, self.config.port)
        host, port = self._socket.getsockname()[:2]
        return (str(host), int(port))

    def start(self) -> threading.Thread:
        if self._serve_thread is not None:
            return self._serve_thread
        self._serve_thread = threading.Thread(
            target=self.serve_forever,
            name="simple-sshd-listener",
            daemon=True,
        )
        self._serve_thread.start()
        if not self._ready.wait(timeout=10):
            raise TimeoutError("simple-sshd did not finish startup within 10 seconds")
        if self._startup_error is not None:
            raise self._startup_error
        return self._serve_thread

    def serve_forever(self) -> int:
        try:
            self._bind()
        except BaseException as exc:
            self._startup_error = exc
            self._ready.set()
            raise
        self._ready.set()
        LOG.info("listening on %s:%s", *self.server_address)

        assert self._socket is not None
        while not self._stop.is_set():
            try:
                client, address = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(
                target=self._handle_client,
                args=(client, address),
                name=f"simple-sshd-client-{address[0]}:{address[1]}",
                daemon=True,
            )
            thread.start()
        self.close()
        return 0

    def close(self) -> None:
        self._stop.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass

        with self._transports_lock:
            transports = list(self._transports)
            self._transports.clear()
        for transport in transports:
            transport.close()

    def _bind(self) -> None:
        if self._socket is not None:
            return

        last_error: OSError | None = None
        for family, socktype, proto, _, sockaddr in socket.getaddrinfo(
            self.config.host,
            self.config.port,
            type=socket.SOCK_STREAM,
            flags=socket.AI_PASSIVE,
        ):
            sock = socket.socket(family, socktype, proto)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(sockaddr)
                sock.listen(self.config.backlog)
                sock.settimeout(0.5)
                self._socket = sock
                return
            except OSError as exc:
                last_error = exc
                sock.close()
        if last_error is not None:
            raise last_error
        raise ConfigurationError("unable to resolve bind address")

    def _handle_client(self, client: socket.socket, address: object) -> None:
        transport = paramiko.Transport(client)
        transport.local_version = "SSH-2.0-simple-sshd"
        transport.add_server_key(self.host_key)
        server = SimpleServerInterface(self.authenticator, self.config.banner)

        with self._transports_lock:
            self._transports.add(transport)
        try:
            transport.start_server(server=server)
            while transport.is_active() and not self._stop.is_set():
                channel = transport.accept(timeout=1)
                if channel is None:
                    continue
                thread = threading.Thread(
                    target=self._handle_channel,
                    args=(server, channel),
                    name=f"simple-sshd-channel-{channel.get_id()}",
                    daemon=True,
                )
                thread.start()
        except Exception:
            LOG.exception("client session failed for %s", address)
        finally:
            transport.close()
            with self._transports_lock:
                self._transports.discard(transport)

    def _handle_channel(
        self, server: SimpleServerInterface, channel: paramiko.Channel
    ) -> None:
        try:
            request = server.wait_for_request(channel, timeout=30)
            if request is None:
                channel.close()
                return
            session_request, pty, environment, resize_queue = request
            run_shell_session(
                channel=channel,
                shell=self.shell,
                pty=pty,
                resize_queue=resize_queue,
                environment=environment,
                command=session_request.command,
            )
        except Exception:
            LOG.exception("channel failed")
            try:
                channel.send_exit_status(1)
            except OSError:
                pass
        finally:
            server.cleanup_channel(channel)
            channel.close()


def serve_forever(config: SSHDConfig) -> int:
    return SimpleSSHD(config).serve_forever()
