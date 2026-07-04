"""Command-line entry point."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
from pathlib import Path

from .admin import relaunch_as_admin
from .errors import SimpleSSHDError
from .server import SSHDConfig, SimpleSSHD
from .shell import default_shell


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="simple-sshd",
        description="Run a small Paramiko-based SSH daemon.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host/address to bind.")
    parser.add_argument("--port", type=int, default=2222, help="TCP port to bind.")
    parser.add_argument(
        "--shell",
        default=default_shell(),
        help="Shell executable path to launch for authenticated sessions.",
    )
    parser.add_argument(
        "--authorized-keys",
        type=Path,
        help="OpenSSH authorized_keys file used for public-key authentication.",
    )
    parser.add_argument(
        "--password-file",
        type=Path,
        help="Text file whose content is used as an accepted SSH password.",
    )
    parser.add_argument(
        "--host-key",
        type=Path,
        help="Private host key file. Created automatically when omitted.",
    )
    parser.add_argument(
        "--root",
        action="store_true",
        help="Relaunch simple-sshd with administrator/root privileges.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        help="Logging verbosity.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(raw_argv)

    if args.root:
        try:
            return relaunch_as_admin(raw_argv)
        except SimpleSSHDError as exc:
            parser.error(str(exc))

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config = SSHDConfig(
        host=args.host,
        port=args.port,
        shell=args.shell,
        authorized_keys=args.authorized_keys,
        password_file=args.password_file,
        host_key=args.host_key,
    )

    try:
        server = SimpleSSHD(config)
    except SimpleSSHDError as exc:
        parser.error(str(exc))

    def stop(signum: int, frame: object) -> None:
        logging.getLogger(__name__).info("received signal %s, shutting down", signum)
        server.close()

    for signal_name in ("SIGINT", "SIGTERM"):
        signum = getattr(signal, signal_name, None)
        if signum is not None:
            signal.signal(signum, stop)

    try:
        return server.serve_forever()
    except KeyboardInterrupt:
        server.close()
        return 130
    except Exception as exc:
        print(f"simple-sshd: {exc}", file=sys.stderr)
        return 1
