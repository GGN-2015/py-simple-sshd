"""Administrator/root relaunch support."""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from typing import Protocol

from .errors import ConfigurationError


class LaunchResultLike(Protocol):
    returncode: int | None


def without_root_flag(argv: Sequence[str]) -> list[str]:
    """Return argv with simple-sshd's --root flag removed."""

    return [argument for argument in argv if argument != "--root"]


def elevated_command(argv: Sequence[str]) -> list[str]:
    """Build the command used for the elevated simple-sshd process."""

    return [sys.executable, "-m", "simple_sshd", *without_root_flag(argv)]


def relaunch_as_admin(argv: Sequence[str]) -> int:
    """Relaunch simple-sshd with administrator/root privileges.

    The child command deliberately omits --root so an already elevated process
    starts the daemon instead of recursively relaunching itself.
    """

    try:
        result = _launch(elevated_command(argv), cwd=os.getcwd(), wait=True)
    except (ImportError, OSError, ValueError) as exc:
        raise ConfigurationError(
            f"failed to relaunch with administrator/root privileges: {exc}"
        ) from exc
    if result.returncode is None:
        return 0
    return int(result.returncode)


def _launch(command: Sequence[str], *, cwd: str, wait: bool) -> LaunchResultLike:
    try:
        from py_admin_launch import AdminLaunchError as PyAdminLaunchError
        from py_admin_launch import launch
    except ImportError as exc:
        raise ImportError("py-admin-launch is required for --root") from exc

    try:
        return launch(command, cwd=cwd, wait=wait)
    except PyAdminLaunchError as exc:
        raise ValueError(str(exc)) from exc
