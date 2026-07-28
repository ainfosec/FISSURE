"""Validate that the local FISSURE Dashboard is running before deployment."""

from pathlib import Path


DEFAULT_GUI_LOCK = Path("/tmp/fissure.lock")
DEFAULT_PROC_ROOT = Path("/proc")


class LocalFissureError(RuntimeError):
    """Raised when a full deployment has no running local Dashboard."""


def require_local_fissure_gui(
    lock_file: Path = DEFAULT_GUI_LOCK,
    proc_root: Path = DEFAULT_PROC_ROOT,
) -> int:
    """Return the Dashboard PID or fail on a missing, stale, or spoofed lock."""
    pid = _read_gui_pid(lock_file)
    command = _read_process_command(proc_root, pid)
    if not _is_dashboard_command(command):
        raise _not_running_error(
            f"lock PID {pid} is not a FISSURE Dashboard process"
        )
    print(f"[✓] Local FISSURE GUI is running (pid={pid})")
    return pid


def _read_gui_pid(lock_file: Path) -> int:
    try:
        value = lock_file.read_text().strip()
    except FileNotFoundError as exc:
        raise _not_running_error(f"{lock_file} does not exist") from exc
    except OSError as exc:
        raise _not_running_error(f"cannot read {lock_file}: {exc}") from exc

    if not value.isdecimal() or int(value) <= 0:
        raise _not_running_error(f"{lock_file} contains an invalid PID")
    return int(value)


def _read_process_command(proc_root: Path, pid: int) -> tuple[str, ...]:
    command_file = proc_root / str(pid) / "cmdline"
    try:
        raw_command = command_file.read_bytes()
    except FileNotFoundError as exc:
        raise _not_running_error(f"lock PID {pid} is not running") from exc
    except OSError as exc:
        raise _not_running_error(f"cannot inspect lock PID {pid}: {exc}") from exc

    arguments = tuple(
        argument.decode(errors="replace")
        for argument in raw_command.split(b"\0")
        if argument
    )
    if not arguments:
        raise _not_running_error(f"lock PID {pid} has no active command")
    return arguments


def _is_dashboard_command(arguments: tuple[str, ...]) -> bool:
    for index, argument in enumerate(arguments):
        normalized = argument.replace("\\", "/")
        if normalized.endswith("fissure/Dashboard/__main__.py"):
            return True
        if (
            argument == "-m"
            and index + 1 < len(arguments)
            and arguments[index + 1] in {"fissure.Dashboard", "fissure.Dashboard.__main__"}
        ):
            return True
    return False


def _not_running_error(detail: str) -> LocalFissureError:
    return LocalFissureError(
        "FISSURE GUI is not running. Start it before deploying a remote "
        f"Sensor Node ({detail})."
    )
