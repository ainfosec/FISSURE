"""Secure privilege acquisition and remote prerequisite bootstrap."""

from dataclasses import dataclass, field
import getpass
import shlex
from typing import Any
import warnings

from remote_sensor_node_deploy_utilities import DeploymentUtilities


class PrivilegeError(RuntimeError):
    """Raised when remote privilege or prerequisite setup fails."""


@dataclass(frozen=True)
class PrivilegeContext:
    """Credentials needed to execute remote commands as root."""

    mode: str
    password: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class RemoteEnvironment:
    """Validated remote account and runtime paths."""

    user: str
    group: str
    apptainer: str
    privilege: PrivilegeContext


async def prepare_remote_environment(
    connection: Any,
    destination: str,
    install_apptainer: bool,
) -> RemoteEnvironment:
    """Validate privilege and install Apptainer when allowed and necessary."""
    result = await _run(connection, DeploymentUtilities.PREFLIGHT_SCRIPT)
    user, group, apptainer, mode = _parse_preflight(result.stdout)
    privilege = await _acquire_privilege(connection, destination, mode)

    if not apptainer:
        if not install_apptainer:
            raise PrivilegeError("Apptainer is not installed on the remote host")
        print("[*] Apptainer is missing; installing it from the official PPA")
        await run_root_script(
            connection,
            DeploymentUtilities.INSTALL_APPTAINER_SCRIPT,
            [],
            privilege,
        )
        apptainer = (
            await _run(connection, "command -v apptainer")
        ).stdout.strip()
        if not apptainer:
            raise PrivilegeError("Apptainer installation did not provide a binary")

    print(f"[✓] Remote prerequisites passed ({user}, {apptainer})")
    return RemoteEnvironment(user, group, apptainer, privilege)


async def prepare_uninstall_privilege(
    connection: Any,
    destination: str,
) -> PrivilegeContext:
    """Acquire only the privilege needed to remove a deployment."""
    result = await _run(connection, DeploymentUtilities.UNINSTALL_PREFLIGHT_SCRIPT)
    mode = result.stdout.strip()
    if mode not in {"root", "passwordless", "password"}:
        raise PrivilegeError("Unable to read remote privilege information")
    return await _acquire_privilege(connection, destination, mode)


async def run_root_command(
    connection: Any,
    args: list[str],
    privilege: PrivilegeContext,
    check: bool = True,
) -> Any:
    """Execute one argument-safe command with remote root privilege."""
    command = shlex.join(
        [
            "bash",
            "-c",
            'exec </dev/null; exec "$@"',
            "fissure-root-command",
            *args,
        ]
    )
    return await _run_as_root(
        connection,
        command,
        privilege,
        check,
    )


async def run_root_script(
    connection: Any,
    script: str,
    args: list[str],
    privilege: PrivilegeContext,
    check: bool = True,
) -> Any:
    """Execute a static script as root without placing credentials in arguments."""
    secured_script = "exec </dev/null\n" + script
    command = shlex.join(
        ["bash", "-c", secured_script, "fissure-deploy", *args]
    )
    return await _run_as_root(connection, command, privilege, check)


async def _acquire_privilege(
    connection: Any,
    destination: str,
    mode: str,
) -> PrivilegeContext:
    if mode == "root":
        return PrivilegeContext(mode)
    if mode == "passwordless":
        return PrivilegeContext(mode)
    if mode != "password":
        raise PrivilegeError(f"Unsupported remote privilege mode: {mode!r}")

    # Privilege is acquired before concurrent deployment work begins.
    password = _prompt_sudo_password(destination)
    privilege = PrivilegeContext(mode, password)
    try:
        await run_root_command(connection, ["true"], privilege)
    except PrivilegeError as exc:
        raise PrivilegeError("Remote sudo authentication failed") from exc
    return privilege


def _prompt_sudo_password(destination: str) -> str:
    try:
        # Refuse getpass's echoed-input fallback to avoid exposing credentials.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass(f"Sudo password for {destination}: ")
    except (EOFError, OSError, getpass.GetPassWarning) as exc:
        raise PrivilegeError("Unable to read the sudo password securely") from exc
    if not password:
        raise PrivilegeError("Sudo password cannot be empty")
    return password


async def _run_as_root(
    connection: Any,
    command: str,
    privilege: PrivilegeContext,
    check: bool,
) -> Any:
    input_data = None
    if privilege.mode == "root":
        privileged_command = command
    elif privilege.password is None:
        privileged_command = f"sudo -n -- {command}"
    else:
        # Invalidate cached credentials so sudo always consumes password stdin.
        privileged_command = f"sudo -k -S -p '' -- {command}"
        input_data = privilege.password + "\n"
    return await _run(connection, privileged_command, check, input_data)


async def _run(
    connection: Any,
    command: str,
    check: bool = True,
    input_data: str | None = None,
) -> Any:
    result = await connection.run(command, input=input_data, check=False)
    if check and result.exit_status:
        detail = result.stderr.strip() or result.stdout.strip()
        raise PrivilegeError(
            f"Remote command failed ({result.exit_status}): {detail}"
        )
    return result


def _parse_preflight(stdout: str) -> tuple[str, str, str, str]:
    try:
        user, group, apptainer, mode = stdout.strip().split("|", 3)
    except ValueError as exc:
        raise PrivilegeError("Unable to read remote account information") from exc
    return user, group, apptainer, mode
