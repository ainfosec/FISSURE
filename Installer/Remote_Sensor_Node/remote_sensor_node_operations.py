"""Lightweight operations against an installed remote sensor-node service."""

from pathlib import Path
import shlex
from typing import Any

from remote_sensor_node_deploy_utilities import DeploymentUtilities
from remote_sensor_node_health import wait_for_sensor_node_health
from remote_sensor_node_privilege import RemoteEnvironment, run_root_script
from remote_sensor_node_scp import scp_with_progress


class RemoteOperationError(RuntimeError):
    """Raised when a lightweight remote operation cannot be completed."""


async def restart_remote_sensor_node(
    connection: Any,
    options: Any,
    environment: RemoteEnvironment,
) -> None:
    """Restart an existing service and validate startup without a heartbeat."""
    await run_root_script(
        connection,
        DeploymentUtilities.RESTART_SERVICE_SCRIPT,
        [options.remote_dir, options.service_name],
        environment.privilege,
    )
    await _check_startup(connection, options, environment)
    print("[✓] Sensor-node service restarted successfully")


async def update_remote_config(
    asyncssh: Any,
    connection: Any,
    options: Any,
    config_file: Path,
    environment: RemoteEnvironment,
) -> None:
    """Replace the active config and restart the existing sensor-node service."""
    stage = await create_remote_stage(connection)
    print(f"[*] Uploading updated configuration to {options.target.hostname}")
    try:
        await scp_with_progress(
            asyncssh,
            str(config_file),
            (connection, f"{stage}/default.yaml"),
        )
    except Exception as exc:
        await run_remote(connection, f"rm -rf -- {shlex.quote(stage)}", check=False)
        raise RemoteOperationError(f"Config upload failed: {exc}") from exc

    await run_root_script(
        connection,
        DeploymentUtilities.UPDATE_CONFIG_SCRIPT,
        [stage, options.remote_dir, options.service_name],
        environment.privilege,
    )
    await _check_startup(connection, options, environment)
    print("[✓] Configuration updated and service restarted successfully")


async def create_remote_stage(connection: Any) -> str:
    """Create and validate a narrowly scoped remote staging directory."""
    result = await run_remote(connection, "mktemp -d /tmp/fissure-node-deploy.XXXXXX")
    stage = result.stdout.strip()
    if not stage.startswith("/tmp/fissure-node-deploy."):
        raise RemoteOperationError(f"Unexpected remote staging path: {stage}")
    return stage


async def run_remote(
    connection: Any,
    command: str,
    check: bool = True,
    input_data: str | None = None,
) -> Any:
    """Run a remote command and normalize command failures."""
    result = await connection.run(command, input=input_data, check=False)
    if check and result.exit_status:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RemoteOperationError(
            f"Remote command failed ({result.exit_status}): {detail}"
        )
    return result


async def _check_startup(
    connection: Any,
    options: Any,
    environment: RemoteEnvironment,
) -> None:
    # Lightweight operations validate the service itself but do not require
    # Dashboard or HIPRFISR availability.
    await wait_for_sensor_node_health(
        connection,
        options,
        environment.privilege,
        require_heartbeat=False,
    )
