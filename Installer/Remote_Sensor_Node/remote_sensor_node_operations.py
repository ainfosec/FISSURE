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
    await _upload_remote_update(
        asyncssh=asyncssh,
        connection=connection,
        options=options,
        local_file=config_file,
        remote_name="default.yaml",
        operation_name="configuration",
        error_name="Config",
        script=DeploymentUtilities.UPDATE_CONFIG_SCRIPT,
        environment=environment,
    )
    await _check_startup(connection, options, environment)
    print("[✓] Configuration updated and service restarted successfully")


async def update_remote_image(
    asyncssh: Any,
    connection: Any,
    options: Any,
    image_file: Path,
    environment: RemoteEnvironment,
) -> None:
    """Replace the active SIF and restart the existing sensor-node service."""
    await _upload_remote_update(
        asyncssh=asyncssh,
        connection=connection,
        options=options,
        local_file=image_file,
        remote_name="fissure-sensor-node.sif",
        operation_name="SIF",
        error_name="SIF",
        script=DeploymentUtilities.UPDATE_IMAGE_SCRIPT,
        environment=environment,
    )
    await _check_startup(connection, options, environment)
    print("[✓] SIF updated and service restarted successfully")


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


async def _upload_remote_update(
    *,
    asyncssh: Any,
    connection: Any,
    options: Any,
    local_file: Path,
    remote_name: str,
    operation_name: str,
    error_name: str,
    script: str,
    environment: RemoteEnvironment,
) -> None:
    stage = await create_remote_stage(connection)
    print(f"[*] Uploading updated {operation_name} to {options.target.hostname}")
    try:
        await scp_with_progress(
            asyncssh,
            str(local_file),
            (connection, f"{stage}/{remote_name}"),
        )
    except Exception as exc:
        await run_remote(connection, f"rm -rf -- {shlex.quote(stage)}", check=False)
        raise RemoteOperationError(f"{error_name} upload failed: {exc}") from exc

    await run_root_script(
        connection,
        script,
        [stage, options.remote_dir, options.service_name],
        environment.privilege,
    )


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
