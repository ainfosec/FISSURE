"""Remove a remote FISSURE Sensor Node deployment without removing Apptainer."""

from typing import Any

from remote_sensor_node_deploy_utilities import DeploymentUtilities
from remote_sensor_node_privilege import (
    prepare_uninstall_privilege,
    run_root_script,
)


async def uninstall_remote(
    connection: Any,
    destination: str,
    remote_dir: str,
    service_name: str,
) -> None:
    privilege = await prepare_uninstall_privilege(connection, destination)
    await run_root_script(
        connection,
        DeploymentUtilities.UNINSTALL_SCRIPT,
        [remote_dir, service_name],
        privilege,
    )
    print(f"[✓] Removed {service_name}.service and {remote_dir}")
