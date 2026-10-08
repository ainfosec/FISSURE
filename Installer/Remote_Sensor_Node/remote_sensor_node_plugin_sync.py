"""Build and apply plugin updates for an installed remote sensor node."""

from pathlib import Path
from typing import Any

from remote_sensor_node_archive import (
    DirectoryArchiveError,
    create_directory_archive,
)
from remote_sensor_node_deploy_utilities import DeploymentUtilities
from remote_sensor_node_health import wait_for_sensor_node_health
from remote_sensor_node_operations import create_remote_stage, remove_remote_stage
from remote_sensor_node_privilege import RemoteEnvironment, run_root_script
from remote_sensor_node_scp import scp_with_progress


PLUGIN_ARCHIVE_NAME = "plugins.tar"


class PluginSyncError(RuntimeError):
    """Raised when plugin staging or synchronization fails."""


def create_plugin_archive(source: Path, destination: Path) -> Path:
    """Create an archive without local caches or repository metadata."""
    try:
        return create_directory_archive(source, destination)
    except DirectoryArchiveError as exc:
        raise PluginSyncError(f"Unable to prepare plugins: {exc}") from exc


async def sync_remote_plugins(
    asyncssh: Any,
    connection: Any,
    options: Any,
    archive: Path,
    environment: RemoteEnvironment,
) -> None:
    """Upload local plugins, merge them remotely, and check startup."""
    stage = await create_remote_stage(connection)
    try:
        await scp_with_progress(
            asyncssh,
            str(archive),
            (connection, f"{stage}/{PLUGIN_ARCHIVE_NAME}"),
        )
    except Exception as exc:
        await remove_remote_stage(connection, stage)
        raise PluginSyncError(f"Plugin upload failed: {exc}") from exc

    await run_root_script(
        connection,
        DeploymentUtilities.SYNC_PLUGINS_SCRIPT,
        [
            stage,
            options.remote_dir,
            options.service_name,
            environment.user,
            environment.group,
        ],
        environment.privilege,
    )
    await wait_for_sensor_node_health(
        connection,
        options,
        environment.privilege,
        require_heartbeat=False,
    )
    print("[✓] Plugins synchronized and service restarted successfully")
