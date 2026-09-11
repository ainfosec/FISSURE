"""Prepare and apply FISSURE source updates to a remote Sensor Node."""

from pathlib import Path, PurePosixPath
from typing import Any

from remote_sensor_node_archive import (
    DirectoryArchiveError,
    create_directory_archive,
)
from remote_sensor_node_deploy_utilities import DeploymentUtilities
from remote_sensor_node_health import wait_for_sensor_node_health
from remote_sensor_node_operations import create_remote_stage, remove_remote_stage
from remote_sensor_node_options import DeployOptions
from remote_sensor_node_privilege import RemoteEnvironment, run_root_script
from remote_sensor_node_scp import scp_with_progress


SOURCE_ARCHIVE_NAME = "source.tar"
SOURCE_PATH_EXCLUSIONS = frozenset(
    {
        PurePosixPath("Sensor_Node/Archive_Replay"),
        PurePosixPath("Sensor_Node/Autorun_Playlists"),
        PurePosixPath("Sensor_Node/IQ_Data_Playback"),
        PurePosixPath("Sensor_Node/Import_Export_Files"),
        PurePosixPath("Sensor_Node/Recordings"),
    }
)


class SourceSyncError(RuntimeError):
    """Raised when source staging or synchronization fails."""


def create_source_archive(source: Path, destination: Path) -> Path:
    """Archive source code without mutable state, secrets, or local caches."""
    try:
        return create_directory_archive(
            source / "fissure",
            destination,
            ignored_paths=SOURCE_PATH_EXCLUSIONS,
            allow_links=False,
        )
    except DirectoryArchiveError as exc:
        raise SourceSyncError(f"Unable to prepare source: {exc}") from exc


async def sync_remote_source(
    asyncssh: Any,
    connection: Any,
    options: DeployOptions,
    archive: Path,
    service_unit: Path,
    environment: RemoteEnvironment,
) -> None:
    """Upload source, enable its host bind, and check service startup."""
    stage = await create_remote_stage(connection)
    try:
        for local_file, remote_name in (
            (archive, SOURCE_ARCHIVE_NAME),
            (service_unit, f"{options.service_name}.service"),
        ):
            await scp_with_progress(
                asyncssh,
                str(local_file),
                (connection, f"{stage}/{remote_name}"),
            )
    except Exception as exc:
        await remove_remote_stage(connection, stage)
        raise SourceSyncError(f"Source upload failed: {exc}") from exc

    await run_root_script(
        connection,
        DeploymentUtilities.SYNC_SOURCE_SCRIPT,
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
    print("[✓] Source synchronized and service restarted successfully")
