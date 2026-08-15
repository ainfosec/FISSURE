"""Build and apply plugin updates for an installed remote sensor node."""

from pathlib import Path, PurePosixPath
import shlex
import tarfile
from typing import Any

from remote_sensor_node_deploy_utilities import DeploymentUtilities
from remote_sensor_node_health import wait_for_sensor_node_health
from remote_sensor_node_operations import create_remote_stage, run_remote
from remote_sensor_node_privilege import RemoteEnvironment, run_root_script
from remote_sensor_node_scp import scp_with_progress


PLUGIN_ARCHIVE_NAME = "plugins.tar"
IGNORED_DIRECTORIES = {".git", ".pytest_cache", "__pycache__"}
IGNORED_FILES = {".DS_Store"}


class PluginSyncError(RuntimeError):
    """Raised when plugin staging or synchronization fails."""


def create_plugin_archive(source: Path, destination: Path) -> Path:
    """Create an archive without local caches or repository metadata."""
    try:
        with tarfile.open(destination, "w") as archive:
            for entry in sorted(source.iterdir(), key=lambda path: path.name):
                archive.add(
                    entry,
                    arcname=entry.name,
                    recursive=True,
                    filter=_filter_archive_member,
                )
    except (OSError, tarfile.TarError) as exc:
        raise PluginSyncError(f"Unable to prepare plugins: {exc}") from exc
    return destination


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
        await _remove_remote_stage(connection, stage)
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


def _filter_archive_member(member: tarfile.TarInfo) -> tarfile.TarInfo | None:
    path = PurePosixPath(member.name)
    if any(part in IGNORED_DIRECTORIES for part in path.parts):
        return None
    if path.name in IGNORED_FILES or path.suffix in {".pyc", ".pyo"}:
        return None
    # The remote install sets ownership after extraction.
    member.uid = member.gid = 0
    member.uname = member.gname = ""
    return member


async def _remove_remote_stage(connection: Any, stage: str) -> None:
    await run_remote(connection, f"rm -rf -- {shlex.quote(stage)}", check=False)
