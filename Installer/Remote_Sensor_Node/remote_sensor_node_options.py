"""Command-line option models and validation for remote sensor-node actions."""

from dataclasses import dataclass
from pathlib import Path
import re

from remote_sensor_node_templates import (
    APPTAINER_TEMPLATE,
    SENSOR_NODE_TEMPLATE,
    SERVICE_UNIT_TEMPLATE,
)


REMOTE_DIR_PATTERN = re.compile(r"^/[A-Za-z0-9._/-]+$")
SERVICE_PATTERN = re.compile(r"^[A-Za-z0-9_.@-]+$")
CLEAR_DATA_KINDS = ("artifacts", "logs", "recordings")


class DeploymentError(RuntimeError):
    """Raised for invalid deployment options."""


@dataclass(frozen=True)
class HostSpec:
    hostname: str
    username: str | None = None

    @classmethod
    def parse(cls, value: str) -> "HostSpec":
        username, separator, hostname = value.rpartition("@")
        if not separator:
            hostname, username = value, "root"
        hostname = hostname.strip("[]")
        if not hostname or hostname.startswith("-") or "\n" in hostname:
            raise DeploymentError(f"Invalid SSH target: {value!r}")
        return cls(hostname, username or None)


@dataclass(frozen=True)
class DeployOptions:
    target: HostSpec
    identity_file: Path | None
    config_file: Path
    certificates_dir: Path
    image_file: Path | None
    output_image: Path
    source_dir: Path
    remote_dir: str
    service_name: str
    health_timeout: int
    health_only: bool
    build_with_sudo: bool
    install_apptainer: bool
    update_config_file: Path | None
    uninstall: bool
    restart: bool = False
    update_image_file: Path | None = None
    clear_data: str | None = None
    sync_plugins_dir: Path | None = None


def validate_options(options: DeployOptions) -> None:
    """Validate paths, action selection, and required local inputs."""
    _validate_remote_destination(options)
    _validate_action_selection(options)
    _validate_identity_file(options.identity_file)
    _validate_plugin_directory(options.sync_plugins_dir)
    _validate_local_inputs(_required_local_inputs(options))


def _validate_remote_destination(options: DeployOptions) -> None:
    if not REMOTE_DIR_PATTERN.fullmatch(options.remote_dir):
        raise DeploymentError("--remote-dir must be absolute and contain no spaces")
    if options.remote_dir in {"/", "/opt"} or ".." in Path(options.remote_dir).parts:
        raise DeploymentError("--remote-dir is too broad or contains '..'")
    if not SERVICE_PATTERN.fullmatch(options.service_name):
        raise DeploymentError("Invalid --service-name")
    if options.health_timeout <= 0:
        raise DeploymentError("Timeout must be positive")


def _validate_action_selection(options: DeployOptions) -> None:
    if options.clear_data and options.clear_data not in CLEAR_DATA_KINDS:
        choices = ", ".join(CLEAR_DATA_KINDS)
        raise DeploymentError(f"--clear-data must be one of: {choices}")
    actions = (
        options.health_only,
        options.uninstall,
        bool(options.update_config_file),
        bool(options.update_image_file),
        options.restart,
        bool(options.clear_data),
        bool(options.sync_plugins_dir),
    )
    if sum(actions) > 1:
        raise DeploymentError(
            "--health-only, --update-config, --update-image, --restart, "
            "--clear-data, --sync-plugins, and --uninstall cannot be combined"
        )


def _validate_identity_file(identity_file: Path | None) -> None:
    if identity_file and not identity_file.is_file():
        raise DeploymentError(f"SSH identity is not a file: {identity_file}")


def _validate_plugin_directory(plugin_directory: Path | None) -> None:
    if plugin_directory and not plugin_directory.is_dir():
        raise DeploymentError(
            f"Plugin sync source is not a directory: {plugin_directory}"
        )


def _required_local_inputs(options: DeployOptions) -> list[Path]:
    if options.update_config_file:
        return [options.update_config_file, SENSOR_NODE_TEMPLATE]
    if options.update_image_file:
        return [options.update_image_file]
    if options.sync_plugins_dir:
        return [options.sync_plugins_dir]
    if _needs_no_local_files(options):
        return []

    inputs = [
        options.config_file,
        options.certificates_dir / "clients/client_0.key_secret",
        options.certificates_dir / "server/server.key",
        SENSOR_NODE_TEMPLATE,
        SERVICE_UNIT_TEMPLATE,
    ]
    if options.image_file:
        inputs.append(options.image_file)
    else:
        inputs.extend([APPTAINER_TEMPLATE, options.source_dir / "fissure/Sensor_Node"])
    return inputs


def _needs_no_local_files(options: DeployOptions) -> bool:
    return any(
        (
            options.health_only,
            options.uninstall,
            options.restart,
            options.clear_data,
        )
    )


def _validate_local_inputs(inputs: list[Path]) -> None:
    missing = [str(path) for path in inputs if not path.exists()]
    if missing:
        raise DeploymentError("Missing required input(s): " + ", ".join(missing))
