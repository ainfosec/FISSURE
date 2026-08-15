"""Command-line option models and validation for remote sensor-node actions."""

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Mapping

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
    target: HostSpec | None
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
    build_image: bool = False
    deploy_image: bool = False
    restart: bool = False
    update_image_file: Path | None = None
    clear_data: str | None = None
    sync_plugins_dir: Path | None = None
    sync_source_dir: Path | None = None


def validate_options(options: DeployOptions) -> None:
    """Validate paths, action selection, and required local inputs."""
    _validate_action_selection(options)
    _validate_action_target(options)
    if not options.build_image:
        _validate_remote_destination(options)
        _validate_identity_file(options.identity_file)
    _validate_sync_directory("Plugin", options.sync_plugins_dir)
    _validate_sync_directory("Source", options.sync_source_dir)
    _validate_fissure_source(options.sync_source_dir)
    _validate_deployment_image(options)
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
        options.build_image,
        options.deploy_image,
        options.health_only,
        options.uninstall,
        bool(options.update_config_file),
        bool(options.update_image_file),
        options.restart,
        bool(options.clear_data),
        bool(options.sync_plugins_dir),
        bool(options.sync_source_dir),
    )
    if sum(actions) > 1:
        raise DeploymentError(
            "--build, --deploy, and maintenance actions cannot be combined"
        )


def _validate_action_target(options: DeployOptions) -> None:
    if options.build_image:
        if options.target:
            raise DeploymentError("--build does not accept an SSH destination")
        if options.image_file:
            raise DeploymentError("--build uses --output-image, not --image")
        return
    if not options.target:
        raise DeploymentError("An SSH destination is required for deployment actions")


def _validate_identity_file(identity_file: Path | None) -> None:
    if identity_file and not identity_file.is_file():
        raise DeploymentError(f"SSH identity is not a file: {identity_file}")


def _validate_sync_directory(name: str, directory: Path | None) -> None:
    if directory and not directory.is_dir():
        raise DeploymentError(f"{name} sync source is not a directory: {directory}")


def _validate_fissure_source(source: Path | None) -> None:
    if not source or not source.is_dir():
        return
    sensor_node = source / "fissure/Sensor_Node/SensorNode.py"
    if not sensor_node.is_file():
        raise DeploymentError(
            "Source sync directory is not a FISSURE source tree; missing: "
            "fissure/Sensor_Node/SensorNode.py"
        )


def _validate_deployment_image(options: DeployOptions) -> None:
    if not _is_full_deployment(options):
        return
    image = options.image_file or options.output_image
    if not image.is_file():
        raise DeploymentError(
            f"Deployment image is not a file: {image}. "
            "Run --build first or provide --image."
        )


def _is_full_deployment(options: DeployOptions) -> bool:
    return not any(
        (
            options.build_image,
            options.health_only,
            options.uninstall,
            options.update_config_file,
            options.update_image_file,
            options.restart,
            options.clear_data,
            options.sync_plugins_dir,
            options.sync_source_dir,
        )
    )


def _required_local_inputs(options: DeployOptions) -> list[Path]:
    if options.build_image:
        return [APPTAINER_TEMPLATE, options.source_dir / "fissure/Sensor_Node"]
    if options.update_config_file:
        return [options.update_config_file, SENSOR_NODE_TEMPLATE]
    if options.update_image_file:
        return [options.update_image_file]
    if options.sync_plugins_dir:
        return [options.sync_plugins_dir]
    if options.sync_source_dir:
        return [options.sync_source_dir, SERVICE_UNIT_TEMPLATE]
    if _needs_no_local_files(options):
        return []

    inputs = [
        options.config_file,
        options.certificates_dir / "clients/client_0.key_secret",
        options.certificates_dir / "server/server.key",
        SENSOR_NODE_TEMPLATE,
        SERVICE_UNIT_TEMPLATE,
    ]
    inputs.append(options.image_file or options.output_image)
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


def options_from_arguments(
    args: Mapping[str, Any],
    repository_root: Path,
) -> DeployOptions:
    """Map docopt values into the deployment model."""

    def path(name: str, default: Path | None = None) -> Path | None:
        value = args[name]
        return Path(value).expanduser() if value else default

    try:
        source_dir = path("--source", repository_root) or repository_root
        raw_target = args["<destination>"] or args["--target"]
        return DeployOptions(
            target=HostSpec.parse(raw_target) if raw_target else None,
            identity_file=path("--identity"),
            config_file=path(
                "--config",
                source_dir / "YAML/Sensor_Node_Config/default.yaml",
            ),
            certificates_dir=path("--certificates", source_dir / "certificates"),
            image_file=path("--image"),
            output_image=path(
                "--output-image",
                source_dir
                / "Installer/Remote_Sensor_Node/build/fissure-sensor-node.sif",
            ),
            source_dir=source_dir,
            remote_dir=args["--remote-dir"].rstrip("/") or "/",
            service_name=args["--service-name"].removesuffix(".service"),
            health_timeout=int(args["--health-timeout"]),
            health_only=bool(args["--health-only"]),
            build_with_sudo=bool(args["--build-with-sudo"]),
            install_apptainer=not bool(args["--no-install-apptainer"]),
            update_config_file=path("--update-config"),
            uninstall=bool(args["--uninstall"]),
            build_image=bool(args["--build"]),
            deploy_image=bool(args["--deploy"]),
            restart=bool(args["--restart"]),
            update_image_file=path("--update-image"),
            clear_data=args["--clear-data"],
            sync_plugins_dir=path("--sync-plugins"),
            sync_source_dir=path("--sync-source"),
        )
    except (TypeError, ValueError) as exc:
        raise DeploymentError(f"Invalid numeric option: {exc}") from exc
