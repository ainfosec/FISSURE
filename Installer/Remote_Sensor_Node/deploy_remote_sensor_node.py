#!/usr/bin/env python3
"""Deploy and health-check a FISSURE sensor node with Apptainer and AsyncSSH.

Usage:
  deploy_remote_sensor_node.py <destination> [options]
  deploy_remote_sensor_node.py --target=<destination> [options]
  deploy_remote_sensor_node.py (-h | --help)

Options:
  -h --help                  Show this help.
  --target=<destination>     Legacy [user@]IP form (default user: root).
  -i <path> --identity=<path>  SSH private key; omit to enter a password.
  --config=<path>            Values for rendered YAML (default: installed YAML).
  --certificates=<path>      Certificate root (default: installed certificates).
  --image=<path>             Existing SIF to deploy instead of building.
  --output-image=<path>      Local SIF output (default: deployment build path).
  --source=<path>            FISSURE source tree (default: repository root).
  --build-with-sudo          Build with sudo instead of Apptainer fakeroot.
  --no-install-apptainer     Do not install missing local or remote Apptainer.
  --remote-dir=<path>        Installation root [default: /opt/fissure-sensor-node].
  --service-name=<name>      systemd unit name [default: fissure-sensor-node].
  --overlay-size=<mb>        Persistent overlay size [default: 4096].
  --health-timeout=<seconds>  Startup and diagnostic timeout [default: 180].
  --health-only              Check without changing the deployment.
  --update-config=<path>     Replace the installed config and restart the service.
  --update-image=<path>      Replace the installed SIF and restart the service.
  --restart                  Restart the installed service without other changes.
  --uninstall                Remove the remote service and deployment files.
"""
import asyncio
from dataclasses import dataclass, replace
import getpass
import importlib
from pathlib import Path
import re
import shlex
import shutil
import sys
import tempfile
import time
from typing import Any, Mapping, Sequence
import warnings

from remote_sensor_node_deploy_utilities import DeploymentUtilities
from remote_sensor_node_local_apptainer import (
    LocalApptainerError,
    ensure_local_apptainer,
)
from remote_sensor_node_health import (
    HealthCheckError,
    wait_for_sensor_node_health,
)
from remote_sensor_node_scp import scp_with_progress
from remote_sensor_node_config import ConfigPreparationError, prepare_remote_config
from remote_sensor_node_operations import (
    RemoteOperationError,
    create_remote_stage,
    restart_remote_sensor_node,
    run_remote,
    update_remote_config,
    update_remote_image,
)
from remote_sensor_node_templates import (
    APPTAINER_TEMPLATE,
    SENSOR_NODE_TEMPLATE,
    SERVICE_UNIT_TEMPLATE,
    TemplateRenderError,
    render_apptainer_definition,
    render_service_unit,
)
from remote_sensor_node_uninstall import uninstall_remote
from remote_sensor_node_privilege import (
    PrivilegeError,
    RemoteEnvironment,
    prepare_remote_environment,
    run_root_script,
)

INSTALLER_DIR = Path(__file__).resolve().parent
REPO_ROOT = INSTALLER_DIR.parent.parent
REMOTE_DIR_PATTERN = re.compile(r"^/[A-Za-z0-9._/-]+$")
SERVICE_PATTERN = re.compile(r"^[A-Za-z0-9_.@-]+$")


class DeploymentError(RuntimeError):
    pass


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
    overlay_size_mb: int
    health_only: bool
    build_with_sudo: bool
    install_apptainer: bool
    update_config_file: Path | None
    uninstall: bool
    restart: bool = False
    update_image_file: Path | None = None


def main(argv: Sequence[str] | None = None) -> int:
    try:
        options = parse_options(argv)
        validate_options(options)
        asyncssh = load_module("asyncssh")
        asyncio.run(deploy(options, asyncssh))
        return 0
    except (
        ConfigPreparationError,
        DeploymentError,
        LocalApptainerError,
        PrivilegeError,
        TemplateRenderError,
        HealthCheckError,
        RemoteOperationError,
    ) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Deployment interrupted", file=sys.stderr)
        return 130


async def deploy(options: DeployOptions, asyncssh: Any) -> None:
    destination = f"{options.target.username}@{options.target.hostname}"
    if options.update_image_file:
        password = prompt_for_ssh_password(options)
        async with await connect(asyncssh, options, password) as connection:
            environment = await preflight(connection, False, destination)
            await update_remote_image(
                asyncssh,
                connection,
                options,
                options.update_image_file,
                environment,
            )
        return
    if options.restart:
        password = prompt_for_ssh_password(options)
        async with await connect(asyncssh, options, password) as connection:
            environment = await preflight(connection, False, destination)
            await restart_remote_sensor_node(connection, options, environment)
        return
    if options.update_config_file:
        with tempfile.TemporaryDirectory(prefix="fissure-node-config.") as name:
            password = prompt_for_ssh_password(options)
            async with await connect(asyncssh, options, password) as connection:
                environment = await preflight(connection, False, destination)
                config_file = prepare_remote_config(
                    options.update_config_file,
                    Path(name) / "default.yaml",
                    connection,
                )
                await update_remote_config(
                    asyncssh,
                    connection,
                    options,
                    config_file,
                    environment,
                )
        return
    if options.uninstall:
        password = prompt_for_ssh_password(options)
        async with await connect(asyncssh, options, password) as connection:
            await uninstall_remote(
                connection,
                destination,
                options.remote_dir,
                options.service_name,
            )
        return
    if options.health_only:
        password = prompt_for_ssh_password(options)
        async with await connect(asyncssh, options, password) as connection:
            environment = await preflight(connection, False, destination)
            await wait_for_sensor_node_health(
                connection,
                options,
                environment.privilege,
                require_heartbeat=True,
            )
        return

    with tempfile.TemporaryDirectory(prefix="fissure-node-deploy.") as name:
        temp_dir = Path(name)
        image = await get_image(options, temp_dir)
        password = prompt_for_ssh_password(options)
        async with await connect(asyncssh, options, password) as connection:
            environment = await preflight(connection, options.install_apptainer, destination, )
            config_file = prepare_remote_config(
                options.config_file,
                temp_dir / "default.yaml",
                connection,
            )
            options = replace(options, config_file=config_file)
            unit = render_service_unit(
                temp_dir / f"{options.service_name}.service",
                options.remote_dir,
                environment.user,
                environment.group,
                environment.apptainer,
            )
            await deploy_release(asyncssh, connection, options, image, unit, environment)


def parse_options(argv: Sequence[str] | None = None) -> DeployOptions:
    docopt = load_module("docopt").docopt
    args = docopt(__doc__, argv=list(argv) if argv is not None else None)
    return options_from_arguments(args)


def options_from_arguments(args: Mapping[str, Any]) -> DeployOptions:
    def path(name: str, default: Path | None = None) -> Path | None:
        value = args[name]
        return Path(value).expanduser() if value else default

    def integer(name: str) -> int:
        return int(args[name])

    try:
        source_dir = path("--source", REPO_ROOT) or REPO_ROOT
        return DeployOptions(
            target=HostSpec.parse(args["<destination>"] or args["--target"]),
            identity_file=path("--identity"),
            config_file=path("--config", source_dir / "YAML/Sensor_Node_Config/default.yaml"),
            certificates_dir=path( "--certificates", source_dir / "certificates"),
            image_file=path("--image"),
            output_image=path(
                "--output-image",
                source_dir / "Installer/Remote_Sensor_Node/build/fissure-sensor-node.sif",
            ),
            source_dir=source_dir,
            remote_dir=args["--remote-dir"].rstrip("/") or "/",
            service_name=args["--service-name"].removesuffix(".service"),
            health_timeout=integer("--health-timeout"),
            overlay_size_mb=integer("--overlay-size"),
            health_only=bool(args["--health-only"]),
            build_with_sudo=bool(args["--build-with-sudo"]),
            install_apptainer=not bool(args["--no-install-apptainer"]),
            update_config_file=path("--update-config"),
            uninstall=bool(args["--uninstall"]),
            restart=bool(args["--restart"]),
            update_image_file=path("--update-image"),
        )
    except (TypeError, ValueError) as exc:
        raise DeploymentError(f"Invalid numeric option: {exc}") from exc


def validate_options(options: DeployOptions) -> None:
    if not REMOTE_DIR_PATTERN.fullmatch(options.remote_dir):
        raise DeploymentError("--remote-dir must be absolute and contain no spaces")
    if options.remote_dir in {"/", "/opt"} or ".." in Path(options.remote_dir).parts:
        raise DeploymentError("--remote-dir is too broad or contains '..'")
    if not SERVICE_PATTERN.fullmatch(options.service_name):
        raise DeploymentError("Invalid --service-name")
    if options.health_timeout <= 0 or options.overlay_size_mb <= 0:
        raise DeploymentError("Timeout and overlay size must be positive")
    actions = [
        options.health_only,
        options.uninstall,
        bool(options.update_config_file),
        bool(options.update_image_file),
        options.restart,
    ]
    if sum(actions) > 1:
        raise DeploymentError(
            "--health-only, --update-config, --update-image, --restart, and "
            "--uninstall cannot be combined"
        )
    if options.identity_file and not options.identity_file.is_file():
        raise DeploymentError(
            f"SSH identity is not a file: {options.identity_file}"
        )
    local_inputs = []
    if options.update_config_file:
        local_inputs += [options.update_config_file, SENSOR_NODE_TEMPLATE]
    elif options.update_image_file:
        local_inputs.append(options.update_image_file)
    elif not options.health_only and not options.uninstall and not options.restart:
        local_inputs += [
            options.config_file,
            options.certificates_dir / "clients/client_0.key_secret",
            options.certificates_dir / "server/server.key",
            SENSOR_NODE_TEMPLATE,
            SERVICE_UNIT_TEMPLATE,
        ]
        if options.image_file:
            local_inputs.append(options.image_file)
        else:
            local_inputs += [APPTAINER_TEMPLATE, options.source_dir / "fissure/Sensor_Node"]
    missing = [str(path) for path in local_inputs if path and not path.exists()]
    if missing:
        raise DeploymentError("Missing required input(s): " + ", ".join(missing))


def prompt_for_ssh_password(options: DeployOptions) -> str | None:
    if options.identity_file:
        return None

    username = f"{options.target.username}@" if options.target.username else ""
    prompt = f"SSH password for {username}{options.target.hostname}: "
    try:
        # getpass otherwise falls back to echoed stdin when no secure terminal exists.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass(prompt)
    except (EOFError, OSError, getpass.GetPassWarning) as exc:
        raise DeploymentError(
            "Unable to read an SSH password securely; use -i with a private key"
        ) from exc
    if not password:
        raise DeploymentError("SSH password cannot be empty; use -i with a private key")
    return password


async def connect(
    asyncssh: Any, options: DeployOptions, password: str | None
) -> Any:
    kwargs: dict[str, Any] = {"keepalive_interval": 30}
    if options.target.username:
        kwargs["username"] = options.target.username
    if options.identity_file:
        kwargs["client_keys"] = [str(options.identity_file)]
    elif password:
        kwargs.update(client_keys=None, password=password)
    else:
        raise DeploymentError("SSH password is required when -i is not specified")
    try:
        return await asyncssh.connect(options.target.hostname, **kwargs)
    except (OSError, asyncssh.Error) as exc:
        raise DeploymentError(f"SSH connection failed: {exc}") from exc


async def preflight(connection: Any,install_apptainer: bool, destination: str) -> RemoteEnvironment:
    try:
        return await prepare_remote_environment(
            connection,
            destination,
            install_apptainer,
        )
    except PrivilegeError as exc:
        raise DeploymentError(str(exc)) from exc


async def get_image(options: DeployOptions, temp_dir: Path) -> Path:
    if options.image_file:
        return options.image_file.resolve()
    if options.output_image.is_file():
        print(f"[✓] Using existing image {options.output_image}")
        return options.output_image.resolve()
    apptainer = await ensure_local_apptainer(options.install_apptainer)
    source = temp_dir / "source"
    await asyncio.to_thread(copy_build_context, options.source_dir, source)
    definition = render_apptainer_definition(
        source,
        temp_dir / APPTAINER_TEMPLATE.stem,
    )
    options.output_image.parent.mkdir(parents=True, exist_ok=True)
    command = [apptainer, "build", "--force"]
    command += ["--fakeroot"] if not options.build_with_sudo else []
    command += [str(options.output_image), str(definition)]
    if options.build_with_sudo:
        command.insert(0, "sudo")
    print(f"[*] Building {options.output_image}")
    process = await asyncio.create_subprocess_exec(*command)
    if await process.wait():
        raise DeploymentError(f"Build failed: {shlex.join(command)}")
    return options.output_image.resolve()


def copy_build_context(source: Path, destination: Path) -> None:
    root_exclusions = {
        ".agents", ".codex", ".env", ".git", ".idea", ".venv",
        "build", "certificates", "Logs",
    }

    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored = {name for name in names if name in {".git", "__pycache__", ".pytest_cache"}}
        if Path(directory).resolve() == source.resolve():
            ignored.update(root_exclusions.intersection(names))
        ignored.update(name for name in names if name.endswith(".key_secret"))
        return ignored

    shutil.copytree(source.resolve(), destination, symlinks=True, ignore=ignore)


async def deploy_release(
    asyncssh: Any,
    connection: Any,
    options: DeployOptions,
    image: Path,
    unit: Path,
    environment: RemoteEnvironment,
) -> None:
    release_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    stage = await create_remote_stage(connection)
    await upload_payload(asyncssh, connection, stage, options, image, unit)
    args = [
        stage, options.remote_dir, release_id, options.service_name,
        environment.user,
        environment.group,
        environment.apptainer,
        str(options.overlay_size_mb),
    ]
    await run_root_script(
        connection,
        DeploymentUtilities.INSTALL_SCRIPT,
        args,
        environment.privilege,
    )
    await wait_for_sensor_node_health(
        connection,
        options,
        environment.privilege,
        require_heartbeat=False,
    )
    print(f"[✓] Release {release_id} started successfully")


async def upload_payload(asyncssh: Any, connection: Any, stage: str, options: DeployOptions, image: Path, unit: Path,
) -> None:
    files = {
        image: "fissure-sensor-node.sif",
        options.config_file: "default.yaml",
        options.certificates_dir / "clients/client_0.key_secret": "client_0.key_secret",
        options.certificates_dir / "server/server.key": "server.key",
        unit: unit.name,
    }
    print(f"[*] Uploading {image.name} and runtime inputs with SCP")
    try:
        for local, remote_name in files.items():
            destination = (connection, f"{stage}/{remote_name}")
            await scp_with_progress(asyncssh, str(local), destination)
    except Exception as exc:
        await run_remote(connection, f"rm -rf -- {shlex.quote(stage)}", check=False)
        raise DeploymentError(f"SCP upload failed: {exc}") from exc


def load_module(name: str) -> Any:
    try:
        return importlib.import_module(name)
    except ImportError as exc:
        raise DeploymentError(
            f"{name} is required. Install dependencies with: "
            "python3 -m pip install -r "
            "Installer/Remote_Sensor_Node/requirements-node-deploy.txt"
        ) from exc

if __name__ == "__main__":
    raise SystemExit(main())
