#!/usr/bin/env python3
"""Build, deploy, and maintain a FISSURE Sensor Node with Apptainer and SSH.

Usage:
  deploy_remote_sensor_node.py --build [options]
  deploy_remote_sensor_node.py <destination> --deploy [options]
  deploy_remote_sensor_node.py --target=<destination> --deploy [options]
  deploy_remote_sensor_node.py <destination> [options]
  deploy_remote_sensor_node.py --target=<destination> [options]
  deploy_remote_sensor_node.py (-h | --help)

Options:
  -h --help                  Show this help.
  --target=<destination>     Legacy [user@]IP form (default user: root).
  --build                    Build the Sensor Node SIF locally without SSH.
  --deploy                   Deploy an existing SIF without building one.
  -i <path> --identity=<path>  SSH private key; omit to enter a password.
  --config=<path>            Values for rendered YAML (default: installed YAML).
  --certificates=<path>      Certificate root (default: installed certificates).
  --image=<path>             Existing SIF to deploy instead of building.
  --output-image=<path>      Build output and default SIF used by --deploy.
  --source=<path>            FISSURE source tree (default: repository root).
  --build-with-sudo          Build with sudo instead of Apptainer fakeroot.
  --no-install-apptainer     Do not install missing local or remote Apptainer.
  --remote-dir=<path>        Installation root [default: /opt/fissure-sensor-node].
  --service-name=<name>      systemd unit name [default: fissure-sensor-node].
  --health-timeout=<seconds>  Startup and diagnostic timeout [default: 180].
  --health-only              Check without changing the deployment.
  --update-config=<path>     Replace the installed config and restart the service.
  --update-image=<path>      Replace the installed SIF and restart the service.
  --restart                  Restart the installed service without other changes.
  --clear-data=<kind>        Clear logs, artifacts, or recordings and restart.
  --sync-plugins=<path>      Add or update plugins without deleting remote-only files.
  --uninstall                Remove the remote service and deployment files.
"""
import asyncio
from dataclasses import replace
import getpass
import importlib
from pathlib import Path
import shlex
import sys
import tempfile
import time
from typing import Any, Mapping, Sequence
import warnings

from remote_sensor_node_deploy_utilities import DeploymentUtilities
from remote_sensor_node_local_apptainer import LocalApptainerError
from remote_sensor_node_health import (
    HealthCheckError,
    wait_for_sensor_node_health,
)
from remote_sensor_node_scp import scp_with_progress
from remote_sensor_node_config import ConfigPreparationError, prepare_remote_config
from remote_sensor_node_operations import (
    RemoteOperationError,
    clear_remote_data,
    create_remote_stage,
    restart_remote_sensor_node,
    run_remote,
    update_remote_config,
    update_remote_image,
)
from remote_sensor_node_options import (
    DeployOptions,
    DeploymentError,
    HostSpec,
    validate_options,
)
from remote_sensor_node_image import (
    build_sensor_node_image,
    copy_build_context as copy_build_context,
    select_deployment_image,
)
from remote_sensor_node_plugin_sync import (
    PluginSyncError,
    create_plugin_archive,
    sync_remote_plugins,
)
from remote_sensor_node_templates import (
    TemplateRenderError,
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


def main(argv: Sequence[str] | None = None) -> int:
    try:
        options = parse_options(argv)
        validate_options(options)
        if options.build_image:
            asyncio.run(run_build_action(options))
            return 0
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
        PluginSyncError,
    ) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted", file=sys.stderr)
        return 130


async def run_build_action(options: DeployOptions) -> None:
    with tempfile.TemporaryDirectory(prefix="fissure-node-build.") as name:
        await build_sensor_node_image(options, Path(name))


async def deploy(options: DeployOptions, asyncssh: Any) -> None:
    target = require_target(options)
    destination = f"{target.username}@{target.hostname}"
    if await run_selected_maintenance_action(options, asyncssh, destination):
        return
    await deploy_new_release(options, asyncssh, destination)


async def run_selected_maintenance_action(
    options: DeployOptions,
    asyncssh: Any,
    destination: str,
) -> bool:
    if options.clear_data:
        await run_clear_data_action(options, asyncssh, destination)
        return True
    if options.sync_plugins_dir:
        await run_plugin_sync_action(options, asyncssh, destination)
        return True
    if options.update_image_file:
        await run_image_update_action(options, asyncssh, destination)
        return True
    if options.restart:
        await run_restart_action(options, asyncssh, destination)
        return True
    if options.update_config_file:
        await run_config_update_action(options, asyncssh, destination)
        return True
    if options.uninstall:
        await run_uninstall_action(options, asyncssh, destination)
        return True
    if options.health_only:
        await run_health_check_action(options, asyncssh, destination)
        return True
    return False


async def run_clear_data_action(
    options: DeployOptions,
    asyncssh: Any,
    destination: str,
) -> None:
    password = prompt_for_ssh_password(options)
    async with await connect(asyncssh, options, password) as connection:
        environment = await preflight(connection, False, destination)
        await clear_remote_data(connection, options, environment)


async def run_plugin_sync_action(
    options: DeployOptions,
    asyncssh: Any,
    destination: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="fissure-node-plugins.") as name:
        archive = await asyncio.to_thread(
            create_plugin_archive,
            options.sync_plugins_dir,
            Path(name) / "plugins.tar",
        )
        password = prompt_for_ssh_password(options)
        async with await connect(asyncssh, options, password) as connection:
            environment = await preflight(connection, False, destination)
            await sync_remote_plugins(
                asyncssh,
                connection,
                options,
                archive,
                environment,
            )


async def run_image_update_action(
    options: DeployOptions,
    asyncssh: Any,
    destination: str,
) -> None:
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


async def run_restart_action(
    options: DeployOptions,
    asyncssh: Any,
    destination: str,
) -> None:
    password = prompt_for_ssh_password(options)
    async with await connect(asyncssh, options, password) as connection:
        environment = await preflight(connection, False, destination)
        await restart_remote_sensor_node(connection, options, environment)


async def run_config_update_action(
    options: DeployOptions,
    asyncssh: Any,
    destination: str,
) -> None:
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


async def run_uninstall_action(
    options: DeployOptions,
    asyncssh: Any,
    destination: str,
) -> None:
    password = prompt_for_ssh_password(options)
    async with await connect(asyncssh, options, password) as connection:
        await uninstall_remote(
            connection,
            destination,
            options.remote_dir,
            options.service_name,
        )


async def run_health_check_action(
    options: DeployOptions,
    asyncssh: Any,
    destination: str,
) -> None:
    password = prompt_for_ssh_password(options)
    async with await connect(asyncssh, options, password) as connection:
        environment = await preflight(connection, False, destination)
        await wait_for_sensor_node_health(
            connection,
            options,
            environment.privilege,
            require_heartbeat=True,
        )


async def deploy_new_release(
    options: DeployOptions,
    asyncssh: Any,
    destination: str,
) -> None:

    with tempfile.TemporaryDirectory(prefix="fissure-node-deploy.") as name:
        temp_dir = Path(name)
        image = select_deployment_image(options)
        password = prompt_for_ssh_password(options)
        async with await connect(asyncssh, options, password) as connection:
            environment = await preflight(
                connection,
                options.install_apptainer,
                destination,
            )
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
        raw_target = args["<destination>"] or args["--target"]
        return DeployOptions(
            target=HostSpec.parse(raw_target) if raw_target else None,
            identity_file=path("--identity"),
            config_file=path("--config", source_dir / "YAML/Sensor_Node_Config/default.yaml"),
            certificates_dir=path("--certificates", source_dir / "certificates"),
            image_file=path("--image"),
            output_image=path(
                "--output-image",
                source_dir / "Installer/Remote_Sensor_Node/build/fissure-sensor-node.sif",
            ),
            source_dir=source_dir,
            remote_dir=args["--remote-dir"].rstrip("/") or "/",
            service_name=args["--service-name"].removesuffix(".service"),
            health_timeout=integer("--health-timeout"),
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
        )
    except (TypeError, ValueError) as exc:
        raise DeploymentError(f"Invalid numeric option: {exc}") from exc


def prompt_for_ssh_password(options: DeployOptions) -> str | None:
    if options.identity_file:
        return None

    target = require_target(options)
    username = f"{target.username}@" if target.username else ""
    prompt = f"SSH password for {username}{target.hostname}: "
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
    target = require_target(options)
    kwargs: dict[str, Any] = {"keepalive_interval": 30}
    if target.username:
        kwargs["username"] = target.username
    if options.identity_file:
        kwargs["client_keys"] = [str(options.identity_file)]
    elif password:
        kwargs.update(client_keys=None, password=password)
    else:
        raise DeploymentError("SSH password is required when -i is not specified")
    try:
        return await asyncssh.connect(target.hostname, **kwargs)
    except (OSError, asyncssh.Error) as exc:
        raise DeploymentError(f"SSH connection failed: {exc}") from exc


def require_target(options: DeployOptions) -> HostSpec:
    if not options.target:
        raise DeploymentError("An SSH destination is required for this action")
    return options.target


async def preflight(
    connection: Any,
    install_apptainer: bool,
    destination: str,
) -> RemoteEnvironment:
    try:
        return await prepare_remote_environment(
            connection,
            destination,
            install_apptainer,
        )
    except PrivilegeError as exc:
        raise DeploymentError(str(exc)) from exc


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
        stage,
        options.remote_dir,
        release_id,
        options.service_name,
        environment.user,
        environment.group,
        environment.apptainer,
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


async def upload_payload(
    asyncssh: Any,
    connection: Any,
    stage: str,
    options: DeployOptions,
    image: Path,
    unit: Path,
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
