#!/usr/bin/python3
"""Plugin Related Functionality
"""
import asyncio
import csv
import filecmp
import importlib.util
import inspect
import logging
import os
from psycopg2.extensions import connection
import shutil
from subprocess import Popen, run
import traceback
from typing import List, Dict, Set, Any
import copy
import yaml
import sys
import hashlib
import stat
import tempfile
import zipfile


from fissure.utils import FISSURE_ROOT, PLUGIN_DIR
from fissure.utils.library import (
    openDatabaseConnection,
    addProtocol,
    removeProtocol,
    addModulationType,
    removeModulationType,
    addPacketType,
    removePacketType,
    addSOI,
    removeSOI,
    addDemodulationFlowGraph,
    removeDemodulationFlowGraph,
    addAttack,
    removeAttack,
)


TABLES_FUNCTIONS = [
    ('attacks.csv', addAttack, removeAttack),
    ('demodulation_flow_graphs.csv', addDemodulationFlowGraph, removeDemodulationFlowGraph),
    ('modulation_types.csv', addModulationType, removeModulationType),
    ('packet_types.csv', addPacketType, removePacketType),
    ('protocols.csv', addProtocol, removeProtocol),
    ('soi_data.csv', addSOI, removeSOI)
]

async def get_fissure_plugin_editor_plugins_path() -> str:
    """Get the path to the FISSURE Plugin Editor plugins directory.

    Returns
    -------
    str
        Path to the FISSURE Plugin Editor plugins directory.
    """
    if shutil.which("fissure-plugin-editor") is not None:
        proc = await asyncio.create_subprocess_exec(
            "fissure-plugin-editor", "plugins", "-d",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode().strip()
        if output.startswith("Plugins directory:"):
            return output.split("Plugins directory:")[1].strip()
        else:
            return None
    else:
        return None

def launch_fissure_plugin_editor() -> bool:
    """Launch the FISSURE Plugin Editor.

    Returns
    -------
    bool
        True if the editor was launched successfully, False otherwise.
    """
    try:
        # Launch the FISSURE Plugin Editor in a new terminal
        Popen(["fissure-plugin-editor", "gui"])
    except FileNotFoundError:
        return False

    # Check if the process is running
    result = run(["pgrep", "-f", "fissure-plugin-editor"], capture_output=True)
    return bool(result.stdout.strip())

def get_local_plugin_names():
    """
    
    """
    # Scan plugins file directory; get plugin names based on plugin folder/compressed
    plugins = []
    for candidate in os.listdir(PLUGIN_DIR):
        candidate_path = os.path.join(PLUGIN_DIR, candidate)
        if os.path.isdir(candidate_path):
            # plugin folder
            plugins += [candidate]
        elif os.path.isfile(candidate_path):
            (root, ext) = os.path.splitext(candidate)
            if ext == '.zip':
                # plugin zip file; use root name
                plugins += [root]
    return plugins


def get_plugin_manifest(plugin_name: str) -> Dict[str, Any]:
    """Read lightweight metadata for one deployed plugin directory."""
    plugin_name = str(plugin_name or "").strip()
    plugin_path = os.path.join(PLUGIN_DIR, plugin_name)
    manifest_path = os.path.join(plugin_path, "plugin.yaml")

    manifest = {}
    manifest_error = ""

    if os.path.isfile(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as stream:
                loaded = yaml.safe_load(stream) or {}

            if isinstance(loaded, dict):
                manifest = loaded
            else:
                manifest_error = "plugin.yaml must contain a mapping."

        except Exception as exc:
            manifest_error = str(exc)

    cleanup_supported = manifest.get("cleanup", False)

    if isinstance(cleanup_supported, str):
        cleanup_supported = cleanup_supported.strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
    else:
        cleanup_supported = bool(cleanup_supported)

    required_plugins_raw = manifest.get(
        "required_plugins",
        [],
    )

    if required_plugins_raw is None:
        required_plugins = []

    elif isinstance(required_plugins_raw, str):
        required_plugins = [
            required_plugins_raw.strip()
        ] if required_plugins_raw.strip() else []

    elif isinstance(required_plugins_raw, (list, tuple)):
        required_plugins = []

        for required_plugin in required_plugins_raw:
            required_plugin = str(
                required_plugin
                or ""
            ).strip()

            if (
                required_plugin
                and required_plugin not in required_plugins
            ):
                required_plugins.append(
                    required_plugin
                )

    else:
        required_plugins = []

        required_plugins_error = (
            "required_plugins must be a list of plugin names."
        )

        if manifest_error:
            manifest_error = (
                f"{manifest_error} {required_plugins_error}"
            )
        else:
            manifest_error = required_plugins_error

    return {
        "name": plugin_name,
        "manifest_name": str(
            manifest.get("name") or plugin_name
        ).strip(),
        "version": str(
            manifest.get("version") or ""
        ).strip(),
        "description": str(
            manifest.get("description") or ""
        ).strip(),
        "manifest_present": os.path.isfile(manifest_path),
        "manifest_error": manifest_error,
        "setup_present": os.path.isfile(
            os.path.join(plugin_path, "setup.py")
        ),
        "cleanup_supported": cleanup_supported,
        "required_plugins": required_plugins,
    }


def get_local_plugin_inventory() -> Dict[str, Dict[str, Any]]:
    """Return manifest/setup metadata for plugin directories physically present here."""
    inventory = {}

    if not os.path.isdir(PLUGIN_DIR):
        return inventory

    for candidate in sorted(os.listdir(PLUGIN_DIR), key=str.casefold):
        if candidate.startswith(".") or candidate == "__pycache__":
            continue

        candidate_path = os.path.join(PLUGIN_DIR, candidate)
        if not os.path.isdir(candidate_path):
            continue

        inventory[candidate] = get_plugin_manifest(candidate)

    return inventory


async def run_plugin_setup(
    plugin_name: str,
    action: str,
    timeout: float = 30.0,
) -> Dict[str, Any]:
    """Run one predefined plugin-owned setup action locally and capture its result."""
    plugin_name = str(plugin_name or "").strip()
    action = str(action or "").strip().lower()

    result = {
        "plugin_name": plugin_name,
        "action": action,
        "ok": False,
        "returncode": None,
        "status": "Setup Failed",
        "message": "",
        "output": "",
    }

    if action not in {"check", "install", "cleanup"}:
        result["message"] = f"Unsupported setup action: {action}"
        return result

    if (
        not plugin_name
        or os.path.basename(plugin_name) != plugin_name
        or plugin_name in {".", ".."}
    ):
        result["message"] = "Invalid plugin name."
        return result

    plugin_root = os.path.realpath(PLUGIN_DIR)
    plugin_path = os.path.realpath(os.path.join(plugin_root, plugin_name))

    if os.path.dirname(plugin_path) != plugin_root:
        result["message"] = "Plugin path is outside the Plugins directory."
        return result

    if not os.path.isdir(plugin_path):
        result["message"] = f"Plugin is not deployed: {plugin_name}"
        return result

    setup_path = os.path.realpath(os.path.join(plugin_path, "setup.py"))
    if os.path.dirname(setup_path) != plugin_path:
        result["message"] = "Plugin setup path is invalid."
        return result

    if not os.path.isfile(setup_path):
        if action == "check":
            result.update({
                "ok": True,
                "returncode": 0,
                "status": "Ready",
                "message": "No external setup required.",
            })
        else:
            result["message"] = f"{plugin_name} does not provide setup.py."
        return result

    try:
        timeout = max(1.0, float(timeout))
    except (TypeError, ValueError):
        timeout = 30.0

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    process = None

    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            setup_path,
            action,
            cwd=plugin_path,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        try:
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            stdout, _ = await process.communicate()

            output = (stdout or b"").decode(
                errors="replace"
            ).strip()
            if len(output) > 65536:
                output = output[-65536:]

            result.update({
                "returncode": process.returncode,
                "status": "Setup Failed",
                "message": (
                    f"{action.capitalize()} timed out after "
                    f"{timeout:g} seconds."
                ),
                "output": output,
            })
            return result

        output = (stdout or b"").decode(
            errors="replace"
        ).strip()
        if len(output) > 65536:
            output = output[-65536:]

        returncode = int(process.returncode or 0)

        if action == "check":
            if returncode == 0:
                status = "Ready"
                ok = True
                message = "Setup check passed."
            elif returncode == 1:
                status = "Setup Required"
                ok = False
                message = "Setup check reports that setup is required."
            else:
                status = "Setup Failed"
                ok = False
                message = f"Setup check failed with exit code {returncode}."

        elif action == "install":
            if returncode == 0:
                status = "Installed"
                ok = True
                message = "Setup install completed."
            else:
                status = "Setup Failed"
                ok = False
                message = f"Setup install failed with exit code {returncode}."

        else:
            if returncode == 0:
                status = "Cleaned"
                ok = True
                message = "Plugin cleanup completed."
            else:
                status = "Cleanup Failed"
                ok = False
                message = f"Plugin cleanup failed with exit code {returncode}."

        result.update({
            "ok": ok,
            "returncode": returncode,
            "status": status,
            "message": message,
            "output": output,
        })
        return result

    except Exception as exc:
        result["message"] = f"Could not run {plugin_name} setup {action}: {exc}"
        return result
    

_PLUGIN_PACKAGE_EXCLUDED_DIRS = {
    "__pycache__",
    ".git",
    ".pytest_cache",
    ".mypy_cache",
    "build",
    "dist",
}

_PLUGIN_PACKAGE_EXCLUDED_FILES = {
    ".DS_Store",
    ".setup_test_ready",
}


def _validate_plugin_name(plugin_name: str) -> str:
    """Return one safe canonical plugin-directory name."""
    plugin_name = str(
        plugin_name
        or ""
    ).strip()

    if (
        not plugin_name
        or plugin_name in {".", ".."}
        or os.path.basename(plugin_name) != plugin_name
    ):
        raise ValueError(
            "Invalid plugin name"
        )

    return plugin_name


def _file_sha256(filepath: str) -> str:
    """Calculate SHA-256 without loading the entire file into memory."""
    digest = hashlib.sha256()

    with open(filepath, "rb") as handle:
        while True:
            chunk = handle.read(
                1024 * 1024
            )
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def create_plugin_package(
    plugin_name: str,
) -> Dict[str, Any]:
    """
    Package one Hub plugin directory as a temporary ZIP.

    The ZIP always has exactly one canonical top-level directory:
        <plugin_name>/...
    """
    plugin_name = _validate_plugin_name(
        plugin_name
    )

    plugin_path = os.path.realpath(
        os.path.join(
            PLUGIN_DIR,
            plugin_name,
        )
    )

    plugin_root = os.path.realpath(
        PLUGIN_DIR
    )

    if (
        os.path.dirname(plugin_path) != plugin_root
        or not os.path.isdir(plugin_path)
    ):
        raise FileNotFoundError(
            f"Hub plugin is not deployed: {plugin_name}"
        )

    fd, package_path = tempfile.mkstemp(
        prefix=f"fissure-plugin-{plugin_name}-",
        suffix=".zip",
    )
    os.close(fd)

    try:
        with zipfile.ZipFile(
            package_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as archive:
            for root, dirs, files in os.walk(
                plugin_path
            ):
                dirs[:] = [
                    dirname
                    for dirname in dirs
                    if dirname
                    not in _PLUGIN_PACKAGE_EXCLUDED_DIRS
                ]

                for filename in files:
                    if filename in _PLUGIN_PACKAGE_EXCLUDED_FILES:
                        continue

                    if filename.endswith(
                        (
                            ".pyc",
                            ".pyo",
                        )
                    ):
                        continue

                    source_path = os.path.join(
                        root,
                        filename,
                    )

                    if os.path.islink(
                        source_path
                    ):
                        raise RuntimeError(
                            "Plugin packages do not support symbolic links: "
                            f"{source_path}"
                        )

                    relative_path = os.path.relpath(
                        source_path,
                        plugin_path,
                    )

                    archive_name = (
                        plugin_name
                        + "/"
                        + relative_path.replace(
                            os.sep,
                            "/",
                        )
                    )

                    archive.write(
                        source_path,
                        archive_name,
                    )

        return {
            "plugin_name": plugin_name,
            "package_path": package_path,
            "file_size": os.path.getsize(
                package_path
            ),
            "sha256": _file_sha256(
                package_path
            ),
        }

    except Exception:
        try:
            os.remove(
                package_path
            )
        except OSError:
            pass
        raise


def get_plugin_package_staging_path(
    plugin_name: str,
    transfer_id: str,
    create_folder: bool = False,
) -> str:
    """Resolve the Sensor Node's private incoming plugin-package path."""
    plugin_name = _validate_plugin_name(
        plugin_name
    )

    transfer_id = str(
        transfer_id
        or ""
    ).strip()

    if (
        not transfer_id
        or os.path.basename(transfer_id) != transfer_id
    ):
        raise ValueError(
            "Invalid plugin transfer ID"
        )

    staging_root = os.path.realpath(
        os.path.join(
            PLUGIN_DIR,
            ".incoming",
        )
    )

    if create_folder:
        os.makedirs(
            staging_root,
            exist_ok=True,
        )

    package_path = os.path.realpath(
        os.path.join(
            staging_root,
            f"{plugin_name}.{transfer_id}.zip",
        )
    )

    if os.path.dirname(package_path) != staging_root:
        raise ValueError(
            "Invalid plugin staging path"
        )

    return package_path


def _safe_extract_plugin_package(
    package_path: str,
    destination_root: str,
    plugin_name: str,
) -> str:
    """Extract one trusted plugin ZIP while rejecting traversal and symlinks."""
    plugin_name = _validate_plugin_name(
        plugin_name
    )

    destination_root = os.path.realpath(
        destination_root
    )
    os.makedirs(
        destination_root,
        exist_ok=True,
    )

    expected_prefix = (
        plugin_name
        + "/"
    )

    with zipfile.ZipFile(
        package_path,
        "r",
    ) as archive:
        members = archive.infolist()

        if not members:
            raise RuntimeError(
                "Plugin package is empty"
            )

        for member in members:
            member_name = str(
                member.filename
                or ""
            ).replace(
                "\\",
                "/",
            )

            if not member_name:
                continue

            if (
                member_name.startswith("/")
                or member_name == ".."
                or member_name.startswith("../")
                or "/../" in member_name
            ):
                raise RuntimeError(
                    f"Unsafe plugin package member: {member_name}"
                )

            if not (
                member_name == plugin_name
                or member_name.startswith(
                    expected_prefix
                )
            ):
                raise RuntimeError(
                    "Plugin package contains files outside "
                    f"{plugin_name}/: {member_name}"
                )

            unix_mode = (
                member.external_attr
                >> 16
            )

            if stat.S_ISLNK(
                unix_mode
            ):
                raise RuntimeError(
                    "Plugin packages do not support symbolic links: "
                    f"{member_name}"
                )

            target_path = os.path.realpath(
                os.path.join(
                    destination_root,
                    *[
                        part
                        for part in member_name.split("/")
                        if part
                    ],
                )
            )

            if os.path.commonpath(
                [
                    destination_root,
                    target_path,
                ]
            ) != destination_root:
                raise RuntimeError(
                    f"Unsafe plugin package path: {member_name}"
                )

            if member.is_dir():
                os.makedirs(
                    target_path,
                    exist_ok=True,
                )
                continue

            os.makedirs(
                os.path.dirname(
                    target_path
                ),
                exist_ok=True,
            )

            with archive.open(
                member,
                "r",
            ) as source_handle:
                with open(
                    target_path,
                    "wb",
                ) as destination_handle:
                    shutil.copyfileobj(
                        source_handle,
                        destination_handle,
                    )

            permission_bits = (
                unix_mode
                & 0o777
            )

            if permission_bits:
                try:
                    os.chmod(
                        target_path,
                        permission_bits,
                    )
                except OSError:
                    pass

    extracted_plugin_path = os.path.join(
        destination_root,
        plugin_name,
    )

    if not os.path.isdir(
        extracted_plugin_path
    ):
        raise RuntimeError(
            "Plugin package did not contain its expected "
            f"{plugin_name}/ directory"
        )

    return extracted_plugin_path


def deploy_staged_plugin_package(
    plugin_name: str,
    transfer_id: str,
) -> Dict[str, Any]:
    """
    Atomically replace one deployed plugin directory from its verified staged ZIP.

    External setup/cleanup is intentionally NOT performed here.
    """
    plugin_name = _validate_plugin_name(
        plugin_name
    )

    package_path = get_plugin_package_staging_path(
        plugin_name,
        transfer_id,
        create_folder=False,
    )

    if not os.path.isfile(
        package_path
    ):
        raise FileNotFoundError(
            "Staged plugin package was not found"
        )

    deploy_root = os.path.realpath(
        os.path.join(
            PLUGIN_DIR,
            ".deploy",
        )
    )
    os.makedirs(
        deploy_root,
        exist_ok=True,
    )

    extraction_root = tempfile.mkdtemp(
        prefix=(
            f"{plugin_name}."
            f"{transfer_id}."
        ),
        dir=deploy_root,
    )

    plugin_path = os.path.realpath(
        os.path.join(
            PLUGIN_DIR,
            plugin_name,
        )
    )

    backup_path = os.path.realpath(
        os.path.join(
            deploy_root,
            f"{plugin_name}.{transfer_id}.old",
        )
    )

    old_moved = False
    new_installed = False

    try:
        extracted_plugin_path = (
            _safe_extract_plugin_package(
                package_path,
                extraction_root,
                plugin_name,
            )
        )

        if os.path.exists(
            backup_path
        ):
            if os.path.isdir(
                backup_path
            ):
                shutil.rmtree(
                    backup_path
                )
            else:
                os.remove(
                    backup_path
                )

        if os.path.isdir(
            plugin_path
        ):
            os.replace(
                plugin_path,
                backup_path,
            )
            old_moved = True

        os.replace(
            extracted_plugin_path,
            plugin_path,
        )
        new_installed = True

        if old_moved and os.path.isdir(
            backup_path
        ):
            shutil.rmtree(
                backup_path
            )

        manifest = get_plugin_manifest(
            plugin_name
        )

        return {
            "plugin_name": plugin_name,
            "version": str(
                manifest.get("version")
                or ""
            ),
            "manifest_present": bool(
                manifest.get(
                    "manifest_present"
                )
            ),
            "setup_present": bool(
                manifest.get(
                    "setup_present"
                )
            ),
        }

    except Exception:
        if (
            not new_installed
            and old_moved
            and os.path.isdir(
                backup_path
            )
            and not os.path.exists(
                plugin_path
            )
        ):
            try:
                os.replace(
                    backup_path,
                    plugin_path,
                )
            except OSError:
                pass

        raise

    finally:
        shutil.rmtree(
            extraction_root,
            ignore_errors=True,
        )

        if os.path.isdir(
            backup_path
        ):
            shutil.rmtree(
                backup_path,
                ignore_errors=True,
            )


def remove_local_plugin_directory(plugin_name: str) -> None:
    """Delete one deployed plugin directory from this FISSURE installation."""
    plugin_name = _validate_plugin_name(
        plugin_name
    )

    if plugin_name.casefold() == "base":
        raise RuntimeError(
            "The Base plugin cannot be removed."
        )

    plugin_root = os.path.realpath(
        PLUGIN_DIR
    )

    plugin_path = os.path.realpath(
        os.path.join(
            plugin_root,
            plugin_name,
        )
    )

    if os.path.dirname(plugin_path) != plugin_root:
        raise RuntimeError(
            "Plugin path is outside the Plugins directory."
        )

    if not os.path.isdir(plugin_path):
        raise FileNotFoundError(
            f"Plugin is not deployed: {plugin_name}"
        )

    shutil.rmtree(
        plugin_path
    )


def _normalize_action_tags(tags) -> Set[str]:
    """Normalize ACTION_TAGS entries into a clean string set."""
    if not isinstance(
        tags,
        (
            list,
            tuple,
            set,
        ),
    ):
        return set()

    return {
        str(tag).strip()
        for tag in tags
        if tag is not None
        and str(tag).strip()
    }


def _requester_type_action_tag(
    requester_type: str,
) -> str:
    """Translate the message requester type into the reserved client tag."""
    requester = str(
        requester_type
        or ""
    ).strip().lower()

    if requester == "dashboard":
        return "client.dashboard"

    if requester in {
        "tak",
        "wintak",
        "atak",
    }:
        return "client.tak"

    return ""


def _node_location_action_tag(
    node_location: str,
) -> str:
    """Translate Sensor Node local/remote state into the reserved node tag."""
    location = str(
        node_location
        or ""
    ).strip().lower()

    if location == "local":
        return "node.local"

    if location == "remote":
        return "node.remote"

    return ""


def action_tags_allow_context(
    tags,
    requester_type: str = "",
    node_location: str = "",
) -> bool:
    """
    Apply optional client.* and node.* capability restrictions.

    Absence of a namespace is permissive for backward compatibility.
    Presence of a namespace requires an exact context match. Autorun is a
    node-owned execution context, so client.* tags do not restrict it.
    """
    normalized_tags = _normalize_action_tags(tags)
    requester = str(requester_type or "").strip().lower()

    client_tags = {
        tag
        for tag in normalized_tags
        if tag.startswith("client.")
    }

    if client_tags and requester != "autorun":
        requester_tag = _requester_type_action_tag(requester_type)
        if not requester_tag or requester_tag not in client_tags:
            return False

    node_tags = {
        tag
        for tag in normalized_tags
        if tag.startswith("node.")
    }

    if node_tags:
        node_tag = _node_location_action_tag(node_location)
        if not node_tag or node_tag not in node_tags:
            return False

    return True


def action_is_allowed(
    plugin: str,
    action_name: str,
    requester_type: str = "",
    node_location: str = "",
    logger: logging.Logger = logging.getLogger(__name__),
) -> bool:
    """
    Return whether one plugin action is allowed for the supplied client/node
    context.

    Plugins without ACTION_TAGS, actions missing from ACTION_TAGS, and actions
    without client.* / node.* restrictions remain allowed.
    """
    actions_path = os.path.join(
        PLUGIN_DIR,
        plugin,
        "actions.py",
    )

    if not os.path.exists(
        actions_path
    ):
        return False

    try:
        module_name = (
            f"{plugin}_actions_context"
        )

        spec = (
            importlib.util.spec_from_file_location(
                module_name,
                actions_path,
            )
        )

        if (
            spec is None
            or spec.loader is None
        ):
            raise ImportError(
                f"Cannot load module spec for {actions_path}"
            )

        module = (
            importlib.util.module_from_spec(
                spec
            )
        )

        spec.loader.exec_module(
            module
        )

        action_tags = getattr(
            module,
            "ACTION_TAGS",
            {},
        ) or {}

        tags = action_tags.get(
            action_name,
            [],
        )

        return action_tags_allow_context(
            tags,
            requester_type=requester_type,
            node_location=node_location,
        )

    except Exception as exc:
        logger.error(
            "Failed checking action context for "
            f"{plugin}.{action_name}: {exc}"
        )
        logger.debug(
            "Traceback while checking action context:\n%s",
            traceback.format_exc(),
        )

        return False
    

def get_plugin_actions(
    plugin: str,
    sensor_node_settings: dict = None,
    logger: logging.Logger = logging.getLogger(__name__),
    requester_type: str = "",
    node_location: str = "",
) -> List[str]:
    """
    Get plugin actions filtered by configured hardware and optional
    client/node capability tags.
    """
    actions_path = os.path.join(
        PLUGIN_DIR,
        plugin,
        "actions.py",
    )

    actions: List[str] = []

    if not os.path.exists(
        actions_path
    ):
        return actions

    try:
        module_name = f"{plugin}_actions"

        spec = (
            importlib.util.spec_from_file_location(
                module_name,
                actions_path,
            )
        )

        if (
            spec is None
            or spec.loader is None
        ):
            raise ImportError(
                f"Cannot load module spec for {actions_path}"
            )

        module = (
            importlib.util.module_from_spec(
                spec
            )
        )

        spec.loader.exec_module(
            module
        )

        discovered_actions = [
            name
            for name, obj in inspect.getmembers(
                module,
                inspect.iscoroutinefunction,
            )
            if not name.startswith("_")
            and obj.__module__ == module.__name__
        ]

        action_hardware = getattr(
            module,
            "ACTION_HARDWARE",
            {},
        ) or {}

        action_tags = getattr(
            module,
            "ACTION_TAGS",
            {},
        ) or {}

        configured_hw_types = (
            get_configured_hardware_types(
                sensor_node_settings
            )
            if sensor_node_settings
            else set()
        )

        filtered_actions = []

        for action_name in discovered_actions:
            required_hw = (
                action_hardware.get(
                    action_name
                )
            )

            if (
                sensor_node_settings
                and required_hw
                and not any(
                    hw in configured_hw_types
                    for hw in required_hw
                )
            ):
                continue

            if not action_tags_allow_context(
                action_tags.get(
                    action_name,
                    [],
                ),
                requester_type=(
                    requester_type
                ),
                node_location=(
                    node_location
                ),
            ):
                continue

            filtered_actions.append(
                action_name
            )

        actions = filtered_actions

    except Exception as exc:
        logger.error(
            f"Failed to load actions from {actions_path}: {exc}"
        )

        logger.debug(
            "Traceback while loading actions:\n%s",
            traceback.format_exc(),
        )

    return actions


def get_configured_hardware_types(sensor_node_settings: Dict[str, Any]) -> Set[str]:
    """
    Extract configured hardware types from sensor node settings.

    Returns a set like:
    {"USRP B20xmini", "802.11x Adapter"}
    """
    hw_types: set[str] = set()

    try:
        hardware = sensor_node_settings.get("Sensor Node", {}).get("hardware", {})

        # SDRs
        for _, sdr_cfg in (hardware.get("sdrs") or {}).items():
            if isinstance(sdr_cfg, dict):
                hw_type = sdr_cfg.get("type")
                if hw_type:
                    hw_types.add(hw_type)

        # Wi-Fi adapters
        wifi_adapters = hardware.get("wifi_adapters") or {}
        if wifi_adapters:
            hw_types.add("802.11x Adapter")

        # Optional: always present logical hardware
        hw_types.add("Computer")

    except Exception:
        pass

    return hw_types


def _load_plugin_actions_module(
    plugin_name: str,
    *,
    module_name: str = "",
):
    """Load one plugin's actions.py module."""
    actions_path = os.path.join(
        PLUGIN_DIR,
        plugin_name,
        "actions.py",
    )

    if not os.path.isfile(
        actions_path
    ):
        return None

    safe_plugin_name = (
        str(plugin_name)
        .replace("-", "_")
        .replace(" ", "_")
    )

    resolved_module_name = (
        module_name
        or f"{safe_plugin_name}_actions_delegate"
    )

    spec = (
        importlib.util.spec_from_file_location(
            resolved_module_name,
            actions_path,
        )
    )

    if (
        spec is None
        or spec.loader is None
    ):
        raise ImportError(
            f"Cannot load module spec for {actions_path}"
        )

    module = (
        importlib.util.module_from_spec(
            spec
        )
    )

    spec.loader.exec_module(
        module
    )

    return module


def _make_delegated_action(
    destination_module_name: str,
    source_plugin: str,
    action_name: str,
    source_action,
):
    """Create one coroutine wrapper around a source-plugin action."""
    async def delegated_action(
        component,
        parameters,
        node_uid: str = "",
    ) -> None:
        component.logger.info(
            f"Delegating action {action_name} to {source_plugin}"
        )

        await source_action(
            component,
            parameters,
            node_uid,
        )

    delegated_action.__name__ = (
        action_name
    )

    delegated_action.__qualname__ = (
        action_name
    )

    # Required by get_plugin_actions(), which intentionally ignores imported
    # coroutine functions from other modules.
    delegated_action.__module__ = (
        destination_module_name
    )

    delegated_action.__doc__ = (
        f"Delegate {action_name} to the "
        f"{source_plugin} plugin."
    )

    return delegated_action


def register_delegated_actions(
    namespace: Dict[str, Any],
    delegated_actions: Dict[str, str],
    logger: logging.Logger = logging.getLogger(__name__),
) -> None:
    """
    Register source-plugin actions in another plugin's actions.py namespace.

    Example
    -------
    DELEGATED_ACTIONS = {
        "iq_record": "Base",
        "dummy_alert": "Dummy",
    }

    ACTION_TAGS = {}
    ACTION_HARDWARE = {}

    register_delegated_actions(
        globals(),
        DELEGATED_ACTIONS,
    )

    For each delegated action this automatically inherits:
    - the source action coroutine behavior;
    - <action_name>_schema when present;
    - ACTION_TAGS when present;
    - ACTION_HARDWARE when present.

    Missing source plugins are skipped so unavailable dependencies are not
    advertised. A source plugin that exists but does not contain the named
    action is treated as a configuration error.
    """
    if not isinstance(
        namespace,
        dict,
    ):
        raise TypeError(
            "namespace must be a module globals dictionary"
        )

    if not isinstance(
        delegated_actions,
        dict,
    ):
        raise TypeError(
            "delegated_actions must be a dictionary"
        )

    destination_module_name = str(
        namespace.get(
            "__name__",
            "",
        )
        or ""
    ).strip()

    if not destination_module_name:
        raise ValueError(
            "Destination module namespace is missing __name__"
        )

    action_tags = namespace.setdefault(
        "ACTION_TAGS",
        {},
    )

    action_hardware = namespace.setdefault(
        "ACTION_HARDWARE",
        {},
    )

    if not isinstance(
        action_tags,
        dict,
    ):
        raise TypeError(
            "ACTION_TAGS must be a dictionary"
        )

    if not isinstance(
        action_hardware,
        dict,
    ):
        raise TypeError(
            "ACTION_HARDWARE must be a dictionary"
        )

    loaded_modules = {}

    for (
        action_name,
        source_plugin,
    ) in delegated_actions.items():
        action_name = str(
            action_name
            or ""
        ).strip()

        source_plugin = str(
            source_plugin
            or ""
        ).strip()

        if (
            not action_name
            or not source_plugin
        ):
            raise ValueError(
                "Delegated action names and source plugins "
                "must be non-empty strings"
            )

        source_module = (
            loaded_modules.get(
                source_plugin
            )
        )

        if source_module is None:
            source_module = (
                _load_plugin_actions_module(
                    source_plugin,
                    module_name=(
                        f"{destination_module_name}"
                        f"_source_"
                        f"{source_plugin}"
                        f"_actions"
                    ).replace(
                        "-",
                        "_",
                    ).replace(
                        " ",
                        "_",
                    ),
                )
            )

            if source_module is None:
                logger.warning(
                    "Skipping delegated action "
                    f"{action_name}: source plugin "
                    f"{source_plugin} is unavailable"
                )
                continue

            loaded_modules[
                source_plugin
            ] = source_module

        source_action = getattr(
            source_module,
            action_name,
            None,
        )

        if not inspect.iscoroutinefunction(
            source_action
        ):
            raise AttributeError(
                f"{source_plugin} does not provide "
                f"async action {action_name}"
            )

        namespace[
            action_name
        ] = _make_delegated_action(
            destination_module_name,
            source_plugin,
            action_name,
            source_action,
        )

        schema_name = (
            f"{action_name}_schema"
        )

        source_schema = getattr(
            source_module,
            schema_name,
            None,
        )

        if isinstance(
            source_schema,
            dict,
        ):
            namespace[
                schema_name
            ] = copy.deepcopy(
                source_schema
            )

        source_tags = getattr(
            source_module,
            "ACTION_TAGS",
            {},
        ) or {}

        if (
            isinstance(
                source_tags,
                dict,
            )
            and action_name in source_tags
        ):
            action_tags[
                action_name
            ] = copy.deepcopy(
                source_tags[
                    action_name
                ]
            )

        source_hardware = getattr(
            source_module,
            "ACTION_HARDWARE",
            {},
        ) or {}

        if (
            isinstance(
                source_hardware,
                dict,
            )
            and action_name in source_hardware
        ):
            action_hardware[
                action_name
            ] = copy.deepcopy(
                source_hardware[
                    action_name
                ]
            )


# def apply_csv_to_table(conn:connection, file: str, function: object):
#     """Apply CSV Rows to PostgreSQL Table

#     Parameters
#     ----------
#     conn : connection
#         Database connection
#     file : str
#         CSV file
#     function : object
#         Function to apply changes
#     """
#     with open(file, 'r') as f:
#         reader = csv.reader(f,dialect='unix',quotechar="'")
#         for row in reader:
#             _ = function(conn, *row[1:])


def get_action_schema(plugin: str, action_name: str,
                      logger: logging.getLogger = logging.getLogger(__name__)) -> dict:
    """
    Get Action Schema

    Looks for a variable named:  <action_name>_schema  inside the plugin's actions.py
    Example: promote_to_soi_schema = {"params": [...]}

    Returns {"params": []} if not found or on failure.
    """
    actions_path = os.path.join(PLUGIN_DIR, plugin, "actions.py")

    if not os.path.exists(actions_path):
        return {"params": []}

    try:
        # Use a unique module name to reduce collisions if multiple plugins are loaded
        spec = importlib.util.spec_from_file_location(f"{plugin}_actions", actions_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load module spec for {actions_path}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        schema_attr = f"{action_name}_schema"
        schema = getattr(module, schema_attr, None)

        if isinstance(schema, dict):
            # Minimal sanity check: must have params list if present
            params = schema.get("params", [])
            if isinstance(params, list):
                return schema

        return {"params": []}

    except Exception as e:
        logger.error(f"Failed to load action schema from {actions_path}: {e}")
        logger.debug("Traceback while loading schema:\n%s", traceback.format_exc())
        return {"params": []}


def get_actions_for_classifications(
    plugin: str,
    classification_candidates: List[str],
    logger: logging.Logger = logging.getLogger(__name__),
    requester_type: str = "",
    node_location: str = "",
) -> List[str]:
    """
    Load ACTION_TAGS from a plugin and return classification-matching actions
    that are also allowed for the current client/node context.

    Classification matching remains unchanged:
    - "All" matches every classification;
    - otherwise any matching classification tag is sufficient.

    client.* and node.* capability namespaces are then applied separately.
    """
    actions_path = os.path.join(
        PLUGIN_DIR,
        plugin,
        "actions.py",
    )

    if not os.path.exists(
        actions_path
    ):
        logger.error(
            f"Actions file does not exist: {actions_path}"
        )
        return []

    try:
        spec = (
            importlib.util.spec_from_file_location(
                f"{plugin}_actions",
                actions_path,
            )
        )

        if (
            spec is None
            or spec.loader is None
        ):
            raise ImportError(
                f"Cannot load module spec for {actions_path}"
            )

        module = (
            importlib.util.module_from_spec(
                spec
            )
        )

        spec.loader.exec_module(
            module
        )

        action_tags = getattr(
            module,
            "ACTION_TAGS",
            None,
        )

        if not isinstance(
            action_tags,
            dict,
        ):
            logger.warning(
                "No valid ACTION_TAGS dictionary found in "
                f"{actions_path}"
            )
            return []

        candidates = {
            str(candidate).strip()
            for candidate
            in (
                classification_candidates
                or []
            )
            if candidate is not None
            and str(candidate).strip()
        }

        matched = []

        for action_name, tags in action_tags.items():
            if not isinstance(
                action_name,
                str,
            ):
                continue

            normalized_tags = (
                _normalize_action_tags(
                    tags
                )
            )

            if (
                "All" not in normalized_tags
                and candidates.isdisjoint(
                    normalized_tags
                )
            ):
                continue

            if not action_tags_allow_context(
                normalized_tags,
                requester_type=(
                    requester_type
                ),
                node_location=(
                    node_location
                ),
            ):
                continue

            matched.append(
                action_name
            )

        return sorted(
            matched
        )

    except Exception as exc:
        logger.error(
            "Failed to load action tags from "
            f"{actions_path}: {exc}"
        )

        logger.debug(
            "Traceback while loading action tags:\n%s",
            traceback.format_exc(),
        )

        return []