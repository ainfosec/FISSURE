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
    Presence of a namespace requires an exact context match.
    """
    normalized_tags = _normalize_action_tags(
        tags
    )

    client_tags = {
        tag
        for tag in normalized_tags
        if tag.startswith(
            "client."
        )
    }

    if client_tags:
        requester_tag = (
            _requester_type_action_tag(
                requester_type
            )
        )

        if (
            not requester_tag
            or requester_tag not in client_tags
        ):
            return False

    node_tags = {
        tag
        for tag in normalized_tags
        if tag.startswith(
            "node."
        )
    }

    if node_tags:
        node_tag = (
            _node_location_action_tag(
                node_location
            )
        )

        if (
            not node_tag
            or node_tag not in node_tags
        ):
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


# def modify_database(logger: logging.getLogger=logging.getLogger(__name__), plugin_names:List[str] = None, action:str='add'):
#     """Modify PostgreSQL Database

#     Modify tables in the PostgreSQL database using rows in CSV files. Expected tables are in `fissure.utils.plugins.TABLES_FUNCTIONS`.

#     Parameters
#     ----------
#     conn : connection
#         Database connection
#     paths : str
#         Path(s) to csv files
#     action : str, optional
#         Action to apply from set {'add', 'remove'}, by default 'add'

#     Raises
#     ------
#     RuntimeError
#         _description_
#     """
#     # Parse Action
#     if action.lower() == 'add':
#         fcn_idx = 1
#     elif action.lower() == 'remove':
#         fcn_idx = 2
#     else:
#         logger.error('`action` must be in set {"add", "remove"}')

#     for plugin_name in plugin_names:
#         # Apply Changes to Database
#         conn = openDatabaseConnection()
#         try:
#             for functions in TABLES_FUNCTIONS:
#                 apply_csv_to_table(conn, os.path.join(PLUGIN_DIR, plugin_name, 'tables/', functions[0]), functions[fcn_idx])
#         except:
#             logger.error('Failure to apply action "' + str(action) + '" to the database for plugin ' + str(plugin_name))
#         finally:
#             conn.close()


# def install(plugin: str):
#     """Install Plugin

#     Copies files from the `PLUGIN_DIR`/`plugin`/install_files directory into the main FISSURE file structure.

#     Parameters
#     ----------
#     plugin : str
#         Plugin name
#     """
#     # Copy flow graph library files into directory
#     # Get install files directory path
#     install_files = os.path.join(PLUGIN_DIR, plugin, 'install_files')

#     # Copy Files to FISSURE Directories
#     shutil.copytree(install_files, FISSURE_ROOT, symlinks=True, dirs_exist_ok=True)


# def installed(plugin: str) -> bool:
#     """Check if Plugin is Installed

#     Parameters
#     ----------
#     plugin : str
#         Plugin name

#     Returns
#     -------
#     bool
#         True if files within FISSURE match plugin files, False otherwise
#     """
#     if os.path.exists(os.path.join(PLUGIN_DIR, plugin)):
#         return _installed(os.path.join(PLUGIN_DIR, plugin, 'install_files'), FISSURE_ROOT)
#     else:
#         return False


# def _installed(path1: os.PathLike, path2: os.PathLike) -> bool:
#     """Recursive Installed File Check

#     Intended to be used with `installed`. `path1` is the baseline for files expected to be in `path2` to meet installed criteria.

#     Parameters
#     ----------
#     path1 : os.PathLike
#         Baseline path
#     path2 : os.PathLike
#         Target path

#     Returns
#     -------
#     bool
#         True if files and file structure of `path1` are within `path2`, False otherwise
#     """
#     path1_list = os.listdir(path1)
#     path2_list = os.listdir(path2)
#     for item in path1_list:
#         path1_path = os.path.join(path1, item)
#         path2_path = os.path.join(path2, item)
#         if not item in path2_list:
#             # Item Path not in path2
#             return False
#         elif os.path.isdir(path1_path):
#             # Item is a Directory
#             if not os.path.isdir(path2_path):
#                 # Item is not a Directory in path2
#                 return False
#             elif not _installed(path1_path, path2_path):
#                 # Recursive Search Found Differences
#                 return False
#         else:
#             # path1 Item is a File
#             if not filecmp.cmp(path1_path, path2_path):
#                 # Files Fail Comparison
#                 return False

#     return True


# def uninstall(plugin: str):
#     """Uninstall Plugin

#     Removes files in the main FISSURE file structure that are identified based on files in the `plugin_path`/install_files directory.

#     **WARNING:** No name mangling is used. If a file is the same as one in FISSURE or another plugin it will be removed.

#     Parameters
#     ----------
#     plugin : str
#         Plugin name
#     """
#     plugin_path = os.path.join(PLUGIN_DIR, plugin, 'install_files')
#     if os.path.exists(plugin_path):
#         _uninstall(plugin_path, FISSURE_ROOT)


# def _uninstall(path1: os.PathLike, path2: os.PathLike):
#     """Recursive Uninstall Plugin Function

#     Intended to be used with `uninstall`. `path1` is the baseline for files expected to be uninstalled from `path2`.

#     Parameters
#     ----------
#     path1 : os.PathLike
#         Baseline path
#     path2 : os.PathLike
#         Target path
#     """
#     path1_list = os.listdir(path1)
#     for item in path1_list:
#         path1_path = os.path.join(path1, item)
#         path2_path = os.path.join(path2, item)
#         if os.path.isdir(path1_path) and os.path.isdir(path2_path):
#             if _uninstall(path1_path, path2_path):
#                 os.rmdir(path2_path)
#         elif os.path.exists(path2_path):
#             if filecmp.cmp(path1_path, path2_path):
#                 os.remove(path2_path)
#     return len(os.listdir(path2)) == 0 # indicate if directory is empty


# def remove(plugin: str):
#     """Remove Plugin from File System

#     **WARNING:** No name mangling is used. If a file is the same as one in FISSURE or another plugin it will be removed.

#     Parameters
#     ----------
#     plugin : str
#         Plugin name
#     """
#     plugin_path = os.path.join(PLUGIN_DIR, plugin)
#     if os.path.exists(plugin_path):
#         uninstall(plugin)
#         shutil.rmtree(os.path.join(PLUGIN_DIR, plugin))


# def install_to_database(plugin: str):
#     """Plugin to install to the database

#     Parameters
#     ----------
#     plugin : str
#         Plugin name
#     """
#     plugin_path = os.path.join(PLUGIN_DIR, plugin)
#     run(['python', os.path.join(plugin_path, 'installer.py'), '-i'])


# def remove_from_database(plugin: str):
#     """Plugin to remove from the database

#     Parameters
#     ----------
#     plugin : str
#         Plugin name
#     """
#     plugin_path = os.path.join(PLUGIN_DIR, plugin)
#     run(['python', os.path.join(plugin_path, 'installer.py'), '-u'])


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