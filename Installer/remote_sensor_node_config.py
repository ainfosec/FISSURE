"""Prepare the installed Sensor Node configuration for remote deployment."""

from ipaddress import IPv4Address, ip_address
from pathlib import Path
from typing import Any

import yaml


LOOPBACK_NAMES = {"", "ipc", "localhost"}


class ConfigPreparationError(RuntimeError):
    """Raised when a usable remote Sensor Node configuration cannot be made."""


def prepare_remote_config(
    source: Path,
    destination: Path,
    connection: Any,
) -> Path:
    config = _load_config(source)
    node = config.get("Sensor Node")
    if not isinstance(node, dict):
        raise ConfigPreparationError("Sensor Node configuration is missing")

    network_type = str(node.get("network_type", "")).strip()
    configured_address = str(node.get("hiprfisr_ip_address", "")).strip()
    if network_type != "IP" or _is_remote_address(configured_address):
        return source

    hub_address = _connection_ipv4_address(connection)
    node["hiprfisr_ip_address"] = hub_address
    destination.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    destination.chmod(0o600)
    print(f"[*] Staged Sensor Node config uses HIPRFISR address {hub_address}")
    return destination


def _load_config(source: Path) -> dict[str, Any]:
    try:
        with source.open(encoding="utf-8") as config_file:
            config = yaml.safe_load(config_file)
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigPreparationError(f"Unable to read Sensor Node YAML: {exc}") from exc
    if not isinstance(config, dict):
        raise ConfigPreparationError("Sensor Node YAML must contain a mapping")
    return config


def _is_remote_address(value: str) -> bool:
    if value.lower() in LOOPBACK_NAMES:
        return False
    try:
        address = ip_address(value)
    except ValueError:
        return True
    return not (address.is_loopback or address.is_unspecified)


def _connection_ipv4_address(connection: Any) -> str:
    sockname = connection.get_extra_info("sockname")
    if not isinstance(sockname, (tuple, list)) or not sockname:
        raise ConfigPreparationError("SSH connection did not report its local address")

    try:
        address = ip_address(str(sockname[0]))
    except ValueError as exc:
        raise ConfigPreparationError(
            f"SSH connection reported an invalid local address: {sockname[0]!r}"
        ) from exc
    if not isinstance(address, IPv4Address) or address.is_loopback or address.is_unspecified:
        raise ConfigPreparationError(
            "Could not derive a reachable IPv4 HIPRFISR address; use --config"
        )
    return str(address)
