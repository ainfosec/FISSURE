import os
from typing import Any, Dict, List, Tuple


LISTENING_POST_TYPES = (
    "Meshtastic",
    "ZMQ SUB",
    "Website Poller",
    "Serial Port",
    "TCP/UDP",
    "Filesystem",
    "MQTT",
)


LISTENING_POST_FIELDS = {
    "Meshtastic": [
        {
            "name": "serial_port",
            "label": "Serial Port",
            "kind": "text",
            "default": "/dev/ttyUSB0",
        },
    ],
    "ZMQ SUB": [
        {
            "name": "ip_address",
            "label": "IP Address",
            "kind": "text",
            "default": "localhost",
        },
        {
            "name": "port",
            "label": "Port",
            "kind": "text",
            "default": "55555",
        },
        {
            "name": "topic_filter",
            "label": "Topic Filter",
            "kind": "text",
            "default": "alerts",
        },
    ],
    "Website Poller": [
        {
            "name": "url",
            "label": "URL",
            "kind": "text",
            "default": "http://localhost:8080",
        },
        {
            "name": "check_interval",
            "label": "Check Interval (s)",
            "kind": "text",
            "default": "60",
        },
    ],
    "Serial Port": [
        {
            "name": "serial_port",
            "label": "Serial Port",
            "kind": "text",
            "default": "/dev/ttyUSB0",
        },
        {
            "name": "baud_rate",
            "label": "Baud Rate",
            "kind": "text",
            "default": "9600",
        },
    ],
    "TCP/UDP": [
        {
            "name": "protocol",
            "label": "Protocol",
            "kind": "choice",
            "choices": ["TCP", "UDP"],
            "default": "TCP",
        },
        {
            "name": "ip_address",
            "label": "Bind Address",
            "kind": "text",
            "default": "0.0.0.0",
        },
        {
            "name": "port",
            "label": "Port",
            "kind": "text",
            "default": "55555",
        },
    ],
    "Filesystem": [
        {
            "name": "mode",
            "label": "Watch Mode",
            "kind": "choice",
            "choices": ["New Files", "File Changes"],
            "default": "New Files",
        },
        {
            "name": "folder",
            "label": "Folder",
            "kind": "folder",
            "default": "",
            "show_when": ("mode", "New Files"),
        },
        {
            "name": "file_pattern",
            "label": "File Pattern",
            "kind": "text",
            "default": "*.txt",
            "show_when": ("mode", "New Files"),
        },
        {
            "name": "filepath",
            "label": "File Path",
            "kind": "file",
            "default": "",
            "show_when": ("mode", "File Changes"),
        },
    ],
    "MQTT": [
        {
            "name": "broker_address",
            "label": "Broker Address",
            "kind": "text",
            "default": "localhost",
        },
        {
            "name": "port",
            "label": "Port",
            "kind": "text",
            "default": "1883",
        },
        {
            "name": "topic",
            "label": "Topic",
            "kind": "text",
            "default": "fissure/alerts",
        },
        {
            "name": "username",
            "label": "Username",
            "kind": "text",
            "default": "",
        },
        {
            "name": "password",
            "label": "Password",
            "kind": "password",
            "default": "",
        },
    ],
}


def listening_post_fields(post_type: str) -> List[Dict[str, Any]]:
    """Return a copy of the UI/runtime field description for one post type."""
    return [dict(field) for field in LISTENING_POST_FIELDS.get(post_type, [])]


def default_parameters(post_type: str) -> Dict[str, str]:
    """Return default parameters for one supported Listening Post type."""
    return {
        field["name"]: str(field.get("default", ""))
        for field in listening_post_fields(post_type)
    }


def _require_text(parameters: dict, key: str, label: str) -> str:
    value = str(parameters.get(key, "") or "").strip()
    if not value:
        raise ValueError(f"{label} is required.")
    return value


def _validate_port(parameters: dict, key="port") -> str:
    raw = _require_text(parameters, key, "Port")
    try:
        port = int(raw)
    except ValueError:
        raise ValueError("Port must be an integer.")
    if port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535.")
    return str(port)


def _validate_positive_int(parameters: dict, key: str, label: str) -> str:
    raw = _require_text(parameters, key, label)
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{label} must be an integer.")
    if value <= 0:
        raise ValueError(f"{label} must be greater than zero.")
    return str(value)


def normalize_listening_post_definition(definition: dict) -> Dict[str, Any]:
    """Validate and normalize one persisted Listening Post definition."""
    if not isinstance(definition, dict):
        raise ValueError("Listening Post definition must be a mapping.")

    post_id = str(definition.get("id", "") or "").strip()
    name = str(definition.get("name", "") or "").strip()
    post_type = str(definition.get("type", "") or "").strip()
    host = str(definition.get("host", "hiprfisr") or "hiprfisr").strip().lower()
    autostart_raw = definition.get("autostart", False)
    if isinstance(autostart_raw, str):
        autostart = autostart_raw.strip().lower() in {"1", "true", "yes", "on"}
    else:
        autostart = bool(autostart_raw)
    parameters = definition.get("parameters", {}) or {}

    if not name:
        raise ValueError("Listening Post name is required.")
    if post_type not in LISTENING_POST_TYPES:
        raise ValueError(f"Unsupported Listening Post type: {post_type}")
    if host != "hiprfisr":
        raise ValueError("This release supports HIPRFISR-hosted Listening Posts only.")
    if not isinstance(parameters, dict):
        raise ValueError("Listening Post parameters must be a mapping.")

    normalized = default_parameters(post_type)
    for key, value in parameters.items():
        normalized[str(key)] = "" if value is None else str(value)

    if post_type == "Meshtastic":
        normalized["serial_port"] = _require_text(normalized, "serial_port", "Serial Port")
        normalized.pop("baud_rate", None)

    elif post_type == "ZMQ SUB":
        normalized["ip_address"] = _require_text(normalized, "ip_address", "IP Address")
        normalized["port"] = _validate_port(normalized)
        normalized["topic_filter"] = str(normalized.get("topic_filter", "") or "")

    elif post_type == "Website Poller":
        normalized["url"] = _require_text(normalized, "url", "URL")
        normalized["check_interval"] = _validate_positive_int(
            normalized,
            "check_interval",
            "Check Interval",
        )

    elif post_type == "Serial Port":
        normalized["serial_port"] = _require_text(normalized, "serial_port", "Serial Port")
        normalized["baud_rate"] = _validate_positive_int(normalized, "baud_rate", "Baud Rate")

    elif post_type == "TCP/UDP":
        protocol = str(normalized.get("protocol", "TCP") or "TCP").strip().upper()
        if protocol not in {"TCP", "UDP"}:
            raise ValueError("Protocol must be TCP or UDP.")
        normalized["protocol"] = protocol
        normalized["ip_address"] = _require_text(normalized, "ip_address", "Bind Address")
        normalized["port"] = _validate_port(normalized)

    elif post_type == "Filesystem":
        mode = str(normalized.get("mode", "New Files") or "New Files").strip()
        if mode not in {"New Files", "File Changes"}:
            raise ValueError("Filesystem Watch Mode must be New Files or File Changes.")
        normalized["mode"] = mode

        if mode == "New Files":
            normalized["folder"] = _require_text(normalized, "folder", "Folder")
            normalized["file_pattern"] = str(
                normalized.get("file_pattern", "*.txt") or "*.txt"
            ).strip() or "*.txt"
            normalized["filepath"] = ""
        else:
            normalized["filepath"] = _require_text(normalized, "filepath", "File Path")
            normalized["folder"] = ""
            normalized["file_pattern"] = ""

    elif post_type == "MQTT":
        normalized["broker_address"] = _require_text(
            normalized,
            "broker_address",
            "Broker Address",
        )
        normalized["port"] = _validate_port(normalized)
        normalized["topic"] = _require_text(normalized, "topic", "Topic")
        normalized["username"] = str(normalized.get("username", "") or "")
        normalized["password"] = str(normalized.get("password", "") or "")

    return {
        "id": post_id,
        "name": name,
        "type": post_type,
        "host": "hiprfisr",
        "autostart": autostart,
        "parameters": normalized,
    }


def endpoint_summary(definition: dict) -> str:
    """Build the compact Endpoint column text for one Listening Post."""
    post_type = str(definition.get("type", "") or "")
    parameters = definition.get("parameters", {}) or {}

    if post_type == "Meshtastic":
        return str(parameters.get("serial_port", "") or "")

    if post_type == "ZMQ SUB":
        address = str(parameters.get("ip_address", "") or "")
        port = str(parameters.get("port", "") or "")
        topic = str(parameters.get("topic_filter", "") or "")
        endpoint = f"tcp://{address}:{port}"
        return f"{endpoint} / {topic}" if topic else endpoint

    if post_type == "Website Poller":
        return str(parameters.get("url", "") or "")

    if post_type == "Serial Port":
        serial_port = str(parameters.get("serial_port", "") or "")
        baud_rate = str(parameters.get("baud_rate", "") or "")
        return f"{serial_port} @ {baud_rate}" if baud_rate else serial_port

    if post_type == "TCP/UDP":
        protocol = str(parameters.get("protocol", "TCP") or "TCP").upper()
        address = str(parameters.get("ip_address", "") or "")
        port = str(parameters.get("port", "") or "")
        return f"{protocol} {address}:{port}"

    if post_type == "Filesystem":
        mode = str(parameters.get("mode", "New Files") or "New Files")
        if mode == "File Changes":
            return str(parameters.get("filepath", "") or "")
        folder = str(parameters.get("folder", "") or "")
        pattern = str(parameters.get("file_pattern", "") or "")
        if folder and pattern:
            return os.path.join(folder, pattern)
        return folder or pattern

    if post_type == "MQTT":
        broker = str(parameters.get("broker_address", "") or "")
        port = str(parameters.get("port", "") or "")
        topic = str(parameters.get("topic", "") or "")
        endpoint = f"{broker}:{port}" if port else broker
        return f"{endpoint} / {topic}" if topic else endpoint

    return ""
