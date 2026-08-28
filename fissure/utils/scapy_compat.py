"""Compatibility helpers for Scapy runtimes used by FISSURE.

This module intentionally uses feature detection instead of Scapy version checks.
The Dashboard and Sensor Node can therefore normalize differences between older
and newer Scapy installations without spreading compatibility branches through
the UI code.
"""

import ast
import importlib
import os


SCAPY_AVAILABLE = False
SCAPY_IMPORT_ERROR = ""
SCAPY_VERSION = "unknown"

_scapy = None
_scapy_all = None
_conf = None
Packet = object
NoPayload = object


try:
    _scapy = importlib.import_module("scapy")
    _scapy_all = importlib.import_module("scapy.all")
    packet_module = importlib.import_module("scapy.packet")

    Packet = getattr(packet_module, "Packet", object)
    NoPayload = getattr(packet_module, "NoPayload", object)
    _conf = getattr(_scapy_all, "conf", None)

    SCAPY_VERSION = str(getattr(_scapy, "__version__", "unknown") or "unknown")
    SCAPY_AVAILABLE = True
except Exception as exc:
    SCAPY_IMPORT_ERROR = str(exc)


CORE_LAYER_NAMES = (
    "Ether",
    "ARP",
    "IP",
    "IPv6",
    "ICMP",
    "TCP",
    "UDP",
    "Raw",
    "RadioTap",
    "Dot11",
    "Dot11Beacon",
    "Dot11Deauth",
    "Dot11Disas",
    "Dot11Auth",
    "Dot11AssoReq",
    "Dot11AssoResp",
    "Dot11ProbeReq",
    "Dot11ProbeResp",
    "Dot11Elt",
    "LLC",
    "SNAP",
    "Dot15d4",
    "ZigbeeNWK",
    "ZigbeeAppDataPayload",
)


def is_available():
    return bool(SCAPY_AVAILABLE)


def import_error():
    return SCAPY_IMPORT_ERROR


def version():
    return SCAPY_VERSION


def get_conf():
    return _conf


def _is_packet_class(value):
    if not isinstance(value, type):
        return False

    try:
        return Packet is not object and issubclass(value, Packet)
    except Exception:
        return False


def _walk_packet_subclasses():
    if Packet is object:
        return []

    results = []
    seen = set()
    pending = list(getattr(Packet, "__subclasses__", lambda: [])())

    while pending:
        layer_class = pending.pop()

        if layer_class in seen:
            continue

        seen.add(layer_class)
        results.append(layer_class)

        try:
            pending.extend(layer_class.__subclasses__())
        except Exception:
            pass

    return results


def get_layer_classes():
    """Return packet classes available in this Scapy runtime."""
    if not SCAPY_AVAILABLE:
        return []

    classes = []
    seen = set()

    registry = getattr(_conf, "layers", None)
    if registry is not None:
        try:
            registry_classes = list(registry)
        except Exception:
            registry_classes = []

        for layer_class in registry_classes:
            if _is_packet_class(layer_class) and layer_class not in seen:
                seen.add(layer_class)
                classes.append(layer_class)

    for layer_class in _walk_packet_subclasses():
        if _is_packet_class(layer_class) and layer_class not in seen:
            seen.add(layer_class)
            classes.append(layer_class)

    for layer_name in CORE_LAYER_NAMES:
        layer_class = getattr(_scapy_all, layer_name, None)
        if _is_packet_class(layer_class) and layer_class not in seen:
            seen.add(layer_class)
            classes.append(layer_class)

    return classes


def get_layer_class(name):
    """Return one packet layer class by name, or None if unavailable."""
    if not SCAPY_AVAILABLE:
        return None

    layer_class = getattr(_scapy_all, str(name or ""), None)
    if _is_packet_class(layer_class):
        return layer_class

    wanted = str(name or "").strip().lower()
    for candidate in get_layer_classes():
        if str(getattr(candidate, "__name__", "") or "").strip().lower() == wanted:
            return candidate

    return None


def packet_to_layers(packet):
    """Split a Scapy packet into standalone layer instances."""
    if Packet is object or packet is None:
        return []

    layers = []
    current = packet

    while isinstance(current, Packet) and not isinstance(current, NoPayload):
        standalone = current.copy()

        try:
            standalone.remove_payload()
        except Exception:
            try:
                standalone.payload = NoPayload()
            except Exception:
                pass

        layers.append(standalone)
        current = getattr(current, "payload", None)

    return layers


def packet_bytes(packet):
    return bytes(packet)


def packet_command(packet):
    command_method = getattr(packet, "command", None)
    if callable(command_method):
        return str(command_method())

    return repr(packet)


def field_enum_values(field):
    enum_values = getattr(field, "i2s", None)

    if not isinstance(enum_values, dict):
        enum_values = getattr(getattr(field, "fld", None), "i2s", None)

    return enum_values if isinstance(enum_values, dict) else {}


def field_flag_options(field):
    """Return (bit_mask, display_name) pairs for a Scapy FlagsField."""
    base_field = getattr(field, "fld", field)
    class_name = base_field.__class__.__name__.lower()

    if "flagsfield" not in class_name:
        return []

    names = getattr(base_field, "names", None)
    if names is None:
        return []

    options = []

    if isinstance(names, str):
        for bit_index, name in enumerate(names):
            name = str(name or "").strip()
            if name:
                options.append((1 << bit_index, name))
        return options

    if isinstance(names, (list, tuple)):
        for bit_index, name in enumerate(names):
            name = str(name or "").strip()
            if name:
                options.append((1 << bit_index, name))
        return options

    if isinstance(names, dict):
        numeric_items = []

        for key, name in names.items():
            try:
                numeric_key = int(key)
            except Exception:
                return []

            if isinstance(name, (dict, list, tuple, set)):
                return []

            name = str(name or "").strip()
            if name:
                numeric_items.append((numeric_key, name))

        if not numeric_items:
            return []

        keys = [key for key, _name in numeric_items]
        keys_are_masks = (
            0 not in keys
            and all(key > 0 and (key & (key - 1)) == 0 for key in keys)
        )

        for key, name in sorted(numeric_items, key=lambda item: item[0]):
            mask = key if keys_are_masks else 1 << key
            options.append((mask, name))

    return options


def field_type_name(field):
    base_field = getattr(field, "fld", field)
    type_name = base_field.__class__.__name__

    if type_name.endswith("Field"):
        type_name = type_name[:-5]

    return type_name


def field_length(field):
    base_field = getattr(field, "fld", field)
    size = getattr(base_field, "sz", None)

    if isinstance(size, (int, float)):
        if float(size).is_integer():
            return str(int(size))
        return str(size)

    return "—"


def field_display_text(field, layer, value):
    if value is None:
        return ""

    if isinstance(value, bytes):
        try:
            decoded = value.decode("utf-8")
            if decoded.isprintable():
                return decoded
        except Exception:
            pass

        return "0x" + value.hex()

    renderer = getattr(field, "i2repr", None)
    if callable(renderer):
        try:
            rendered = renderer(layer, value)
            if rendered is not None:
                return str(rendered)
        except Exception:
            pass

    return str(value)


def parse_field_text(field, layer, text):
    """Parse an edited field value using helpers available in this Scapy runtime."""
    text = str(text or "").strip()

    if text == "":
        return None

    base_field = getattr(field, "fld", field)
    class_name = base_field.__class__.__name__.lower()
    field_name = getattr(field, "name", getattr(base_field, "name", ""))

    if text.startswith(("b'", 'b"')):
        value = ast.literal_eval(text)
        if isinstance(value, bytes):
            return value

    current_value = None
    getfieldval = getattr(layer, "getfieldval", None)

    if callable(getfieldval):
        try:
            current_value = getfieldval(field_name)
        except Exception:
            pass

    if isinstance(current_value, bytes):
        if text.lower().startswith("0x"):
            return bytes.fromhex(text[2:].replace(" ", ""))
        return text.encode("utf-8")

    numeric_tokens = (
        "byte",
        "short",
        "int",
        "long",
        "bit",
        "xbyte",
        "xshort",
        "xint",
        "xlong",
    )

    if any(token in class_name for token in numeric_tokens) and "str" not in class_name:
        return int(text, 0)

    converter = getattr(field, "any2i", None)
    if callable(converter):
        try:
            return converter(layer, text)
        except Exception:
            pass

    return text


def _safe_interface_call(function_name, interface_name):
    if _scapy_all is None:
        return ""

    function = getattr(_scapy_all, function_name, None)
    if not callable(function):
        return ""

    try:
        return str(function(interface_name) or "").strip()
    except Exception:
        return ""


def _classify_interface(name):
    if name == "lo":
        return "Loopback"

    sysfs_path = os.path.join("/sys/class/net", name)

    try:
        with open(os.path.join(sysfs_path, "type"), "r", encoding="utf-8") as handle:
            link_type = int(handle.read().strip())

        if link_type == 803:
            return "Wireless (Monitor)"

        if link_type in (801, 802):
            return "Wireless"
    except Exception:
        pass

    if os.path.isdir(os.path.join(sysfs_path, "wireless")):
        return "Wireless"

    virtual_prefixes = (
        "br-",
        "docker",
        "veth",
        "virbr",
        "vmnet",
        "tun",
        "tap",
        "tailscale",
        "zt",
    )

    if name.startswith(virtual_prefixes):
        return "Virtual"

    try:
        if "/virtual/" in os.path.realpath(sysfs_path):
            return "Virtual"
    except Exception:
        pass

    return "Wired"


def _driver_name(name):
    try:
        driver_link = os.path.join("/sys/class/net", name, "device", "driver")

        if os.path.islink(driver_link):
            return os.path.basename(os.path.realpath(driver_link))
    except Exception:
        pass

    return ""


def _interface_sort_order(interface_type):
    order = {
        "Wired": 0,
        "Wireless": 1,
        "Wireless (Monitor)": 2,
        "Virtual": 3,
        "Loopback": 4,
    }

    return order.get(interface_type, 5)


def get_interfaces():
    """Return normalized interface rows across old and new Scapy APIs."""
    if not SCAPY_AVAILABLE:
        return []

    metadata_by_name = {}
    interface_names = []

    ifaces = getattr(_conf, "ifaces", None)

    if ifaces is not None:
        reload_method = getattr(ifaces, "reload", None)

        if callable(reload_method):
            try:
                reload_method()
            except Exception:
                pass

        try:
            interface_objects = list(ifaces.values())
        except Exception:
            try:
                interface_objects = list(ifaces)
            except Exception:
                interface_objects = []

        for interface in interface_objects:
            name = str(
                getattr(interface, "name", "")
                or getattr(interface, "network_name", "")
                or ""
            ).strip()

            if not name:
                continue

            interface_names.append(name)
            metadata_by_name[name] = {
                "description": str(getattr(interface, "description", "") or "").strip(),
                "ip": str(getattr(interface, "ip", "") or "").strip(),
                "mac": str(getattr(interface, "mac", "") or "").strip(),
            }

    get_if_list = getattr(_scapy_all, "get_if_list", None)

    if callable(get_if_list):
        try:
            interface_names.extend(str(name or "").strip() for name in get_if_list())
        except Exception:
            pass

    if not interface_names:
        try:
            interface_names.extend(sorted(os.listdir("/sys/class/net")))
        except Exception:
            pass

    results = []
    seen = set()

    for name in interface_names:
        name = str(name or "").strip()

        if not name or name in seen:
            continue

        seen.add(name)
        metadata = metadata_by_name.get(name, {})
        details = []

        description = str(metadata.get("description", "") or "").strip()
        if description and description != name:
            details.append(description)

        driver = _driver_name(name)
        if driver and driver not in details:
            details.append(driver)

        ip_address = str(metadata.get("ip", "") or "").strip()
        if not ip_address:
            ip_address = _safe_interface_call("get_if_addr", name)

        if ip_address and ip_address not in ("0.0.0.0", "::"):
            details.append(ip_address)

        mac_address = str(metadata.get("mac", "") or "").strip()
        if not mac_address:
            mac_address = _safe_interface_call("get_if_hwaddr", name)

        if mac_address and mac_address != "00:00:00:00:00:00":
            details.append(mac_address)

        results.append(
            {
                "name": name,
                "type": _classify_interface(name),
                "description": " | ".join(details),
            }
        )

    results.sort(
        key=lambda row: (
            _interface_sort_order(row["type"]),
            row["name"].lower(),
        )
    )

    return results
