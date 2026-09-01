from typing import Any, Dict, Optional, Tuple

#import distro
import logging
import logging.config
import os
import socket
import time
import yaml
import zmq
import zmq.asyncio
import zmq.auth
import zmq.auth.asyncio
import subprocess
import re
import mgrs
import math

FISSURE_ROOT: os.PathLike = os.path.abspath(os.path.join(__file__, "..", "..", ".."))
LOG_DIR: os.PathLike = os.path.join(FISSURE_ROOT, "Logs")
YAML_DIR: os.PathLike = os.path.join(FISSURE_ROOT, "YAML")
UI_DIR: os.PathLike = os.path.join(FISSURE_ROOT, "UI")
CERT_DIR: os.PathLike = os.path.join(FISSURE_ROOT, "certificates")
FLOW_GRAPH_LIBRARY_3_8: os.PathLike = os.path.join(FISSURE_ROOT, "Flow Graph Library", "maint-3.8")
FLOW_GRAPH_LIBRARY_3_10: os.PathLike = os.path.join(FISSURE_ROOT, "Flow Graph Library", "maint-3.10")
TOOLS_DIR: os.PathLike = os.path.join(FISSURE_ROOT, "Tools")
USER_CONFIGS_DIR: os.PathLike = os.path.join(FISSURE_ROOT, "YAML", "User Configs")
ARCHIVE_DIR: os.PathLike = os.path.join(FISSURE_ROOT, "Archive")
IQ_RECORDINGS_DIR: os.PathLike = os.path.join(FISSURE_ROOT, "IQ Recordings")
SENSOR_NODE_DIR: os.PathLike = os.path.join(FISSURE_ROOT, "fissure", "Sensor_Node")
GALLERY_DIR: os.PathLike = os.path.join(FISSURE_ROOT, "docs", "Gallery")
CLASSIFIER_DIR: os.PathLike = os.path.join(FISSURE_ROOT, "Classifier")
PLUGIN_DIR: os.PathLike = os.path.join(FISSURE_ROOT, "Plugins")
HUB_ARTIFACTS_DIR: os.PathLike = os.path.join(FISSURE_ROOT, "artifacts")


FISSURE_CONFIG_FILE = os.path.join(YAML_DIR, "fissure_config.yaml")
FISSURE_CONFIG_DEFAULT = os.path.join(YAML_DIR, "User Configs", "default.yaml")
LOG_CONFIG_FILE = "logging.yaml"

OS_3_8_KEYWORDS = ["Ubuntu 20.04"]
OS_3_10_KEYWORDS = ["Ubuntu 22.04", "Kali", "DragonOS", "Raspberry Pi OS", "Parrot", "Ubuntu 24.04"]

QTERMINAL_LIST = ["DragonOS", "Kali"]
LXTERMINAL_LIST = ["Raspberry Pi OS"]
GNOME_TERMINAL_LIST = ["Ubuntu 20.04", "Ubuntu 22.04", "Parrot", "Ubuntu 24.04"]

DATABASE_TABLE_HEADERS = {
    "archive_collection": ["id", "name", "file_list", "filepath", "files", "format", "size", "notes", "parent_id", "created_at"],
    "archive_favorites": ["id", "file_name", "date", "format", "modulation", "notes", "protocol", "sample_rate", "samples", "size", "tuned_frequency"],
    "attack_categories": ["id", "category_name", "parent"],
    "attacks": ["id", "protocol", "attack_name", "modulation_type", "hardware", "attack_type", "filename", "category_name", "version"],
    "conditioner_flow_graphs": ["id", "isolation_category", "isolation_method", "hardware", "file_type", "data_type", "version", "parameter_names", "parameter_values", "parameter_labels", "filepath"],
    "demodulation_flow_graphs": ["id", "protocol", "modulation_type", "hardware", "filename", "output_type", "version"],
    "detector_flow_graphs": ["id", "detector_type", "hardware", "filename", "file_type", "version"],
    "inspection_flow_graphs": ["id", "hardware", "python_file", "version"],
    "modulation_types": ["id", "protocol", "modulation_type"],
    "packet_types": ["id", "protocol", "packet_name", "dissector", "fields", "sort_order"],
    "protocols": ["id", "protocol_name", "data_rates", "median_packet_lengths"],
    "soi_data": ["id", "protocol", "soi_name", "center_frequency", "start_frequency", "end_frequency", "bandwidth", "continuous", "modulation", "notes"],
    "triggers": ["id", "category", "trigger_name", "default_settings", "filename", "file_type", "version"]
}

# Commands Banned from Logging the Parameters Values in Console and File (messages with a lot of data)
BANNED_MESSAGE_NAMES = [
    "demodFG_LibrarySearchReturn",
    "findEntropyReturn",
    "findPreamblesReturn",
    "overwriteDefaultAutorunPlaylist",
    "pdBitsReturn",
    "recallSettingsReturn",
    "retrieveDatabaseCacheReturn",
    "retrieveDatabaseCacheReturnPD",
    "saveFile",
    "searchLibraryReturn",
    "sliceByPreambleReturn",
    "transferSensorNodeFile",
]


class FissureUtilObjects:
    config: Dict = None
    zmq_ctx: zmq.asyncio.Context = None
    zmq_authenticator: zmq.auth.asyncio.AsyncioAuthenticator = None


__vars = FissureUtilObjects()


def init_logging():
    """
    Configure Logging
    """
    # Create the log directory if it doesn't already exist
    if not os.path.exists(LOG_DIR):  # pragma: no cover
        os.mkdir(LOG_DIR)

    # Read logging config file
    config = load_yaml(LOG_CONFIG_FILE)
    for handler in config["handlers"]:
        handler_info = config["handlers"][handler]
        if handler_info.get("filename") is not None:
            logfile = os.path.join(FISSURE_ROOT, handler_info.get("filename"))
            config["handlers"][handler]["filename"] = logfile

    # Set Logging Config
    logging.config.dictConfig(config)

    # print("After dictConfig:")
    # for name, logger in logging.Logger.manager.loggerDict.items():
    #     if isinstance(logger, logging.Logger):
    #         print(f"Logger: {name}, Handlers: {logger.handlers}, Propagate: {logger.propagate}")


def get_logger(source: str) -> logging.Logger:
    """
    Get the requested logger, initializing it if necessary

    :param source: logger source
    :type source: str
    :return: logger object
    :rtype: logging.Logger
    """

    # Format logger name if it's not the root fissure logger
    if source != "fissure":
        source = f"fissure.{source.lower()}"
    
    logger = logging.getLogger(source.lower())

    return logger


def update_logging_levels(logger, new_console_level=None, new_file_level=None):
    """
    Update the logging levels for a FISSURE component.
    """
    level_mapping = {
        "DEBUG": 10,
        "INFO": 20,
        "WARNING": 30,
        "ERROR": 40,
    }

    # # Print initial handler levels
    # for handler in logger.handlers:
    #     print(f"Handler {type(handler).__name__} level before update: {handler.level}")

    if new_console_level is not None and new_console_level.strip():
        console_level = level_mapping.get(new_console_level.upper(), 20)
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setLevel(console_level)
    else:
        console_level = logger.level

    if new_file_level is not None and new_file_level.strip():
        file_level = level_mapping.get(new_file_level.upper(), 20)
        for handler in logger.handlers:
            if isinstance(handler, logging.FileHandler):
                handler.setLevel(file_level)
    else:
        file_level = logger.level

    logger.setLevel(min(console_level, file_level))

    # # Print final handler levels
    # for handler in logger.handlers:
    #     print(f"Handler {type(handler).__name__} level after update: {handler.level}")
    # print(f"Logger level after update: {logger.level}")


def get_fg_library_dir(os_info: str) -> str:
    """
    Returns the maint-3.8 or maint-3.10 flow graph library directory.

    :param os_info: result of get_os_info()
    :type os_info: str
    :return: flow graph library directory filepath
    :rtype: str
    """
    # Choose Filepath Based on Operating System
    if any(keyword == os_info for keyword in OS_3_8_KEYWORDS):
        return FLOW_GRAPH_LIBRARY_3_8
    elif any(keyword == os_info for keyword in OS_3_10_KEYWORDS):
        return FLOW_GRAPH_LIBRARY_3_10
    else:
        return FLOW_GRAPH_LIBRARY_3_10
    

def get_default_expect_terminal(os_info: str) -> str:
    """
    Returns qterminal, lxterminal, or gnome-terminal based on operating system.

    :param os_info: result of get_os_info()
    :type os_info: str
    :return: terminal type
    :rtype: str
    """
    # Choose Default Terminal Based on Operating System
    if any(keyword == os_info for keyword in GNOME_TERMINAL_LIST):
        return "gnome-terminal"
    elif any(keyword == os_info for keyword in QTERMINAL_LIST):
        return "qterminal"
    elif any(keyword == os_info for keyword in LXTERMINAL_LIST):
        return "lxterminal"
    else:
        return "gnome-terminal"


def get_zmq_context() -> zmq.asyncio.Context:
    """
    :return: ZMQ Context
    :rtype: zmq.Context
    """
    if __vars.zmq_ctx is None:
        __vars.zmq_ctx = zmq.asyncio.Context()
    return __vars.zmq_ctx


def get_authenticator(allowed_keys: str = None) -> zmq.auth.asyncio.AsyncioAuthenticator:
    """
    :return: the ZMQ Authenticator
    :rtype: zmq.auth.asyncio.AsyncioAuthenticator
    """
    if __vars.zmq_authenticator is None:
        __vars.zmq_authenticator = zmq.auth.asyncio.AsyncioAuthenticator(context=__vars.zmq_ctx)
        __vars.zmq_authenticator.start()
        __vars.zmq_authenticator.allow()
        __vars.zmq_authenticator.configure_curve(domain=zmq.auth.CURVE_ALLOW_ANY, location=allowed_keys)
    return __vars.zmq_authenticator


def authenticator_cleanup():
    """
    """
    auth = get_authenticator()
    if auth is not None:
        try:
            auth.stop()
        except:
            pass


def zmq_cleanup():
    # Stop the authenticator if it exists
    try:
        if __vars.zmq_authenticator is not None:
            __vars.zmq_authenticator.stop()
            __vars.zmq_authenticator = None
    except Exception:
        pass

    # Destroy ZMQ context if it exists
    try:
        if __vars.zmq_ctx is not None:
            __vars.zmq_ctx.destroy(linger=0)
            __vars.zmq_ctx = None
    except Exception:
        pass


    # For Brute Forcing Socket Close:
    # import gc
    # print("ZMQ cleanup starting")

    # raw_sockets = set()
    # async_sockets = set()

    # # Collect sockets
    # for obj in gc.get_objects():
    #     try:
    #         if isinstance(obj, zmq.asyncio.Socket):
    #             async_sockets.add(obj)
    #         elif isinstance(obj, zmq.Socket):
    #             raw_sockets.add(obj)
    #     except:
    #         pass

    # print("\n=== SOCKETS BEFORE CLOSE ===")
    # for s in async_sockets:
    #     print("ASYNC SOCKET:", s, "closed=", s.closed)
    # for s in raw_sockets:
    #     print("RAW SOCKET:", s, "closed=", s.closed)

    # # 1) Close asyncio wrappers AND their underlying raw sockets
    # print("\nClosing async sockets:")
    # for s in async_sockets:
    #     try:
    #         if hasattr(s, "socket"):
    #             try:
    #                 print("  closing underlying raw:", s.socket)
    #                 s.socket.close(linger=0)
    #             except Exception as e:
    #                 print("    raw close error:", e)
    #         print("  closing async:", s)
    #         s.close(linger=0)
    #     except Exception as e:
    #         print("  async close error:", e)

    # # 2) Close any raw sockets not already closed
    # print("\nClosing raw sockets:")
    # for s in raw_sockets:
    #     if not s.closed:
    #         try:
    #             print("  closing:", s)
    #             s.close(linger=0)
    #         except Exception as e:
    #             print("  raw close error:", e)

    # # 3) Now destroy context
    # try:
    #     __vars.zmq_ctx.destroy(linger=0)
    #     print("Context destroyed.")
    # except Exception as e:
    #     print("Destroy error:", e)


def load_yaml(filename: str) -> Optional[Dict]:
    """
    Loads the settings from a YAML file and stores them in a dictionary

    :param filename: path to YAML file containing settings
    :type filename: str
    :return: dictionary representation of settings from the YAML file
    :rtype: Optional[Dict]
    """
    settings = None
    with open(os.path.join(YAML_DIR, filename), "r") as yaml_file:
        settings = yaml.load(yaml_file, yaml.FullLoader)
    return settings


def save_yaml(filename: str, data: Any):
    """
    Saves the settings to a YAML file

    :param filename: filename to dump settings to
    :type filename: str
    :param data: settings data to dump to file
    :type data: Any
    """
    logger: logging.Logger = logging.getLogger("fissure")
    stream = open(os.path.join(YAML_DIR, filename), "w")
    yaml.dump(data, stream)
    logger.debug(f"configuation file updated (YAML/{filename})")


def get_fissure_config() -> Dict:
    logger: logging.Logger = logging.getLogger("fissure")

    if __vars.config is None:
        __vars.config = load_yaml(FISSURE_CONFIG_FILE)
        remember = __vars.config.get("remember_configuration")
        if not remember:
            __vars.config = load_yaml(FISSURE_CONFIG_DEFAULT)
            logger.debug(f"loaded default config ({FISSURE_CONFIG_DEFAULT})")
        else:
            logger.debug(f"loaded fissure config ({FISSURE_CONFIG_FILE})")

    return __vars.config


def save_fissure_config(data: Dict):
    """
    If `remember_configuration` is set to `True`, store the configured settings,
    overwriting the `fissure_config.yaml` file.

    :param data: fissure configuration settings
    :type data: Dict
    """
    if data.get("remember_configuration") is True:
        save_yaml(FISSURE_CONFIG_FILE, data)


def get_timestamp(t: float = None) -> str:
    """
    :return: formatted UTC timestamp
    :rtype: str
    """
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def get_ip_address() -> str:
    """
    :return: IP Address
    :rtype: str
    """
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)


def get_os_info() -> Tuple[str, str, str]:
    """
    :return: Linux Distribution Info (name, version, codename)
    :rtype: tuple
    """
    # return distro.linux_distribution()  # Potentially use this method once values are collected
    # ('Ubuntu', '20.04', 'focal')
    
    # This method contains previously gathered values
    # Detect Operating System

    # Ubuntu 24.04
    proc = subprocess.Popen("lsb_release -d 2>&1 | grep 'Ubuntu 24.04'", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()
    if len(output) > 0:
        return "Ubuntu 24.04"
    
    # Ubuntu 22.04
    proc = subprocess.Popen("lsb_release -d 2>&1 | grep 'Ubuntu 22.04'", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()
    if len(output) > 0:
        return "Ubuntu 22.04"
    
    # Ubuntu 20.04
    proc = subprocess.Popen("lsb_release -d 2>&1 | grep 'Ubuntu 20.04'", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()
    if len(output) > 0:
        return "Ubuntu 20.04"
    
    # DragonOS
    proc = subprocess.Popen("cat /etc/os-dragonos 2>&1 | grep 'DragonOS'", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()
    if len(output) > 0:
        return "DragonOS"
    
    # Kali
    proc = subprocess.Popen("lsb_release -d 2>&1 | grep 'Kali'", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()
    if len(output) > 0:
        return "Kali"
    
    # Raspberry Pi OS
    proc = subprocess.Popen("lsb_release -d 2>&1 | grep 'bookworm'", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()
    if len(output) > 0:
        return "Raspberry Pi OS"
    
    # KDE Neon
    proc = subprocess.Popen("lsb_release -d 2>&1 | grep 'KDE Neon'", shell=True, stdout=subprocess.PIPE, )  # Test this
    output = proc.communicate()[0].decode()
    if len(output) > 0:
        return "Ubuntu 20.04"  # Same settings as Ubuntu 20.04
    
    # Parrot OS
    proc = subprocess.Popen("lsb_release -d 2>&1 | grep 'Parrot'", shell=True, stdout=subprocess.PIPE, )  # Parrot Security 6.1 (lorikeet)
    output = proc.communicate()[0].decode()
    if len(output) > 0:
        return "Parrot"
    
    # BackBox
    proc = subprocess.Popen("lsb_release -d 2>&1 | grep 'BackBox'", shell=True, stdout=subprocess.PIPE, )  # Test this
    output = proc.communicate()[0].decode()
    if len(output) > 0:
        return "Ubuntu 22.04"  # Same settings as Ubuntu 22.04


def isFloat(x):
    """
    Returns "True" if the input is a Float. Returns "False" otherwise.
    """
    # Check Value
    try:
        float(x)
    except ValueError:
        return False
    return True


def safe_float(value, default=None):
    """
    Convert a value to float without raising.

    Useful for message payloads where values may be None, empty strings,
    numeric strings, or already numeric.
    """
    if value is None:
        return default

    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_bool(value, default=False):
    """
    Convert common bool-like payload values to bool without treating every
    non-empty string as True.
    """
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        return bool(value)

    if isinstance(value, str):
        value = value.strip().lower()

        if value in {"true", "1", "yes", "y", "on", "enabled"}:
            return True

        if value in {"false", "0", "no", "n", "off", "disabled"}:
            return False

    return default


def updateCRC(crc_poly, crc_acc, crc_input, crc_length):
    """
    Calculates CRC for bytes. Used in multiple tabs. Move this function somewhere else?
    """
    # 8-bit CRC
    if crc_length == 8:
        # Convert Hex Byte String to int
        crc_input_int = int(crc_input, 16)
        crc_acc_int = int(crc_acc, 16)
        crc_acc_int = crc_acc_int ^ crc_input_int
        for _ in range(8):
            crc_acc_int <<= 1
            if crc_acc_int & 0x0100:
                crc_acc_int ^= crc_poly
            # crc &= 0xFF

        # Convert to Hex String
        crc_acc = ("%0.2X" % crc_acc_int)[-2:]

    # 16-bit CRC
    elif crc_length == 16:
        # Convert Hex Byte String to int
        crc_input_int = int(crc_input, 16)
        crc_acc_int = int(crc_acc, 16)
        crc_acc_int = crc_acc_int ^ (crc_input_int << 8)
        for i in range(0, 8):
            if (crc_acc_int & 32768) == 32768:
                crc_acc_int = crc_acc_int << 1
                crc_acc_int = crc_acc_int ^ crc_poly
            else:
                crc_acc_int = crc_acc_int << 1

        # Convert to Hex String
        crc_acc = "%0.4X" % crc_acc_int

        # Keep Only the Last 2 Bytes
        crc_acc = crc_acc[-4:]

    # 32-bit CRC
    elif crc_length == 32:
        crc_input_int = int(crc_input, 16)
        crc_acc = crc_acc ^ crc_input_int
        for _ in range(0, 8):
            mask = -(crc_acc & 1)
            crc_acc = (crc_acc >> 1) ^ (crc_poly & mask)

    return crc_acc


def get_library_version():
    """
    Returns the library version for flow graphs and scripts stored in the database based on operating system.
    """
    # Return Value by Operating System
    os_info = get_os_info()
    if os_info in OS_3_8_KEYWORDS:
        return "maint-3.8"
    elif os_info in OS_3_10_KEYWORDS:
        return "maint-3.10"


def extractFrequencyFromUID(uid: str):
    """
    Extracts a frequency from a UID such as:
        FTN-ALERT-311MHz
        HACKRF-433_MHz
        SENSOR-908mhz
        ANYTHING-2412

    Returns a frequency string suitable for classifyFrequencyFromTextDirect(),
    such as "311 MHz" or "908.4 MHz", or None if not found.
    """

    import re

    # Normalize UID for easier parsing
    text = uid.replace("_", " ").replace("-", " ")

    # Look for number + optional decimal + optional unit
    m = re.search(r"(\d+(\.\d+)?)\s*(MHz|mhz|kHz|khz|Hz|hz)?", text)
    if not m:
        return None

    value_str = m.group(1)
    unit = (m.group(3) or "").lower()

    # If no explicit unit was found, assume MHz for values < 10,000
    if not unit:
        if float(value_str) < 10000:
            unit = "mhz"
        else:
            unit = "hz"

    # Normalize unit capitalization and spacing
    unit_map = {
        "mhz": "MHz",
        "khz": "kHz",
        "hz": "Hz",
    }

    unit_str = unit_map.get(unit, "MHz")  # default to MHz if unknown

    # Build a frequency string consumable by classifyFrequencyFromTextDirect
    return f"{value_str} {unit_str}"


############################################# GPS Functions ####################################################

def format_coordinates(lat, lon, format_type):
    if format_type == "DD":  # Decimal Degrees
        return f"{lat:.6f}, {lon:.6f}"  # Ensure full precision
    elif format_type == "MGRS":
        return mgrs.MGRS().toMGRS(lat, lon)
    elif format_type == "DMS":
        return decimal_to_dms(lat, lon)
    return "Invalid format."


def parse_nmea(nmea_sentence):
    """
    Parses an NMEA sentence (e.g., $GPGGA) and extracts latitude and longitude.
    """
    parts = nmea_sentence.strip().split(',')

    if parts[0] not in ["$GPGGA", "$GPRMC"]:  # Ensure it's a valid GPS sentence
        return None, None

    try:
        # Extract latitude
        lat_raw = parts[2]
        lat_dir = parts[3]  # N or S
        lon_raw = parts[4]
        lon_dir = parts[5]  # E or W

        # Convert to Decimal Degrees
        lat = convert_to_decimal(lat_raw, lat_dir)
        lon = convert_to_decimal(lon_raw, lon_dir)

        return lat, lon
    except (IndexError, ValueError):
        return None, None


def convert_to_decimal(degrees_minutes, direction):
    """
    Converts NMEA latitude/longitude format to decimal degrees.
    """
    if not degrees_minutes:
        return None

    # NMEA format: DDMM.MMMM (degrees and minutes)
    degrees = int(degrees_minutes[:2])  # First 2 digits are degrees
    minutes = float(degrees_minutes[2:])  # Rest are minutes

    decimal_degrees = degrees + (minutes / 60)

    # South and West are negative
    if direction in ['S', 'W']:
        decimal_degrees *= -1

    return decimal_degrees


def mgrs_to_dd(mgrs_coord):
    """
    Convert MGRS to Decimal Degrees (DD)
    """
    m = mgrs.MGRS()
    lat, lon = m.toLatLon(mgrs_coord)
    return lat, lon


def dms_to_dd(dms_str):
    """
    Converts Degrees, Minutes, Seconds (DMS) format to Decimal Degrees (DD).
    Supports various spacing and delimiters.
    """
    # Improved regex pattern to match different DMS formats
    pattern = re.compile(r"""
        (\d+)[°\s]+      # Degrees (D° or D )
        (\d+)['′\s]+     # Minutes (M' or M )
        ([\d.]+)?        # Seconds (S.S" or S.S, optional)
        ["″]?\s*([NS])   # N/S hemisphere
        [, ]+\s*         # Separator between lat/lon
        (\d+)[°\s]+      # Degrees (D° or D )
        (\d+)['′\s]+     # Minutes (M' or M )
        ([\d.]+)?        # Seconds (S.S" or S.S, optional)
        ["″]?\s*([EW])   # E/W hemisphere
    """, re.VERBOSE)

    match = pattern.match(dms_str)

    if not match:
        raise ValueError(f"Invalid DMS format: {dms_str}")

    lat_d, lat_m, lat_s, lat_dir, lon_d, lon_m, lon_s, lon_dir = match.groups()

    # Convert to Decimal Degrees
    lat_dd = int(lat_d) + int(lat_m) / 60 + (float(lat_s) if lat_s else 0) / 3600
    lon_dd = int(lon_d) + int(lon_m) / 60 + (float(lon_s) if lon_s else 0) / 3600

    # Apply hemisphere corrections
    if lat_dir == "S":
        lat_dd *= -1
    if lon_dir == "W":
        lon_dd *= -1

    return lat_dd, lon_dd


def decimal_to_dms(lat, lon):
    """
    Converts latitude and longitude from Decimal Degrees (DD) to Degrees, Minutes, Seconds (DMS).
    """
    def convert(coord):
        degrees = int(coord)
        minutes = int((abs(coord) - abs(degrees)) * 60)
        seconds = (abs(coord) - abs(degrees) - minutes / 60) * 3600
        return degrees, minutes, seconds

    # Convert latitude and longitude
    lat_d, lat_m, lat_s = convert(lat)
    lon_d, lon_m, lon_s = convert(lon)

    # Determine N/S and E/W
    lat_dir = "N" if lat >= 0 else "S"
    lon_dir = "E" if lon >= 0 else "W"

    # Format output
    return f"{abs(lat_d)}°{lat_m}'{lat_s:.2f}\" {lat_dir}, {abs(lon_d)}°{lon_m}'{lon_s:.2f}\" {lon_dir}"


def decimal_to_ddm(lat:float, lon:float) -> Tuple[str]:
    """
    Converts latitude and longitude from Decimal Degrees (DD) to Degrees, Decimal Minutes.

    Output is in the form [D]DDMM.MMMMN (degrees, decimal minutes and direction).
    """
    def convert(coord):
        degrees = int(coord)
        minutes = (abs(coord) - abs(degrees)) * 60
        return degrees, minutes

    # Convert latitude and longitude
    lat_d, lat_m = convert(lat)
    lon_d, lon_m = convert(lon)

    # Determine N/S and E/W
    lat_dir = "N" if lat >= 0 else "S"
    lon_dir = "E" if lon >= 0 else "W"

    # Format output
    return f"{abs(lat_d)}{lat_m:07.4f}{lat_dir}", f"{abs(lon_d)}{lon_m:07.4f}{lon_dir}"


def is_valid_lat_lon(lat, lon):
    """Return True if lat/lon look usable."""
    try:
        lat = float(lat)
        lon = float(lon)
    except (TypeError, ValueError):
        return False

    return -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0


def haversine_m(lat1, lon1, lat2, lon2):
    """
    Great-circle distance between two points in meters.
    """
    r_earth_m = 6371000.0

    lat1_rad = math.radians(float(lat1))
    lon1_rad = math.radians(float(lon1))
    lat2_rad = math.radians(float(lat2))
    lon2_rad = math.radians(float(lon2))

    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad

    a = (
        math.sin(dlat / 2.0) ** 2
        + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))

    return r_earth_m * c


def get_nearest_nodes_to_target(component, target, max_nodes=3):
    """
    Find up to max_nodes closest registered nodes to a target location.

    Returns
    -------
    list[dict]
        Each item contains:
            {
                "uid": <node uid>,
                "distance_m": <float>,
                "lat": <float>,
                "lon": <float>,
                "alt": <float|None>,
                "status": <str>,
                "connected": <bool>,
                "identity": <any>,
                "nickname": <str|None>,
                "callsign": <str|None>,
            }
    """
    location = target.get("location") or {}
    target_lat = location.get("lat")
    target_lon = location.get("lon")

    if not is_valid_lat_lon(target_lat, target_lon):
        return []

    candidates = []

    for node_uid, node in component.nodes.items():
        node_lat = node.get("lat")
        node_lon = node.get("lon")

        if not is_valid_lat_lon(node_lat, node_lon):
            continue

        # Optional: skip disconnected nodes if that fits your use case
        # If you want "registered nodes" regardless of current link state,
        # remove this block.
        if not node.get("connected", False):
            continue

        try:
            distance_m = haversine_m(target_lat, target_lon, node_lat, node_lon)
        except Exception:
            continue

        candidates.append({
            "uid": node_uid,
            "distance_m": distance_m,
            "lat": float(node_lat),
            "lon": float(node_lon),
            "alt": node.get("alt"),
            "status": node.get("status", "unknown"),
            "connected": node.get("connected", False),
            "identity": node.get("identity"),
            "nickname": node.get("nickname"),
            "callsign": node.get("callsign"),
        })

    candidates.sort(key=lambda x: x["distance_m"])
    return candidates[:max_nodes]


##################################################################################################