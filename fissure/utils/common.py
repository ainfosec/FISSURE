from typing import Any, Dict, Optional, Tuple

import distro
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


FISSURE_CONFIG_FILE = "fissure_config.yaml"
FISSURE_CONFIG_DEFAULT = os.path.join("User Configs", "default.yaml")
LOG_CONFIG_FILE = "logging.yaml"

OS_3_8_KEYWORDS = ["DragonOS Focal", "Ubuntu 20.04"]
OS_3_10_KEYWORDS = ["Ubuntu 22.04", "Kali", "DragonOS FocalX", "Raspberry Pi OS", "Parrot"]

QTERMINAL_LIST = ["DragonOS Focal", "DragonOS FocalX", "Kali"]
LXTERMINAL_LIST = ["Raspberry Pi OS"]
GNOME_TERMINAL_LIST = ["Ubuntu 20.04", "Ubuntu 22.04", "Parrot"]


class FissureUtilObjects:
    config: Dict = None
    zmq_ctx: zmq.asyncio.Context = None
    zmq_authenticator: zmq.auth.asyncio.AsyncioAuthenticator = None


__vars = FissureUtilObjects()


def init_logging():
    """Configure Logging"""
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

    return logging.getLogger(source.lower())


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


def zmq_cleanup():  # pragma: no cover
    """
    Clean up ZMQ Context and stop the Authenticator
    """
    logger: logging.Logger = logging.getLogger("fissure")
    logger.debug("Cleaning Up ZMQ Context")
    if __vars.zmq_authenticator is not None:
        __vars.zmq_authenticator.stop()

        del __vars.zmq_authenticator
        __vars.zmq_authenticator = None

    if __vars.zmq_ctx is not None:
        # __vars.zmq_ctx.destroy(linger=0)

        del __vars.zmq_ctx
        __vars.zmq_ctx = None


def load_library(os_info: str) -> Optional[Dict]:
    """
    Loads the library.yaml file for the operating system. Libraries will be combined into a shared database in the future.

    :param os_info: result of get_os_info()
    :type os_info: str
    :return: dictionary representation of settings from the YAML file
    :rtype: Optional[Dict]
    """
    # Choose File Based on Operating System
    if any(keyword == os_info for keyword in OS_3_8_KEYWORDS):
        library_file = "library_3_8.yaml"
    elif any(keyword == os_info for keyword in OS_3_10_KEYWORDS):
        library_file = "library_3_10.yaml"
    else:
        logger: logging.Logger = logging.getLogger("fissure")
        logger.warning("Operating system not detected while loading library. Loading GNU Radio 3.10 library.")
        library_file = "library_3_10.yaml"

    # Load the Library
    settings = None
    with open(os.path.join(YAML_DIR, library_file), "r") as yaml_file:
        settings = yaml.load(yaml_file, yaml.FullLoader)
    return settings


def save_library(library_dict: Dict, os_info: str):
    """
    Saves the library.yaml file for the operating system. Libraries will be combined into a shared database in the future.
    :param library_dict: library dictionary to save to file
    :type library_dict: Dict
    :param os_info: result of get_os_info()
    :type os_info: str
    """
    # Choose File Based on Operating System
    if any(keyword == os_info for keyword in OS_3_8_KEYWORDS):
        library_file = "library_3_8.yaml"
    elif any(keyword == os_info for keyword in OS_3_10_KEYWORDS):
        library_file = "library_3_10.yaml"
    else:
        logger: logging.Logger = logging.getLogger("fissure")
        logger.warning("Operating system not detected while saving library. Saving to GNU Radio 3.10 library.")
        library_file = "library_3_10.yaml"

    # Save the Library
    stream = open(os.path.join(YAML_DIR, library_file), "w")
    yaml.dump(library_dict, stream, default_flow_style=False, indent=5)


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
    
    # DragonOS Focal
    proc = subprocess.Popen("lsb_release -d 2>&1 | grep 'DragonOS Focal$'", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()
    if len(output) > 0:
        return "DragonOS Focal"

    # DragonOS FocalX
    proc = subprocess.Popen("cat /etc/os-dragonos 2>&1 | grep 'DragonOS FocalX'", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()
    if len(output) > 0:
        return "DragonOS FocalX"
    
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
    