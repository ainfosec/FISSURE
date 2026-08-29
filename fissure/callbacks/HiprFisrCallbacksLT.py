# from comms.FissureZMQNode import *
# from fissure.comms.constants import *
# from fissure_libutils import *
from typing import List

import binascii
import fissure.comms
import fissure.utils
import fissure.utils.library
from fissure.utils.common import PLUGIN_DIR
from fissure.utils import plugin
from fissure.utils import plugin_editor
import os
import time
import yaml
import asyncio
import socket
import shutil
from datetime import datetime, timezone
from fissure.Listeners import (
    MeshtasticListener,
    FilesystemListener,
    ZMQSubscriberListener,
    WebsitePollerListener,
    SerialPortListener,
    TCPUDPListener,
    MQTTListener
)


""" HiprFisr Specific Callback Functions """

# DELAY_SHORT = 0.25  # seconds

async def findGPS_CoordinatesLT(component: object, node_uid="", gps_source="", format=""):
    """
    Queries the remote sensor node for its GPS coordinates. 
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    PARAMETERS = {
        "gps_source": gps_source,
        "format": format
    }
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "findGPS_CoordinatesLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def findGPS_CoordinatesResultsLT(component: object, node_uid="", coordinates=""):
    """
    Forwards the GPS coordinate results message to the Dashboard.
    """
    PARAMETERS = {
        "coordinates": coordinates
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "findGPS_CoordinatesResultsLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def recallInfoMeshtasticReturnLT(component: object, node_uid="", nickname="", location="", notes="", source_id=None):
    """
    Returns the recalled sensor node settings to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {
        "nickname": nickname,
        "location": location,
        "notes": notes
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "recallInfoMeshtasticReturnLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    # Send First Connected Message
    node_uuid, node = component.resolve_uuid_from_assigned_id(source_id)
    component.nodes[node_uuid]["connected"] = True

    msg2 = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "componentConnected",
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg2)


async def recallHardwareMeshtasticReturnLT(component: object, tsi={}):
    """
    Returns the recalled sensor node settings to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"tsi": tsi}  # TODO
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "recallHardwareMeshtasticReturnLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)  # To Do


async def recallInfoMeshtasticLT(component: object, node_uid=""):
    """
    Recalls information from the sensor node config file.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "recallInfoMeshtasticLT",
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def recallHardwareMeshtasticLT(component: object, node_uid=""):
    """
    Recalls information from the sensor node config file.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "recallHardwareMeshtasticLT",
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def recallStatusMeshtasticLT(component: object, node_uid=""):
    """
    Recalls information from the sensor node config file.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "recallStatusMeshtasticLT",
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def recallStatusMeshtasticReturnLT(component: object, node_uid="", status=""):
    """
    Returns the recalled sensor node settings to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {
        "status": status,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "recallStatusMeshtasticReturnLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def scanHardwareLT(component: object, node_uid="", hardware_list=[]):
    """
    Sends a message to a sensor node to scan for hardware information.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    PARAMETERS = {
        "hardware_list": hardware_list
    }
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "scanHardwareLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def probeHardwareLT(component: object, node_uid, table_row_text):
    """
    Sends a message to a sensor node to probe select hardware.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    PARAMETERS = {
        "table_row_text": table_row_text
    }
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "probeHardwareLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def hardwareProbeResultsLT(component: object, node_uid="", output="", height_width=[]):
    """
    Forwards the hardware probe results message to the Dashboard.
    """
    PARAMETERS = {
        "output": output, 
        "height_width": height_width
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "hardwareProbeResultsLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def hardwareScanResultsLT(component: object, node_uid="", hardware_scan_results=[]):
    """
    Forwards the hardware scan results message to the Dashboard.
    """
    PARAMETERS = {
        "hardware_scan_results": hardware_scan_results
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "hardwareScanResultsLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def guessHardwareLT(component: object, node_uid="", table_row=0, table_row_text=[], guess_index=0):
    """
    Sends a message to a sensor node to guess details for select hardware.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    PARAMETERS = {
        "table_row": table_row,
        "table_row_text": table_row_text,
        "guess_index": guess_index,
    }
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "guessHardwareLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def hardwareGuessResultsLT(component: object, results=[]):
    """
    Forwards sensnor node hardware guess results from HIPRFISR to Dashboard.
    """
    PARAMETERS = {
        "table_row": results[0],
        "hardware_type": results[1],
        "scan_results": results[2],
        "new_guess_index": results[3],
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "hardwareGuessResultsLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def autorunPlaylistExecuteLT(component: object, node_uid="", playlist_filename=""):
    """
    Signals to sensor node to start autorun playlist already located on the sensor node.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    PARAMETERS = {
        "playlist_filename": playlist_filename
    }
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistExecuteLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def autorunPlaylistStopLT(component: object, node_uid=""):
    """
    Signals to sensor node to stop autorun playlist.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistStopLT",
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
    

async def alertReturnLT(component: object, node_uid="", alert_text=""):
    """Convert a compact Meshtastic Sensor Node alert into structured CoT."""
    raw_text = str(alert_text or "").strip()

    if "|" in raw_text:
        alert_kind, alert_summary = raw_text.split("|", 1)
        alert_kind = alert_kind.strip() or "plugin_alert"
        alert_summary = alert_summary.strip() or alert_kind
    else:
        alert_kind = "plugin_alert"
        alert_summary = raw_text or "Sensor Node alert"

    payload = {
        "msg_type": "event",
        "uid": f"lt-alert-{node_uid or 'unknown'}-{int(time.time() * 1000)}",
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "tak_icon": "b-t-f-r",
        "alert_kind": alert_kind,
        "alert_summary": alert_summary,
        "node_uid": str(node_uid or "").strip(),
        "suppress_point": True,
    }

    await fissure.utils.tak_messages.send(
        component,
        payload,
    )
    
    
# async def takPlotLT(component: object, msg=[]):
#     """
#     Forwards CoT messages to TAK.
#     """
#     uid = str(msg[0])
#     lat = float(msg[1])
#     lon = float(msg[2])
#     alt = float(msg[3])
#     time = str(msg[4])
#     remarks = str(msg[5])
#     type = str(msg[6]) if len(msg) > 6 else "a-f-G-U-H"

#     # TAK times must be ISO-like
#     time = time.replace(" ", "T")
    
#     # Apply callsign prefix
#     prefix = component.settings['callsign_prefix']
#     callsign = f"{prefix}-{uid}"
#     uid = callsign

#     # Classify based on frequency extracted from UID
#     try:
#         freq_text = fissure.utils.common.extractFrequencyFromUID(uid)
#         if freq_text:
#             classification_text = fissure.utils.library.classifyFrequencyFromTextDirect(freq_text)

#             # classification_text already looks like:
#             # [Protocol=... | Region=... | Priority=... | Notes=...]
#             if classification_text:
#                 remarks = f"{remarks}\n{classification_text}"

#     except Exception as e:
#         component.logger.error(f"Frequency classification error in takPlotLT: {e}")

#     # Forward to TAK
#     try:
#         # await component.send_cot(uid, callsign, lat, lon, alt, time, remarks, type)

#         # Get TAK server settings
#         settings: dict = fissure.utils.get_fissure_config()
#         s_addr = settings["tak"]["ip_addr"]
#         s_port = settings["tak"]["port"]
#         tak_cert = settings["tak"]["cert"]
#         tak_key = settings["tak"]["key"]

#         msg = {
#             "type": "pin",
#             "uid": uid,
#             "callsign": uid,
#             "lat": lat,
#             "lon": lon,
#             "alt": alt,
#             "remarks": remarks
#         }

#         await fissure.utils.tak_messages.send(component, msg)

#     except Exception as e:
#         component.logger.error(f"Error sending COT to TAK (LT): {e}")
#         # tb = traceback.format_exc()
#         # component.logger.debug(tb)


async def takReturnLT(component: object, msg=[]):
    """
    Meshtastic LT TAK return callback.

    msg schema:

        [0] msg_type : "track" | "event"
        [1] time     : ISO string
        [2] uid      : str
        [3] lat      : float | None
        [4] lon      : float | None
        [5] data     : dict  | None
        [6] status   : str
        [7] version  : str
    """
    try:
        if not isinstance(msg, list) or len(msg) < 6:
            return

        msg_type = msg[0]
        timestamp = msg[1]
        uid = msg[2]
        lat = msg[3]
        lon = msg[4]
        data = msg[5]
        status = msg[6]
        version = msg[7]

        if msg_type not in ("track", "event"):
            return

        if not uid:
            return

        if not timestamp:
            timestamp = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            )

        payload = {
            "msg_type": msg_type,
            "uid": str(uid),
            "time": str(timestamp).replace(" ", "T"),
        }

        # ----------------------------
        # TRACK
        # ----------------------------
        if msg_type == "track":
            if lat is None or lon is None:
                return

            payload.update({
                "lat": float(lat),
                "lon": float(lon),
                "alt": 0.0,
                "status": status,
                "version": version,
            })

        # ----------------------------
        # EVENT
        # ----------------------------
        elif msg_type == "event":
            if not isinstance(data, dict):
                return
            if "event_type" not in data:
                return

            payload["data"] = data

        await fissure.utils.tak_messages.send(component, payload)

    except Exception as e:
        try:
            fissure.utils.common.logger.error(f"takReturnLT failed: {e}")
        except Exception:
            pass

    
# async def takPlotGpsUpdateLT(component: object, msg=[]):
#     """
#     Forwards the GPS coordinate results message to TAK.
#     """
#     uid = str(msg[0])
#     lat = float(msg[1])
#     lon = float(msg[2])
#     alt = float(msg[3])
#     time = str(msg[4])
#     remarks = str(msg[5])

#     time = time.replace(" ", "T")

#     max_history = 5

#     # Reject if node is not registered yet
#     node = component.nodes.get(uid)
#     if node is None:
#         component.logger.warning(
#             f"Message 'takPlotGpsUpdateLT' from unknown uuid={uid}"
#         )
#         return

#     # Send to TAK  
#     prefix = component.settings['callsign_prefix']
#     callsign = component.nodes[uid].get('callsign', f"{prefix}-{uid[:8]}")

#     # await component.send_cot_gps_update(uid, callsign, lat, lon, alt, time, remarks, max_history)

#     # print("SEND TRACK")
#     # if not hasattr(component, "_test_lon"):
#     #    component._test_lon = lon   # initialize based on first call input
#     # component._test_lon += 1
#     # lon = component._test_lon

#     msg = {
#         "type": "track",
#         "uid": uid,              # IMPORTANT: must stay the same each update
#         "callsign": callsign,
#         "lat": lat,
#         "lon": lon,
#         "alt": alt,
#         # "cot_type": "b-m-p-w",       # optional override
#         # "stale": 60                    # 60 sec expiration window, or in the future: "2035-01-01T00:00:00Z"
#     }

#     await fissure.utils.tak_messages.send(component, msg)


async def gpsBeaconEnableMeshtasticLT(component: object, node_uid: str):
    """
    Signals to sensor node to enable the GPS TAK beacon.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    PARAMETERS = {}
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "gpsBeaconEnableMeshtasticLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def gpsBeaconDisableMeshtasticLT(component: object, node_uid: str):
    """
    Signals to sensor node to disable the GPS TAK beacon.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    PARAMETERS = {}
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "gpsBeaconDisableMeshtasticLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def rebootMeshtasticLT(component: object, node_uid: str):
    """
    Signals sensor node to reboot the computer.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    PARAMETERS = {}
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "rebootMeshtasticLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def uptimeMeshtasticLT(component: object, node_uid: str):
    """
    Signals sensor node to retrieve the uptime of the computer.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "uptimeMeshtasticLT",
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def uptimeMeshtasticReturnLT(component: object, node_uid: str, uptime: str):
    """
    Forwards uptimeMeshtasticReturnLT message to the Dashboard.
    """
    # Forward to Dashboard
    PARAMETERS = {
        "uptime": uptime,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "uptimeMeshtasticReturnLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def memoryMeshtasticLT(component: object, node_uid: str):
    """
    Signals sensor node to retrieve the memory usage of the computer.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "memoryMeshtasticLT",
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def memoryMeshtasticReturnLT(component: object, node_uid: str, memory: list):
    """
    Forwards memoryMeshtasticReturnLT message to the Dashboard.
    """
    # Forward to Dashboard
    PARAMETERS = {
        "memory": memory,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "memoryMeshtasticReturnLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def diskMeshtasticLT(component: object, node_uid: str):
    """
    Signals sensor node to retrieve the disk usage of the computer.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "diskMeshtasticLT",
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def diskMeshtasticReturnLT(component: object, node_uid: str, disk: dict):
    """
    Forwards diskMeshtasticReturnLT message to the Dashboard.
    """
    # Forward to Dashboard
    PARAMETERS = {
        "disk": disk,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "diskMeshtasticReturnLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def cpuMeshtasticLT(component: object, node_uid: str):
    """
    Signals sensor node to retrieve the CPU percentage of the computer.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "cpuMeshtasticLT",
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def cpuMeshtasticReturnLT(component: object, node_uid: str, cpu: str):
    """
    Forwards cpuMeshtasticReturnLT message to the Dashboard.
    """
    # Forward to Dashboard
    PARAMETERS = {
        "cpu": cpu,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "cpuMeshtasticReturnLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def processesMeshtasticLT(component: object, node_uid: str):
    """
    Signals sensor node to retrieve the processes on the computer.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "processesMeshtasticLT",
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def processesMeshtasticReturnLT(component: object, node_uid: str, processes: str):
    """
    Forwards processesMeshtasticReturnLT message to the Dashboard.
    """
    # Forward to Dashboard
    PARAMETERS = {
        "processes": processes,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "processesMeshtasticReturnLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def ifconfigMeshtasticLT(component: object, node_uid: str):
    """
    Signals sensor node to retrieve the ifconfig output on the computer.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "ifconfigMeshtasticLT",
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def ifconfigMeshtasticReturnLT(component: object, node_uid: str, ifconfig: str):
    """
    Forwards ifconfigMeshtasticReturnLT message to the Dashboard.
    """
    # Forward to Dashboard
    PARAMETERS = {
        "ifconfig": ifconfig,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "ifconfigMeshtasticReturnLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def iwconfigMeshtasticLT(component: object, node_uid: str):
    """
    Signals sensor node to retrieve the iwconfig output on the computer.
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "iwconfigMeshtasticLT",
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def iwconfigMeshtasticReturnLT(component: object, node_uid: str, iwconfig: str):
    """
    Forwards iwconfigMeshtasticReturnLT message to the Dashboard.
    """
    # Forward to Dashboard
    PARAMETERS = {
        "iwconfig": iwconfig,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "iwconfigMeshtasticReturnLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg) 


# async def recvMeshtasticHeartbeatsLT(component: object, assigned_id: str):
async def recvMeshtasticHeartbeatsLT(component: object, msg=[], source_id=None):
    """
    """
    # Ignore messages without a UUID
    if not source_id:
        return

    # Pass heartbeat info into update function
    assigned_id = str(msg[0])
    sn_int = float(msg[1])
    sn_nickname = str(msg[2])
    sn_time = float(msg[3])

    sn_uuid = source_id
    sn_ip = None
    sn_nettype = "Meshtastic"
    sn_id_zmq = None
    sn_assigned_id = assigned_id

    await component.node_heartbeat_updates(sn_time, sn_int, sn_uuid, sn_ip, sn_nickname, sn_nettype, sn_id_zmq, sn_assigned_id)


async def nodeSelectLT(component: object, dashboard_node_index, node_uuid):
    """
    """
    # Lookup identity for this UUID
    node_entry = component.nodes.get(node_uuid)
    if not node_entry:
        component.logger.error(f"[HIPRFISR] No such node_uuid {node_uuid}")
        return

    assigned_id = node_entry["assigned_id"]
    try:
        if not assigned_id or assigned_id <= 0:
            return
    except:
        return

    # Send Message to Node
    PARAMETERS = {
        "dashboard_node_index": dashboard_node_index,
    }
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "nodeSelectLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def nodeReconnectLT(component: object, dashboard_node_index: int):
    """
    """
    # Resolve Assigned ID
    assigned_id = component.nodes[node_uid].get("assigned_id", None)
    if not assigned_id or assigned_id <= 0:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Send Message to Node
    PARAMETERS = {
        "dashboard_node_index": dashboard_node_index,
    }
    msg = {
        fissure.comms.MessageFields.SOURCE: component.identifierLT,
        fissure.comms.MessageFields.DESTINATION: assigned_id,                
        fissure.comms.MessageFields.MESSAGE_NAME: "nodeSelectLT",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)