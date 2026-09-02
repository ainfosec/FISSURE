# from comms.FissureZMQNode import *
# from fissure.comms.constants import *
# from fissure_libutils import *
import pytak
from typing import List, Optional
import xml.etree.ElementTree as ET

import base64
import binascii
import json
import re
import fissure.comms
import fissure.utils
import fissure.utils.library
from fissure.utils.common import PLUGIN_DIR
from fissure.utils import plugin
from fissure.utils.artifacts import ArtifactTracker
import os
import time
import yaml
import asyncio
import socket
import shutil
import tempfile
import importlib
import traceback
import zmq
from datetime import datetime, timezone
import uuid


""" HiprFisr Specific Callback Functions """

DELAY_SHORT = 0.25  # seconds


##########################################################################
########################### For HIPRFISR #################################
##########################################################################

async def retrieveDatabaseCache(component: object, refresh_frontend_widgets=False):
    """
    Retrieves a copy of important database tables needed for operating the Dashboard.
    """
    # Retrieve the Database Cache
    database_return = fissure.utils.library.cacheTableData(source="Dashboard")

    # Return to the Dashboard (or other component?)
    PARAMETERS = {
        "database_return": database_return, 
        "refresh_frontend_widgets": refresh_frontend_widgets
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "retrieveDatabaseCacheReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def removeFromLibrary(
    component: object,
    table_name = "",
    row_id = "",
    delete_files = False
):
    """
    Removes a row from the library/database table.
    """
    # Maintain a Connection to the Database
    conn = fissure.utils.library.openDatabaseConnection()

    try:
        # Remove the Row/Files
        if (len(table_name) > 0) and (len(row_id) > 0):
            fissure.utils.library.removeFromTable(conn, table_name, row_id, delete_files, component.os_info)

        # Send Message to PD to Update Library
        await retrieveDatabaseCachePD(component)

        # Send Message to Dashboard to Update Library
        await retrieveDatabaseCache(component, True)
 
    except:
        component.logger.error("Failure removing data from the FISSURE library.")

    finally:
        conn.close()


async def shutdown(component: object, identifiers: List[str]):
    """
    Process `shutdown` commands

    :param identifier: Identifier of the fissure component to shutdown
    :type identifier: str
    """
    component.logger.info(f"received shutdown command for [{', '.join(identifiers)}]")
    for identifier in identifiers:
        if identifier == component.identifier:
            # component.shutdown = True  # before or after?

            # forward 'Shutdown' command to PD and TSI)
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: component.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: "shutdown",
                fissure.comms.MessageFields.PARAMETERS: {
                    fissure.comms.Parameters.IDENTIFIERS: [fissure.comms.Identifiers.PD, fissure.comms.Identifiers.TSI]
                },
            }
            await component.backend_router.send_msg(
                fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id, component.tsi_id]
            )

            # pd_running = True
            # tsi_running = True
            # while pd_running or tsi_running:
            #     msg = await component.backend_router.recv_msg()

            #     if msg is not None:
            #         msg_type = msg.get(fissure.comms.MessageFields.TYPE)
            #         msg_name = msg.get(fissure.comms.MessageFields.MESSAGE_NAME)
            #         sender = msg.get(fissure.comms.MessageFields.IDENTIFIER)
            #         if msg_type == fissure.comms.MessageTypes.STATUS and msg_name == "Shutting Down":
            #             if sender == fissure.comms.Identifiers.PD:
            #                 pd_running = False
            #             if sender == fissure.comms.Identifiers.TSI:
            #                 tsi_running = False
            component.shutdown = True
        else:
            # forward 'Shutdown' command to specified fissure component(s)
            pass


async def disconnect(component: object):
    ack = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "Disconnect OK",
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.STATUS, ack)
    component.logger.debug("Dashboard Disconnecting")
    component.dashboard_connected = False
    component.session_active = False
    component.heartbeats.update({fissure.comms.Identifiers.DASHBOARD: None})
    component.connect_loop = True


async def queryListeningPosts(
    component: object,
):
    """Return the authoritative HIPRFISR Listening Post inventory."""
    error = ""
    posts = []

    try:
        posts = (
            component
            .listening_post_manager
            .snapshot()
        )

    except Exception as exc:
        error = str(
            exc
        )

        component.logger.error(
            f"Could not query Listening Posts: {exc}"
        )

    PARAMETERS = {
        "posts": posts,
        "error": error,
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "queryListeningPostsReturn",
        fissure.comms.MessageFields.PARAMETERS:
            PARAMETERS,
    }

    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )


async def saveListeningPost(
    component: object,
    definition=None,
):
    """Create or update one stopped persisted Listening Post definition."""
    success = False
    message = ""
    post_id = ""

    try:
        post_id = (
            await component
            .listening_post_manager
            .create_or_update(
                definition
                or {}
            )
        )

        success = True
        message = "Listening Post saved."

    except Exception as exc:
        message = str(
            exc
        )

        component.logger.error(
            f"Could not save Listening Post: {exc}"
        )

    PARAMETERS = {
        "action": "save",
        "post_id": post_id,
        "success": success,
        "message": message,
        "posts": (
            component
            .listening_post_manager
            .snapshot()
        ),
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "listeningPostOperationReturn",
        fissure.comms.MessageFields.PARAMETERS:
            PARAMETERS,
    }

    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )


async def startListeningPost(
    component: object,
    post_id="",
):
    """Start one persisted Listening Post on HIPRFISR."""
    success = False
    message = ""

    post_id = str(
        post_id
        or ""
    ).strip()

    try:
        await (
            component
            .listening_post_manager
            .start(
                post_id
            )
        )

        success = True
        message = "Listening Post started."

    except Exception as exc:
        message = str(
            exc
        )

        component.logger.error(
            f"Could not start Listening Post: {exc}"
        )

    PARAMETERS = {
        "action": "start",
        "post_id": post_id,
        "success": success,
        "message": message,
        "posts": (
            component
            .listening_post_manager
            .snapshot()
        ),
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "listeningPostOperationReturn",
        fissure.comms.MessageFields.PARAMETERS:
            PARAMETERS,
    }

    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )


async def stopListeningPost(
    component: object,
    post_id="",
):
    """Stop one running HIPRFISR Listening Post."""
    success = False
    message = ""

    post_id = str(
        post_id
        or ""
    ).strip()

    try:
        await (
            component
            .listening_post_manager
            .stop(
                post_id
            )
        )

        success = True
        message = "Listening Post stopped."

    except Exception as exc:
        message = str(
            exc
        )

        component.logger.error(
            f"Could not stop Listening Post: {exc}"
        )

    PARAMETERS = {
        "action": "stop",
        "post_id": post_id,
        "success": success,
        "message": message,
        "posts": (
            component
            .listening_post_manager
            .snapshot()
        ),
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "listeningPostOperationReturn",
        fissure.comms.MessageFields.PARAMETERS:
            PARAMETERS,
    }

    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )


async def clearListeningPostActivity(component: object, post_id=""):
    """Clear one Listening Post's bounded Recent Activity buffer."""
    success = False
    message = ""
    post_id = str(post_id or "").strip()

    try:
        await component.listening_post_manager.clear_activity(post_id)
        success = True
    except Exception as exc:
        message = str(exc)
        component.logger.error(f"Could not clear Listening Post activity: {exc}")

    PARAMETERS = {
        "action": "clear",
        "post_id": post_id,
        "success": success,
        "message": message,
        "posts": component.listening_post_manager.snapshot(),
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "listeningPostOperationReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )


async def deleteListeningPost(
    component: object,
    post_id="",
):
    """Delete one stopped persisted Listening Post definition."""
    success = False
    message = ""

    post_id = str(
        post_id
        or ""
    ).strip()

    try:
        await (
            component
            .listening_post_manager
            .delete(
                post_id
            )
        )

        success = True
        message = "Listening Post removed."

    except Exception as exc:
        message = str(
            exc
        )

        component.logger.error(
            f"Could not remove Listening Post: {exc}"
        )

    PARAMETERS = {
        "action": "delete",
        "post_id": post_id,
        "success": success,
        "message": message,
        "posts": (
            component
            .listening_post_manager
            .snapshot()
        ),
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "listeningPostOperationReturn",
        fissure.comms.MessageFields.PARAMETERS:
            PARAMETERS,
    }

    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )


async def pingIP(component: object, node_uid: str):
    """
    Pings the sensor node IP from the HIPRFISR and returns the results to the Dashboard.
    """     
    # Acquire IP Address
    ip_address = component.nodes[node_uid].get("ip_address",None)

    if ip_address is None:
        return

    try:
        proc = await asyncio.create_subprocess_shell(
            f"ping -c 1 -W 2 {ip_address}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        result = stdout.decode().strip() or stderr.decode().strip()
    except Exception as e:
        result = f"Error running ping: {e}"

    PARAMETERS = {
        "ping": result,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "pingIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


##########################################################################
###################### To Multiple Components ############################
##########################################################################

async def updateFISSURE_Configuration(component: object, settings_dict={}):
    """Reload fissure_config.yaml after changes."""
    # Load settings from Fissure Config YAML
    component.settings = settings_dict #fissure.utils.get_fissure_config()  # Stick with Dashboard computer and someday look into storing on HIPRFISR computer.

    # Update TSI/PD/Other Components
    PARAMETERS = {"settings_dict": settings_dict}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "updateFISSURE_Configuration",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id, component.tsi_id]
    )


async def updateLoggingLevels(component: object, new_console_level="", new_file_level=""):
    """
    Update the logging levels on the HIPRFISR and forward to all components.
    """
    # Update New Levels for the HIPRFISR
    await component.updateLoggingLevels(new_console_level, new_file_level)

##########################################################################
##################### From Multiple Components ##########################
##########################################################################



##########################################################################
############################## To PD ####################################
##########################################################################


async def startPD(component: object, node_uid=""):
    """Sends a message to PD and sensor node to start processing on any incoming bits."""
    # Forward Message to PD
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "startPD",
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def stopPD(component: object, node_uid=""):
    """
    Signals to PD and sensor node to stop protocol discovery.
    """
    # Forward Message to PD
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "stopPD",
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def pdBitsReturn(component: object, bits_message=""):
    """
    Forwards bits captured at the sensor node to the protocol discovery circular buffer.
    """
    # Forward Message to PD
    PARAMETERS = {"bits_message": bits_message}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "pdBitsReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])


async def searchLibraryForFlowGraphs(
    component: object, soi_data=[], hardware=""
):  # Future: keep this to wherever the database will be: hiprfisr?
    """
    Queries protocol discovery to look in its version of the library to recommend flow graphs for the SOI.
    """
    # Forward Message to PD
    PARAMETERS = {"soi_data": soi_data, "hardware": hardware}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "searchLibraryForFlowGraphs",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])


async def findPreambles(component: object, window_min=0, window_max=0, ranking=0, std_deviations=0):
    """Sends message to PD to search the buffer for preambles."""
    # Send Message to PD
    PARAMETERS = {
        "window_min": window_min,
        "window_max": window_max,
        "ranking": ranking,
        "std_deviations": std_deviations,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "findPreambles",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])


async def searchLibrary(component: object, soi_data="", field_data=""):
    """
    Sends message to PD to search library.yaml from SOI data and field values.
    """
    # Send Message to PD
    PARAMETERS = {"soi_data": soi_data, "field_data": field_data}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "searchLibrary",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])


async def sliceByPreamble(component: object, preamble="", first_n=0, estimated_length=0):
    """Sends message to PD to slice the data by a single preamble."""
    # Send Message to PD
    PARAMETERS = {"preamble": preamble, "first_n": first_n, "estimated_length": estimated_length}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "sliceByPreamble",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])


async def setBufferSize(component: object, min_buffer_size=0, max_buffer_size=0):
    """
    Sends message to PD with the new sizes for the protocol discovery buffer.
    """
    # Send Message to PD
    PARAMETERS = {"min_buffer_size": min_buffer_size, "max_buffer_size": max_buffer_size}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "setBufferSize",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])


async def clearPD_Buffer(component: object):
    """
    Sends a message to Protocol Discovery to clear its buffer.
    """
    # Send Message to PD
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "clearPD_Buffer",
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])


async def findEntropy(component: object, message_length=0, preamble=""):
    """
    Sends a message to Protocol Discovery to find the entropy for the bit positions of fixed-length messages.
    """
    # Send Message to PD
    PARAMETERS = {"message_length": message_length, "preamble": preamble}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "findEntropy",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])


async def findEntropyReturn(component: object, ents=[]):
    """
    Forwards the findEntropy results to the Dashboard.
    """
    # Send Message to PD
    PARAMETERS = {"ents": ents}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "findEntropyReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def addPubSocket(component: object, ip_address="", port=0):
    """
    Signals to Protocol Discovery to add an additional ZMQ PUB for reading bits.
    """
    # Send Message to PD
    PARAMETERS = {"ip_address": ip_address, "port": port}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "addPubSocket",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])


async def removePubSocket(component: object, address=""):
    """
    Signals to Protocol Discovery to remove a ZMQ PUB.
    """
    # Send Message to PD
    PARAMETERS = {"address": address}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "removePubSocket",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])


##########################################################################
################################ From PD ################################
##########################################################################

async def retrieveDatabaseCachePD(component: object):
    """
    Retrieves a copy of important database tables needed for operating Protocol Discovery.
    """
    # Retrieve the Database Cache
    database_return = fissure.utils.library.cacheTableData(source="Protocol Discovery")

    # Return to the Dashboard (or other component?)
    PARAMETERS = {
        "database_return": database_return, 
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "retrieveDatabaseCacheReturnPD",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])


async def findPreamblesReturn(component: object, slice_medians, candidate_preambles, min_std_dev_max_length_preambles):
    """
    Sends potential preambles found in the circular buffer to the Dashboard.
    """
    PARAMETERS = {
        "slice_medians": slice_medians,
        "candidate_preambles": candidate_preambles,
        "min_std_dev_max_length_preambles": min_std_dev_max_length_preambles,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "findPreamblesReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def searchLibraryReturn(component: object, message=[]):
    """
    Forwards the search results to the Dashboard.
    """
    # Send Message to PD
    PARAMETERS = {"message": message}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "searchLibraryReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def demodFG_LibrarySearchReturn(component: object, flow_graphs=[]):
    """."""
    # Forward Message to Dashboard
    PARAMETERS = {"flow_graphs": flow_graphs}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "demodFG_LibrarySearchReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def bufferSizeReturn(component: object, buffer_size=0):
    """
    Forwards the size of the PD circular buffer to the Dashboard.
    """
    # Forward Message to Dashboard
    PARAMETERS = {"buffer_size": buffer_size}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "bufferSizeReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def sliceByPreambleReturn(component: object, packet_lengths=[], packet_dict={}):
    """
    Forwards the slice results to the Dashboard.
    """
    # Forward Message to Dashboard
    PARAMETERS = {"packet_lengths": packet_lengths, "packet_dict": packet_dict}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "sliceByPreambleReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def foundPreambles(component: object, parameters={}):
    """."""
    # Forward Message to Dashboard
    PARAMETERS = {"parameters": parameters}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "foundPreambles",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def foundPreamblesInLibrary(component: object, parameters={}):
    """."""
    # Forward Message to Dashboard
    PARAMETERS = {"parameters": parameters}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "foundPreamblesInLibrary",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


# ############################ To TSI ####################################


async def startTSI_FE(component: object, common_parameter_names=[], common_parameter_values=[]):
    """
    Signals to TSI to start TSI feature extractor.
    """
    # Forward Message to TSI
    PARAMETERS = {"common_parameter_names": common_parameter_names, "common_parameter_values": common_parameter_values}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "startTSI_FE",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.tsi_id])


async def stopTSI_FE(component: object):
    """
    Signals to TSI to stop TSI feature extractor.
    """
    # Forward Message to TSI
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "stopTSI_FE",
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.tsi_id])


async def startTSI_Conditioner(
    component: object,
    common_parameter_names=[],
    common_parameter_values=[],
    method_parameter_names=[],
    method_parameter_values=[],
    method_filepath=""
):
    """
    Signals to TSI to start TSI Conditioner.
    """
    # Forward Message to TSI
    PARAMETERS = {
        "common_parameter_names": common_parameter_names,
        "common_parameter_values": common_parameter_values,
        "method_parameter_names": method_parameter_names,
        "method_parameter_values": method_parameter_values,
        "method_filepath": method_filepath
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "startTSI_Conditioner",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.tsi_id])


async def stopTSI_Conditioner(component):
    """
    Signals to TSI to stop TSI conditioner.
    """
    # Forward Message to TSI
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "stopTSI_Conditioner",
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.tsi_id])


# ############################# From TSI #################################


async def feProgressBarReturn(component: object, progress=0, file_index=0):
    """."""
    # Forward Message to Dashboard
    PARAMETERS = {"progress": progress, "file_index": file_index}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "feProgressBarReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def tsiFE_Finished(component: object, table_strings=[]):
    """."""
    # Forward Message to Dashboard
    PARAMETERS = {"table_strings": table_strings}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "tsiFE_Finished",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


##########################################################################
############################ To Sensor Node ##############################
##########################################################################

async def queryPluginActions(
    component: object,
    requester_uid: str,
    requester_type: str,
    node_uid: str,
    context: str = "",
    scope: str = "all_plugins",
    plugin_name: str = "",
    include_tags: List[str] = None,
    exclude_tags: List[str] = None,
    hardware: str = "",
):
    """
    Forward a generic filtered plugin-action query to a selected Sensor Node.
    """
    node_record = component.nodes.get(node_uid)
    if not node_record:
        component.logger.warning(
            f"queryPluginActions: unknown node_uid={node_uid}"
        )
        return

    identity = node_record.get("identity", None)
    if identity is None:
        component.logger.warning(
            f"queryPluginActions: missing identity for node_uid={node_uid}"
        )
        return

    PARAMETERS = {
        "requester_uid": requester_uid,
        "requester_type": requester_type,
        "node_uid": node_uid,
        "context": context,
        "scope": scope,
        "plugin_name": plugin_name,
        "include_tags": include_tags or [],
        "exclude_tags": exclude_tags or [],
        "hardware": hardware,
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "queryPluginActions",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity],
    )




async def scanHardware(component: object, node_uid="", hardware_list=[]):
    """
    Sends a message to a sensor node to scan for hardware information.
    """
    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    # Build message
    PARAMETERS = {
        "hardware_list": hardware_list
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "scanHardware",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def probeHardware(component: object, node_uid, table_row_text):
    """
    Sends a message to a sensor node to probe select hardware.
    """
    # Forward the Message
    PARAMETERS = {
        "table_row_text": table_row_text
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "probeHardware",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def guessHardware(component: object, node_uid="", table_row=0, table_row_text=[], guess_index=0):
    """
    Sends a message to a sensor node to guess details for select hardware.
    """
    # Forward the Message
    PARAMETERS = {
        "table_row": table_row,
        "table_row_text": table_row_text,
        "guess_index": guess_index,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "guessHardware",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def transferSensorNodeFile(
    component: object, node_uid="", local_file="", remote_folder="", refresh_file_list=False
):
    """
    Loads a local file and transfers the data to a remote sensor node.
    """
    # Construct Filepath
    remote_filepath = remote_folder + "/" + local_file.split("/")[-1]

    # Load File
    if os.path.isfile(local_file):
        # Read the File
        try:
            with open(local_file, "rb") as f:
                get_data = f.read()
            get_data = binascii.hexlify(get_data)
            get_data = get_data.decode("utf-8").upper()
        except:
            component.logger.error("Error reading file")
            return
    else:
        component.logger.error("Invalid local filepath")
        return

    # Send Message
    PARAMETERS = {
        "local_file_data": get_data,
        "remote_filepath": remote_filepath,
        "refresh_file_list": refresh_file_list,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "transferSensorNodeFile",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def refreshSensorNodeFiles(component: object, node_uid="", sensor_node_folder=""):
    """
    Signals to sensor node to return file details for a specified folder.
    """
    # Send Message
    PARAMETERS = {
        "sensor_node_folder": sensor_node_folder
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "refreshSensorNodeFiles",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def deleteSensorNodeFile(component: object, node_uid="", sensor_node_file=""):
    """
    Signals to sensor node to delete a file or folder for a specified file path.
    """
    # Send Message
    PARAMETERS = {
        "sensor_node_file": sensor_node_file
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "deleteSensorNodeFile",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def downloadSensorNodeFile(component: object, node_uid="", sensor_node_file="", download_folder=""):
    """
    Signals to sensor node to transfer a copy of a file or folder for saving it to a specified file path.
    """
    # Send Message
    PARAMETERS = {
        "sensor_node_file": sensor_node_file,
        "download_folder": download_folder,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "downloadSensorNodeFile",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def overwriteDefaultAutorunPlaylist(component: object, node_uid="", playlist_dict={}):
    """Signals to sensor node to overwrite the default autorun playlist."""
    # Send Message
    PARAMETERS = {
        "playlist_dict": playlist_dict
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "overwriteDefaultAutorunPlaylist",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def autorunPlaylistQuery(component: object, node_uid=""):
    """Ask a Sensor Node for stored Autorun playlist filenames."""
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistQuery",
    }
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity],
    )


async def autorunPlaylistLoad(component: object, node_uid="", playlist_filename=""):
    """Ask a Sensor Node to return one stored Autorun playlist."""
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistLoad",
        fissure.comms.MessageFields.PARAMETERS: {"playlist_filename": playlist_filename},
    }
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity],
    )


async def autorunPlaylistSave(component: object, node_uid="", playlist_filename="", playlist_dict=None):
    """Ask a Sensor Node to save one plugin-backed Autorun playlist."""
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistSave",
        fissure.comms.MessageFields.PARAMETERS: {
            "playlist_filename": playlist_filename,
            "playlist_dict": playlist_dict or {},
        },
    }
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity],
    )


async def autorunPlaylistStart(component: object, node_uid="", playlist_dict=None):
    """Signal a Sensor Node to start the current plugin-backed Autorun playlist."""
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return

    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistStart",
        fissure.comms.MessageFields.PARAMETERS: {"playlist_dict": playlist_dict or {}},
    }
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity],
    )


async def autorunPlaylistExecute(component: object, node_uid="", playlist_filename=""):
    """Signals to sensor node to start autorun playlist already located on the sensor node."""
    # Send Message
    PARAMETERS = {
        "playlist_filename": playlist_filename
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistExecute",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def autorunPlaylistStop(component: object, node_uid=""):
    """Signals to sensor node to stop autorun playlist."""
    # Send Message
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistStop",
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        component.logger.error(f"Could not resolve identity for sensor node UUID {node_uid}")
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def iqFlowGraphStart(
    component: object, node_uid="", flow_graph_filepath="", variable_names=[], variable_values=[], file_type=""
):
    """
    Command for loading an IQ flow graph.
    """
    # Send Message to Sensor Node
    PARAMETERS = {
        "flow_graph_filepath": flow_graph_filepath,
        "variable_names": variable_names,
        "variable_values": variable_values,
        "file_type": file_type,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "iqFlowGraphStart",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def iqFlowGraphStop(component: object, node_uid="", parameter=""):
    """
    Sends message to Sensor Node to stop a running attack flow graph.
    """
    # Send Message to Sensor Node,PD
    PARAMETERS = {
        "parameter": parameter
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "iqFlowGraphStop",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def snifferFlowGraphStart(
    component: object, node_uid="", flow_graph_filepath="", variable_names=[], variable_values=[]
):
    """
    Starts a sniffer flow graph.
    """
    # Send Message to Sensor Node
    PARAMETERS = {
        "flow_graph_filepath": flow_graph_filepath,
        "variable_names": variable_names,
        "variable_values": variable_values,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "snifferFlowGraphStart",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def snifferFlowGraphStop(component: object, node_uid="", parameter=""):
    """
    Stops a sniffer flow graph
    """
    # Send Message to Sensor Node,PD
    PARAMETERS = {
        "parameter": parameter
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "snifferFlowGraphStop",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def refreshScapyInterfaces(component: object, node_uid=""):
    """Ask one Sensor Node to enumerate its Scapy-visible interfaces."""
    node_uid = str(node_uid or "").strip()

    identity = component.nodes.get(node_uid, {}).get("identity", None)
    if identity is None:
        component.logger.error(
            f"Could not resolve identity for sensor node UUID {node_uid}"
        )
        return

    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "refreshScapyInterfaces",
    }

    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity],
    )


async def refreshScapyInterfacesResults(
    component: object,
    node_uid="",
    interfaces=None,
):
    """Forward Sensor Node Scapy interface results to the Dashboard."""
    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "refreshScapyInterfacesResults",
        fissure.comms.MessageFields.PARAMETERS: {
            "node_uid": str(node_uid or ""),
            "interfaces": interfaces or [],
        },
    }

    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )


async def startScapyTransmission(
    component: object,
    node_uid="",
    operation_id="",
    interface="",
    method="",
    interval=0.1,
    count=1,
    loop=False,
    packet_hex="",
):
    """Forward a Scapy transmission request to one Sensor Node."""
    node_uid = str(node_uid or "").strip()
    identity = component.nodes.get(node_uid, {}).get("identity", None)

    if identity is None:
        component.logger.error(
            f"Could not resolve identity for sensor node UUID {node_uid}"
        )
        return

    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "startScapyTransmission",
        fissure.comms.MessageFields.PARAMETERS: {
            "operation_id": str(operation_id or ""),
            "interface": str(interface or ""),
            "method": str(method or ""),
            "interval": float(interval),
            "count": int(count),
            "loop": bool(loop),
            "packet_hex": str(packet_hex or ""),
        },
    }

    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity],
    )


async def scapyTransmissionStatus(
    component: object,
    node_uid="",
    operation_id="",
    state="",
    message="",
    packets_sent=0,
    set_rate="",
    started="",
):
    """Forward Scapy transmission state from a Sensor Node to the Dashboard."""
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "scapyTransmissionStatus",
        fissure.comms.MessageFields.PARAMETERS: {
            "node_uid": str(node_uid or ""),
            "operation_id": str(operation_id or ""),
            "state": str(state or ""),
            "message": str(message or ""),
            "packets_sent": int(packets_sent or 0),
            "set_rate": str(set_rate or ""),
            "started": str(started or ""),
        },
    }

    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )


async def setVariable(component: object, node_uid="", flow_graph="", variable="", value=""):
    """
    Sends a message to Sensor Node to change the variable of the running flow graph.
    """
    # Send Message to Sensor Node
    PARAMETERS = {
        "flow_graph": flow_graph, 
        "variable": variable, 
        "value": value
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "setVariable",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def protocolDiscoveryFG_Start(
    component: object, node_uid="", flow_graph_filepath="", variable_names=[], variable_values=[]
):
    """
    Sends message to Sensor Node to run a flow graph.
    """
    # Send Message to Sensor Node
    PARAMETERS = {
        "flow_graph_filepath": flow_graph_filepath,
        "variable_names": variable_names,
        "variable_values": variable_values,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "protocolDiscoveryFG_Start",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )    


async def protocolDiscoveryFG_Stop(component: object, node_uid=""):
    """
    Sends message to Sensor Node to stop a running flow graph.
    """
    # Send Message to Sensor Node
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "protocolDiscoveryFG_Stop",
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def terminateSensorNode(component: object, node_uid=""):
    """
    Stops sensor_node.py for local operations.
    """
    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return

    # Send to Sensor Node
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "terminateSensorNode",
    }
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def nodeRefresh(component: object):
    """
    """
    # For testing:
    # component.nodes = {
    #     "UUID-123": {
    #         "uuid": "UUID-123",
    #         "ip": "192.168.1.50",
    #         "settings": {"nickname": "Node A"},
    #         "network_type": "IP",
    #         "last_seen": time.time(),
    #         "connected": True
    #     },
    #     "UUID-456": {
    #         "uuid": "UUID-456",
    #         "ip": "10.0.0.15",
    #         "settings": {"nickname": "Node B"},
    #         "network_type": "Meshtastic",
    #         "last_seen": time.time() - 12.3,
    #         "connected": False
    #     }
    # }

    # -----------------------------------------------------
    # Notify dashboard
    # -----------------------------------------------------
    PARAMETERS = {
        "nodes": component.nodes,
    }
    
    msg_to_dashboard = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "nodeRefreshReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg_to_dashboard)


async def removeNode(component, node_uid):
    """ 
    Removes a node from the node dictionary.
    """
    component.nodes.pop(node_uid, None)

    await component.send_node_state_remove_to_dashboard(node_uid)


async def nodeSelectIP(component: object, node_uuid):
    """ Sends a message to the node to retrurn its settings upon Dashboard connection.
    """
    # Lookup identity for this UUID
    node_entry = component.nodes.get(node_uuid)
    if not node_entry:
        component.logger.error(f"[HIPRFISR] No such node_uuid {node_uuid}")
        return

    identity = node_entry["identity"]

    # Send Message to Node
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "nodeSelectIP",
    }
    await component.sensor_node_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[identity])


async def nodeReconnectIP(component: object, node_uid):
    """
    """
    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return

    # Send Message to Node
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "nodeSelectIP",
    }
    await component.sensor_node_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[identity])


async def disconnectFromSensorNode(component, node_uid="", delete_node=False, network_type="IP"):
    """
    Dashboard callback: request disconnection of a Sensor Node.
    """
    pass
    # # Resolve Identity
    # identity = component.nodes[node_uid].get("identity", None)
    # if identity is None:
    #     return

    # # 2) Mark node as disconnected internally
    # node = component.nodes.get(node_uid)
    # if node:
    #     node["connected"] = False

    # # 3) Notify Dashboard immediately
    # msg = {
    #     fissure.comms.MessageFields.IDENTIFIER: component.identifier,
    #     fissure.comms.MessageFields.MESSAGE_NAME: "componentDisconnected",
    #     fissure.comms.MessageFields.PARAMETERS: {"component_name": node_uid},
    # }
    # if component.dashboard_connected:
    #     await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    # # 4) Notify Sensor Node (if still reachable)
    # if network_type == "IP":
    #     try:
    #         msg2 = {
    #             fissure.comms.MessageFields.IDENTIFIER: component.identifier,
    #             fissure.comms.MessageFields.MESSAGE_NAME: "hiprfisrDisconnecting",
    #             fissure.comms.MessageFields.PARAMETERS: {},
    #         }

    #         await component.sensor_node_router.send_msg(
    #             fissure.comms.MessageTypes.COMMANDS,
    #             msg2,
    #             target_ids=[identity]
    #         )
    #     except Exception:
    #         pass

    # # 5) Delete node entirely from HIPRFISR (optional)
    # if delete_node:

    #     # Stop Local Sensor Node Program
    #     if uuid == component.local_node_uuid:
    #         msg3 = {
    #             fissure.comms.MessageFields.IDENTIFIER: component.identifier,
    #             fissure.comms.MessageFields.MESSAGE_NAME: "terminateSensorNode",
    #             fissure.comms.MessageFields.PARAMETERS: {},
    #         }
    #         await component.sensor_node_router.send_msg(
    #             fissure.comms.MessageTypes.COMMANDS,
    #             msg3,
    #             target_ids=[identity]
    #         )

    #         # Remove UUID from HIPRFISR registry for local only
    #         try:
    #             del component.nodes[uuid]
    #             component.logger.info(f"[DELETE] Removed node entry for UUID: {uuid}")
    #         except KeyError:
    #             component.logger.warning(f"[DELETE] UUID {uuid} not found in component.nodes")

    #     # Clear heartbeat tracking
    #     hb = component.heartbeats.get(fissure.comms.Identifiers.SENSOR_NODE, {})

    #     if isinstance(hb, list):
    #         for i, entry in enumerate(hb):
    #             if isinstance(entry, dict):
    #                 # Heartbeat stored using identity, not UUID
    #                 if entry.get("uuid") == identity:
    #                     hb[i] = None
    #                     break

    #     elif isinstance(hb, dict):
    #         # If keyed by identity
    #         hb.pop(identity, None)
    #         # If keyed by UUID
    #         hb.pop(uuid, None)

    #     # Remove UUID from dashboard slot map
    #     component.dashboard_node_map[dashboard_index] = None

    #     # Shift remaining slots left (GUI ONLY)
    #     for i in range(dashboard_index, len(component.dashboard_node_map) - 1):
    #         component.dashboard_node_map[i] = component.dashboard_node_map[i + 1]

    #     component.dashboard_node_map[-1] = None

    #     # --------------------------------------
    #     # E) Cleanup complete
    #     # --------------------------------------
    #     component.logger.info(f"[DELETE] Node {uuid} fully removed from HIPRFISR")


# async def disconnectFromMeshtastic(component: object, node_uid=""):
#     """
#     Ends connections to local serial connection to Meshatastic.
#     """
#     pass
    # sensor_node_id = int(sensor_node_id)

    # # Ensure the sensor node exists
    # if component.sensor_nodes[sensor_node_id] is None:
    #     component.logger.warning(f"Sensor node {sensor_node_id} is not connected.")
    #     return

    # # Disconnect
    # try:
    #     await component.sensor_nodes[sensor_node_id].listener.disconnect()
    # except Exception as e:
    #     component.logger.error(f"Error disconnecting local serial connection for Sensor Node {sensor_node_id}: {e}")        

    # # Set the node to None to fully remove it
    # component.sensor_nodes[sensor_node_id] = None
    # component.logger.info(f"Local serial connection for Sensor Node {sensor_node_id} successfully disconnected.")

    # # Notify the Dashboard
    # PARAMETERS = {"component_name": sensor_node_id}
    # msg = {
    #     fissure.comms.MessageFields.IDENTIFIER: component.identifier,
    #     fissure.comms.MessageFields.MESSAGE_NAME: "componentDisconnected",
    #     fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    # }
    # await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def connectToSensorNodeMeshtastic(component: object, node_uid, serial_port, serial_baud_rate):
    """
    Connects the HIPRFISR to a local serial connection for a device using Meshtastic.
    """
    pass
    # sensor_node_id = int(sensor_node_id)
    # context = component
    # name=f"{fissure.comms.Identifiers.HIPRFISR}::sensor_node"

    # # Initialize Meshtastic connection
    # component.logger.info(f"Connecting to sensor node {sensor_node_id} via Meshtastic on {serial_port}...")

    # try:
    #     if component.sensor_nodes[sensor_node_id] is None:
    #         await component.reset_sensor_node_listener(
    #             sensor_node_id, "Meshtastic", serial_port=serial_port, name=name, context=context
    #         )
    #     component.logger.info(f"Connected to local serial port for communicating with Sensor node {sensor_node_id} via Meshtastic.")

    #     # Send Connected Messages
    #     PARAMETERS = {"component_name": sensor_node_id}
    #     msg = {
    #         fissure.comms.MessageFields.IDENTIFIER: component.identifier,
    #         fissure.comms.MessageFields.MESSAGE_NAME: "componentConnectedSerial",
    #         fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    #     }
    #     await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        
    # except Exception as e:
    #     component.logger.error(f"Failed to connect to sensor node {sensor_node_id} via Meshtastic: {e}")


async def findGPS_Coordinates(component: object, node_uid="", gps_source="", format=""):
    """
    Queries the remote sensor node for its GPS coordinates. 
    """
    # Forward the Message
    PARAMETERS = {
        "gps_source": gps_source,
        "format": format
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "findGPS_Coordinates",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def gpsBeaconEnableDisableIP(component: object, node_uid: str):
    """
    Enables/disables the GPS TAK beacon at the sensor node.
    """
    # Send Message
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "gpsBeaconEnableDisableIP",
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def rebootIP(component: object, node_uid=""):
    """
    Forwards the message to reboot the sensor node computer.
    """
    # Send the Message
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "rebootIP",
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def uptimeIP(component: object, node_uid: str):
    """
    Forwards the message to retrieve the uptime of the sensor node computer.
    """
    # Send the Message
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "uptimeIP",
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )    


async def memoryIP(component: object, node_uid: str):
    """
    Forwards the message to retrieve the memory usage of the sensor node computer.
    """
    # Send the Message
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "memoryIP",
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def diskIP(component: object, node_uid: str):
    """
    Forwards the message to retrieve the disk usage of the sensor node computer.
    """
    # Send the Message
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "diskIP",
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )

    
async def cpuIP(component: object, node_uid: str):
    """
    Forwards the message to retrieve the CPU percentage of the sensor node computer.
    """
    # Send the Message
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "cpuIP",
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )

    
async def processesIP(component: object, node_uid: str):
    """
    Forwards the message to retrieve the processes on the sensor node computer.
    """
    # Send the Message
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "processesIP",
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )    

    
async def ifconfigIP(component: object, node_uid: str):
    """
    Forwards the message to retrieve the ifconfig output on the sensor node computer.
    """
    # Send the Message
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "ifconfigIP",
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def iwconfigIP(component: object, node_uid: str):
    """
    Forwards the message to retrieve the iwconfig output on the sensor node computer.
    """
    # Send the Message
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "iwconfigIP",
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )    


async def updateNodeSettings(component: object, node_uid: str, settings_dict: dict):
    """
    Forwards the message to retrieve the iwconfig output on the sensor node computer.
    """
    # Send the Message
    PARAMETERS = {
        "settings_dict": settings_dict,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "updateNodeSettings",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )    


async def queryPluginActionSchema(
    component: object,
    requester_uid: str,
    requester_type: str,
    node_uid: str,
    plugin_name: str,
    action_name: str,
    context: str = "",
):
    """
    Forward a Dashboard-only plugin action schema query to a selected Sensor Node.
    """
    node_record = component.nodes.get(node_uid)
    if not node_record:
        component.logger.warning(
            f"queryPluginActionSchema: unknown node_uid={node_uid}"
        )
        return

    identity = node_record.get("identity", None)
    if identity is None:
        component.logger.warning(
            f"queryPluginActionSchema: missing identity for node_uid={node_uid}"
        )
        return

    PARAMETERS = {
        "requester_uid": requester_uid,
        "requester_type": requester_type,
        "node_uid": node_uid,
        "plugin_name": plugin_name,
        "action_name": action_name,
        "context": context,
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "queryPluginActionSchema",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity],
    )    

##########################################################################
########################### From Sensor Node #############################
##########################################################################

async def queryPluginActionSchemaResults(
    component: object,
    requester_uid: str,
    requester_type: str,
    node_uid: str,
    plugin_name: str,
    action_name: str,
    schema: dict,
    context: str = "",
):
    """
    Forward a Dashboard-only plugin action schema result to the Dashboard.
    """
    if not isinstance(schema, dict):
        schema = {"params": []}

    if "params" not in schema or not isinstance(schema.get("params"), list):
        schema["params"] = []

    PARAMETERS = {
        "requester_uid": requester_uid,
        "requester_type": requester_type,
        "node_uid": node_uid,
        "plugin_name": plugin_name,
        "action_name": action_name,
        "schema": schema,
        "context": context,
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "queryPluginActionSchemaResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )


async def queryPluginActionsResults(
    component: object,
    requester_uid: str,
    requester_type: str,
    node_uid: str,
    context: str = "",
    actions: List[dict] = None,
):
    """
    Forward filtered plugin-action query results to the Dashboard.
    """
    PARAMETERS = {
        "requester_uid": requester_uid,
        "requester_type": requester_type,
        "node_uid": node_uid,
        "context": context,
        "actions": actions or [],
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "queryPluginActionsResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )


async def sensorNodeFileTransferStatus(
    component: object,
    uuid="",
    transfer_id="",
    transfer_type="",
    plugin_name="",
    success=False,
    message="",
    remote_filepath="",
    remote_folder="",
    bytes_received=0,
    elapsed_seconds=0.0,
    mib_per_second=0.0,
    refresh_file_list=False,
):
    """
    Handle Sensor Node binary-transfer completion.

    Generic Dashboard file uploads keep their existing forwarding behavior.
    HIPRFISR-originated plugin-package uploads are intercepted here and moved
    into the plugin finalization lifecycle.
    """
    transfer_type = str(
        transfer_type
        or ""
    ).strip()

    if transfer_type == "plugin_package_upload":
        deployments = (
            _get_plugin_deployments(
                component
            )
        )

        deployment = deployments.get(
            transfer_id
        )

        if not isinstance(
            deployment,
            dict,
        ):
            component.logger.warning(
                "Ignoring plugin-package transfer status "
                "for unknown transfer_id=%s",
                transfer_id,
            )
            return

        expected_node_uid = str(
            deployment.get(
                "node_uid",
                "",
            )
            or ""
        )
        expected_plugin_name = str(
            deployment.get(
                "plugin_name",
                "",
            )
            or ""
        )

        if (
            uuid != expected_node_uid
            or plugin_name != expected_plugin_name
        ):
            deployments.pop(
                transfer_id,
                None,
            )

            await _cancel_sensor_plugin_deployment(
                component,
                deployment,
            )

            await _send_plugin_deploy_result(
                component,
                node_uid=expected_node_uid,
                plugin_name=expected_plugin_name,
                transfer_id=transfer_id,
                success=False,
                status="Transfer Failed",
                message=(
                    "Plugin package transfer status "
                    "did not match the pending deployment."
                ),
            )
            return

        if not success:
            deployments.pop(
                transfer_id,
                None,
            )

            await _cancel_sensor_plugin_deployment(
                component,
                deployment,
            )

            await _send_plugin_deploy_result(
                component,
                node_uid=expected_node_uid,
                plugin_name=expected_plugin_name,
                transfer_id=transfer_id,
                success=False,
                status="Transfer Failed",
                message=str(
                    message
                    or "Plugin package transfer failed."
                ),
            )
            return

        node = (
            (component.nodes or {})
            .get(
                expected_node_uid,
                {},
            )
            or {}
        )
        identity = node.get(
            "identity"
        )

        if identity is None:
            deployments.pop(
                transfer_id,
                None,
            )

            await _send_plugin_deploy_result(
                component,
                node_uid=expected_node_uid,
                plugin_name=expected_plugin_name,
                transfer_id=transfer_id,
                success=False,
                status="Failed",
                message=(
                    "Sensor Node disconnected after "
                    "receiving the plugin package."
                ),
            )
            return

        PARAMETERS = {
            "plugin_name":
                expected_plugin_name,
            "transfer_id":
                transfer_id,
        }
        msg = {
            fissure.comms.MessageFields.IDENTIFIER:
                component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME:
                "finalizePluginDeployment",
            fissure.comms.MessageFields.PARAMETERS:
                PARAMETERS,
        }

        await component.sensor_node_router.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
            target_ids=[
                identity
            ],
        )
        return

    parameters = {
        "node_uid": uuid,
        "transfer_id": transfer_id,
        "success": bool(success),
        "message": message,
        "remote_filepath": remote_filepath,
        "remote_folder": remote_folder,
        "bytes_received": int(bytes_received),
        "elapsed_seconds": float(elapsed_seconds),
        "mib_per_second": float(mib_per_second),
        "refresh_file_list": bool(refresh_file_list),
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "sensorNodeFileTransferStatus",
        fissure.comms.MessageFields.PARAMETERS:
            parameters,
    }

    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )


async def refreshSensorNodeFilesResults(
    component: object, node_uid="", filepaths=[], file_sizes=[], file_types=[], modified_dates=[]
):
    """
    Forwards the refresh sensor node files results to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {
        "filepaths": filepaths,
        "file_sizes": file_sizes,
        "file_types": file_types,
        "modified_dates": modified_dates,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "refreshSensorNodeFilesResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def refreshSensorNodeActivityResults(
    component: object,
    node_uid="",
    operations=None,
    log_entries=None,
):
    """Forward one Sensor Node Activity snapshot to the Dashboard."""
    PARAMETERS = {
        "node_uid": node_uid,
        "operations": operations or [],
        "log_entries": log_entries or [],
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "refreshSensorNodeActivityResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )


async def refreshSensorNodeActivity(component: object, node_uid="", log_limit=100):
    """Request one bounded Activity snapshot from an IP/local Sensor Node."""
    node = (component.nodes or {}).get(node_uid, {}) or {}
    identity = node.get("identity")

    if identity is None:
        component.logger.warning(
            f"Could not refresh Sensor Node Activity; no identity for {node_uid}."
        )
        return

    PARAMETERS = {
        "log_limit": log_limit,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "refreshSensorNodeActivity",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity],
    )


async def flowGraphError(component: object, node_uid="", error=""):
    """
    Forwards the flow graph error message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {
        "error": error
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphError",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def flowGraphFinishedSniffer(component: object, node_uid="", category=""):
    """
    Forwards the flow graph finished sniffer message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {
        "category": category
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedSniffer",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)



async def flowGraphFinishedIQ_Playback(component: object, node_uid=""):
    """
    Forwards the flow graph finished IQ playback message to the Dashboard.
    """
    # Send the Message
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedIQ_Playback",
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def flowGraphFinished(component: object, node_uid="", category=""):
    """
    Forwards the flow graph finished message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {
        "category": category
    }    
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinished",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def flowGraphStartedSniffer(component: object, node_uid="", category=""):
    """
    Forwards the flow graph started IQ sniffer message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {
        "category": category
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedSniffer",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def flowGraphStartedIQ_Playback(component: object, node_uid=""):
    """
    Forwards the flow graph started IQ playback message to the Dasbhoard.
    """
    # Send the Message
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedIQ_Playback",
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def flowGraphStarted(component: object, node_uid="", category=""):
    """
    Forwards the flow graph started message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {
        "category": category
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStarted",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def recallSettingsReturn(component: object, uuid, settings_dict):
    """
    Returns the recalled sensor node settings to the Dashboard.
    """
    # Get the IP
    get_node_ip = component.nodes[uuid].get("ip", None)

    # Send the Message
    PARAMETERS = {
        "node_uuid": uuid,
        "node_ip_address": get_node_ip,
        "settings_dict": settings_dict
    }
    msg1 = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "recallSettingsReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg1)

    # # Send First Connected Message
    # component.dashboard_node_map[int(dashboard_node_index)] = uuid
    # component.nodes[uuid]["connected"] = True
    # PARAMETERS = {"component_name": dashboard_node_index}
    # msg2 = {
    #     fissure.comms.MessageFields.IDENTIFIER: component.identifier,
    #     fissure.comms.MessageFields.MESSAGE_NAME: "componentConnected",
    #     fissure.comms.MessageFields.PARAMETERS: PARAMETERS
    # }
    # if component.dashboard_connected:
    #     await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg2)


async def hardwareProbeResults(component: object, output="", height_width=[]):
    """
    Forwards the hardware probe results message to the Dashboard.
    """
    PARAMETERS = {
        "output": output, 
        "height_width": height_width
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "hardwareProbeResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def hardwareScanResults(component: object, uuid="", hardware_scan_results=[]):
    """
    Forwards the hardware scan results message to the Dashboard.
    """   
    # Send Message
    PARAMETERS = {
        "hardware_scan_results": hardware_scan_results
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "hardwareScanResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def hardwareGuessResults(
    component: object, table_row=0, hardware_type="", scan_results="", new_guess_index=0
):
    """
    Forwards sensnor node hardware guess results from HIPRFISR to Dashboard.
    """
    PARAMETERS = {
        "table_row": table_row,
        "hardware_type": hardware_type,
        "scan_results": scan_results,
        "new_guess_index": new_guess_index,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "hardwareGuessResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def saveFile(
    component: object,
    node_uid="",
    operation="",
    filepath="",
    data="",
):
    """
    Save a downloaded file from a remote Sensor Node to the HIPRFISR computer.
    """
    if operation != "Download":
        return

    if not filepath:
        return

    with open(filepath, "wb") as file:
        file.write(
            binascii.a2b_hex(data)
        )

    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "fileDownloaded",
    }

    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )


async def findGPS_CoordinatesResults(component: object, coordinates=""):
    """
    Forwards the GPS coordinate results message to the Dashboard.
    """
    PARAMETERS = {
        "coordinates": coordinates
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "findGPS_CoordinatesResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def detectionReturn(
    component,
    detection: dict,
    lat=None,
    lon=None,
    alt=None,
    observation_time=None,
):
    """
    Receive one native FISSURE Detection from a Sensor Node.

    Detections remain transient. HIPRFISR performs any hub-side processing,
    forwards the structured Detection to the Dashboard/TSI path, and emits a
    CoT representation for Tactical and external TAK consumers.
    """
    if not isinstance(detection, dict):
        component.logger.error("detectionReturn requires a detection dictionary.")
        return

    detection = dict(detection)
    detection["kind"] = "detection"
    detection["event_type"] = "detection"

    node_uid = str(detection.get("node_uid") or "").strip()
    if not node_uid:
        component.logger.warning("detectionReturn received detection without node_uid.")

    detection_id = str(
        detection.get("detection_id")
        or uuid.uuid4()
    ).strip()
    detection["detection_id"] = detection_id

    operation_id = str(
        detection.get("opid")
        or detection.get("operation_id")
        or ""
    ).strip()

    if operation_id:
        detection["opid"] = operation_id
        detection.setdefault("operation_id", operation_id)

    if lat is None:
        lat = detection.get("latitude")
    if lat is None:
        lat = detection.get("lat")

    if lon is None:
        lon = detection.get("longitude")
    if lon is None:
        lon = detection.get("lon")

    if alt is None:
        alt = detection.get("altitude")
    if alt is None:
        alt = detection.get("alt")
    if alt is None:
        alt = detection.get("hae_m")
    if alt is None:
        alt = detection.get("hae")

    node_record = {}
    if node_uid:
        node_record = (getattr(component, "nodes", {}) or {}).get(node_uid, {}) or {}

    if lat is None:
        lat = node_record.get("lat")
    if lon is None:
        lon = node_record.get("lon")
    if alt is None:
        alt = node_record.get("alt")

    if lat is not None:
        detection.setdefault("latitude", lat)
    if lon is not None:
        detection.setdefault("longitude", lon)
    if alt is not None:
        detection.setdefault("altitude", alt)

    if not observation_time:
        observation_time = detection.get("observation_time")

    if not observation_time:
        detection_timestamp = detection.get("timestamp")
        try:
            observation_time = datetime.fromtimestamp(
                float(detection_timestamp),
                tz=timezone.utc,
            ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except Exception:
            observation_time = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            )

    detection.setdefault("observation_time", observation_time)

    detector_name = str(detection.get("detector") or "detection").strip()
    event_uid = str(
        detection.get("event_uid")
        or detection.get("uid")
        or f"{detector_name}-{node_uid or 'node'}-{detection_id}"
    ).strip()
    detection.setdefault("event_uid", event_uid)

    payload = {
        "msg_type": "event",
        "uid": event_uid,
        "lat": lat if lat is not None else 0.0,
        "lon": lon if lon is not None else 0.0,
        "alt": alt if alt is not None else 0.0,
        "time": observation_time,
        "data": detection,
        "opid": operation_id,
        "tak_icon": "r-x-fissure-detection",
    }

    try:
        out = maybe_ingest_detection_for_geolocation(component, payload)
        if out is not None:
            target_id, patch, history_entry = out
            await targetPatch(
                component,
                target_id=target_id,
                patch=patch,
                history_entry=history_entry,
                artifact_id="",
            )
    except Exception as exc:
        component.logger.error(
            f"detectionReturn geolocation ingest error: {exc}"
        )

    if component.dashboard_connected:
        dashboard_msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "detectionReturn",
            fissure.comms.MessageFields.PARAMETERS: {
                "detection": detection,
            },
        }

        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            dashboard_msg,
        )

    await fissure.utils.tak_messages.send(
        component,
        payload,
    )


#######################################
async def takReturn(component, payload: dict):
    """
    TAK message schema (required vs. optional).

    ------------------------------------------------------------
    PIN MESSAGE
    Required:
        msg_type = "pin"
        uid
        lat
        lon
        callsign    # provided by utility if missing

    Optional:
        alt (default 0)
        remarks (default "")
        stale (default 999999999)
        tak_icon (default "a-f-G-U-H")
        how (optional)
        # extra metadata ignored unless placed in data

    ------------------------------------------------------------
    TRACK MESSAGE
    Required:
        msg_type = "track"
        uid
        lat
        lon
        callsign    # REQUIRED for proper labeling; utility will supply one
                    # using HIPRFISR prefix + nickname/uid

    Optional:
        alt (default 0)
        stale (default 60)
        tak_icon (default "b-m-p-w")
        how (optional)
        # extra metadata ignored unless utility extended

    ------------------------------------------------------------
    EVENT MESSAGE
    Required:
        msg_type = "event"
        uid
        data["event_type"]

    Optional:
        stale (default 30)
        tak_icon (default "b-f-t-r")
        data[...]  # all structured metadata goes here:
                # freqs, deltas, classifications, plugin lists, etc.

    ------------------------------------------------------------
    """
    if "msg_type" not in payload:
        component.logger.error("TAK send() missing required field: msg_type")
        return
    if "uid" not in payload:
        component.logger.error("TAK send() missing required field: uid")
        return

    mtype = payload["msg_type"]
    uid = payload["uid"]

    # Position and Status Updates
    if mtype == "track":
        node = component.nodes.get(uid)
        if not node:
            component.logger.warning(f"TAK send(): unknown node uid={uid}")
            return

        incoming_status = payload.get("status")
        status = (incoming_status or node.get("status") or "unknown").lower()

        node["status"] = status
        node["last_seen"] = time.time()
        node["connected"] = True

        if "lat" in payload and payload["lat"] is not None:
            node["lat"] = payload["lat"]
        if "lon" in payload and payload["lon"] is not None:
            node["lon"] = payload["lon"]
        if "alt" in payload and payload["alt"] is not None:
            node["alt"] = payload["alt"]

        tak_icon = payload.get("tak_icon")
        if not tak_icon:
            if status in {"idle", "unknown"}:
                tak_icon = component.settings["tak"]["node_idle_icon"]
            else:
                tak_icon = component.settings["tak"]["node_busy_icon"]
            payload["tak_icon"] = tak_icon

        node["tak_icon"] = tak_icon
        component.logger.debug(f"Updated node {uid}: status={status}, tak_icon={tak_icon}")

    # If this is a target-associated detection with usable fields,
    # immediately feed it into hub multilateration and patch the target.
    if mtype == "event":
        try:
            out = maybe_ingest_detection_for_geolocation(component, payload)
            if out is not None:
                target_id, patch, history_entry = out
                await targetPatch(
                    component,
                    target_id=target_id,
                    patch=patch,
                    history_entry=history_entry,
                    artifact_id="",
                )
        except Exception as e:
            component.logger.error(f"takReturn geolocation ingest error: {e}")

    # Forward to TAK via utility layer
    await fissure.utils.tak_messages.send(component, payload)


def maybe_ingest_detection_for_geolocation(component, payload: dict):
    """
    Inspect a TAK event payload. If it is a target-associated detection with usable
    position + power information, feed it into hub multilateration and return
    a target patch when a location estimate is available.

    Returns:
        (target_id, patch, history_entry) or None
    """
    if not isinstance(payload, dict):
        return None

    if payload.get("msg_type") != "event":
        return None

    data = payload.get("data") or {}
    if not isinstance(data, dict):
        return None

    if data.get("event_type") != "detection":
        return None

    target_id = str(data.get("target_id") or "").strip()
    if not target_id:
        return None

    power_dbm = data.get("power_dbm")
    if power_dbm in (None, ""):
        return None

    lat = payload.get("lat")
    lon = payload.get("lon")
    alt = payload.get("alt")
    observation_time = payload.get("time")

    if lat in (None, "") or lon in (None, ""):
        return None

    frequency_hz = None
    try:
        if data.get("frequency_hz") not in (None, ""):
            frequency_hz = float(data.get("frequency_hz"))
        elif data.get("frequency_mhz") not in (None, ""):
            frequency_hz = float(data.get("frequency_mhz")) * 1e6
    except Exception:
        frequency_hz = None

    node_uid = str(data.get("node_uid") or "").strip()

    try:
        est_out = _fissure_geo_process_measurement(
            component,
            target_id=target_id,
            frequency_hz=frequency_hz,
            node_uid=node_uid,
            lat=float(lat),
            lon=float(lon),
            rssi_db=float(power_dbm),
            observation_time=observation_time,
        )
    except Exception as e:
        component.logger.error(
            f"Detection geolocation ingest failed for target_id={target_id}: {e}"
        )
        return None

    if est_out is None:
        return None

    est_lat, est_lon, ce_m = est_out

    ts_iso = observation_time
    if not isinstance(ts_iso, str) or not ts_iso:
        ts_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        ts_iso = ts_iso.replace(" ", "T")

    patch = {
        "location": {
            "lat": float(est_lat),
            "lon": float(est_lon),
            "hae_m": float(alt or 0.0),
            "ce_m": float(ce_m),
            "timestamp": ts_iso,
            "source": "hiprfisr_multilateration",
        },
        "state": "tracking",
    }

    history_entry = {
        "event": "multilateration_update_from_detection",
        "detector": data.get("detector", ""),
        "node_uid": node_uid,
    }

    return target_id, patch, history_entry


async def gpsBeaconEnableDisableIP_Return(component: object, gps_tak_beacon_status: bool):
    """
    Forwards GPS TAK beacon state to the Dashboard.
    """
    # Forward to Dashboard
    PARAMETERS = {
        "gps_tak_beacon_status": gps_tak_beacon_status,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "gpsBeaconEnableDisableIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def uptimeIP_Return(component: object, uptime: str):
    """
    Forwards the uptimeIP_Return message to the Dashboard.
    """
    # Forward to Dashboard
    PARAMETERS = {
        "uptime": uptime,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "uptimeIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def memoryIP_Return(component: object, memory: str):
    """
    Forwards the memoryIP_Return message to the Dashboard.
    """
    # Forward to Dashboard
    PARAMETERS = {
        "memory": memory,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "memoryIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def diskIP_Return(component: object, disk: str):
    """
    Forwards the diskIP_Return message to the Dashboard.
    """
    # Forward to Dashboard
    PARAMETERS = {
        "disk": disk,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "diskIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def cpuIP_Return(component: object, cpu: str):
    """
    Forwards the cpuIP_Return message to the Dashboard.
    """
    # Forward to Dashboard
    PARAMETERS = {
        "cpu": cpu,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "cpuIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def processesIP_Return(component: object, processes: str):
    """
    Forwards the processesIP_Return message to the Dashboard.
    """
    # Forward to Dashboard
    PARAMETERS = {
        "processes": processes,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "processesIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def ifconfigIP_Return(component: object, ifconfig: str):
    """
    Forwards the ifconfigIP_Return message to the Dashboard.
    """
    # Forward to Dashboard
    PARAMETERS = {
        "ifconfig": ifconfig,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "ifconfigIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def iwconfigIP_Return(component: object, iwconfig: str):
    """
    Forwards the iwconfigIP_Return message to the Dashboard.
    """
    # Forward to Dashboard
    PARAMETERS = {
        "iwconfig": iwconfig,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "iwconfigIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg) 


async def autorunPlaylistQueryResults(
    component: object, node_uid="", playlists=None, state="Idle", source="", message=""
):
    """Forward stored Autorun playlist filenames to the Dashboard."""
    if not component.dashboard_connected:
        return
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistQueryResults",
        fissure.comms.MessageFields.PARAMETERS: {
            "node_uid": node_uid,
            "playlists": playlists or [],
            "state": state,
            "source": source,
            "message": message,
        },
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def autorunPlaylistLoadResults(
    component: object,
    node_uid="",
    playlist_filename="",
    playlist_dict=None,
    success=False,
    message="",
):
    """Forward a loaded Sensor Node Autorun playlist to the Dashboard."""
    if not component.dashboard_connected:
        return
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistLoadResults",
        fissure.comms.MessageFields.PARAMETERS: {
            "node_uid": node_uid,
            "playlist_filename": playlist_filename,
            "playlist_dict": playlist_dict or {},
            "success": bool(success),
            "message": message,
        },
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def autorunPlaylistSaveResults(
    component: object,
    node_uid="",
    playlist_filename="",
    success=False,
    message="",
):
    """Forward Sensor Node Autorun save completion to the Dashboard."""
    if not component.dashboard_connected:
        return
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistSaveResults",
        fissure.comms.MessageFields.PARAMETERS: {
            "node_uid": node_uid,
            "playlist_filename": playlist_filename,
            "success": bool(success),
            "message": message,
        },
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def autorunPlaylistStatus(component: object, node_uid="", state="Idle", source="", message=""):
    """Forward authoritative Sensor Node Autorun state to the Dashboard."""
    if not component.dashboard_connected:
        return
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistStatus",
        fissure.comms.MessageFields.PARAMETERS: {
            "node_uid": node_uid,
            "state": state,
            "source": source,
            "message": message,
        },
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


##########################################################################
####################### Outdated/Incomplete/Unused #######################
##########################################################################

async def setAutoStartPD(component: object, value=False):
    """
    Controls whether Protocol Discovery will begin immediately when a target signal is selected.
    """
    if value is True:
        component.auto_start_pd = True
    elif value is False:
        component.auto_start_pd = False


async def clear_SOI_List(component: object):
    """Clears the SOI List"""
    component.logger.debug("Executing Callback: Clear SOI List")
    component.soi_list = []


async def setHeartbeatInterval(component: object, interval=0):
    """Saves the settings changes made in the Dashboard to the HIPRFISR."""
    component.settings["heartbeat_interval"] = str(int(interval))

    # Send Change to TSI
    # component.tsi_hiprfisr_server.sendmsg(
    #     "Commands", Identifier="HIPRFISR", MessageName="Set Heartbeat Interval", Parameters=interval
    # )


async def refreshPluginInventory(component: object, node_uid=""):
    """Request the selected Sensor Node plugin inventory."""
    node_uid = str(node_uid or "").strip()
    hub_inventory = plugin.get_local_plugin_inventory()

    node = (component.nodes or {}).get(node_uid, {}) or {}
    identity = node.get("identity")

    if not node_uid or identity is None:
        PARAMETERS = {
            "node_uid": node_uid,
            "hub_inventory": hub_inventory,
            "node_inventory": {},
            "error": "Selected Sensor Node is unavailable.",
        }
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "refreshPluginInventoryResults",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        if component.dashboard_connected:
            await component.dashboard_socket.send_msg(
                fissure.comms.MessageTypes.COMMANDS,
                msg,
            )
        return

    PARAMETERS = {}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "refreshPluginInventory",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity],
    )


async def refreshPluginInventoryResults(
    component: object,
    node_uid="",
    node_inventory=None,
):
    """Combine Hub and Sensor Node plugin inventories and return them to the Dashboard."""
    PARAMETERS = {
        "node_uid": node_uid,
        "hub_inventory": plugin.get_local_plugin_inventory(),
        "node_inventory": node_inventory or {},
        "error": "",
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "refreshPluginInventoryResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )


async def repairPluginSetup(component: object, node_uid="", plugin_name=""):
    """Request setup repair for one plugin on the selected Sensor Node."""
    node_uid = str(node_uid or "").strip()
    plugin_name = str(plugin_name or "").strip()

    node = (component.nodes or {}).get(node_uid, {}) or {}
    identity = node.get("identity")

    if not node_uid or identity is None:
        PARAMETERS = {
            "node_uid": node_uid,
            "plugin_name": plugin_name,
            "success": False,
            "status": "Failed",
            "message": "Selected Sensor Node is unavailable.",
            "output": "",
        }
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "repairPluginSetupResults",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        if component.dashboard_connected:
            await component.dashboard_socket.send_msg(
                fissure.comms.MessageTypes.COMMANDS,
                msg,
            )
        return

    PARAMETERS = {
        "plugin_name": plugin_name,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "repairPluginSetup",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity],
    )


async def repairPluginSetupResults(
    component: object,
    node_uid="",
    plugin_name="",
    success=False,
    status="",
    message="",
    output="",
    node_inventory=None,
):
    """Forward one Sensor Node setup-repair result to the Dashboard."""
    PARAMETERS = {
        "node_uid": node_uid,
        "plugin_name": plugin_name,
        "success": bool(success),
        "status": status,
        "message": message,
        "output": output,
        "hub_inventory": plugin.get_local_plugin_inventory(),
        "node_inventory": node_inventory,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "repairPluginSetupResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )


async def _send_plugin_deploy_result(
    component: object,
    *,
    node_uid="",
    plugin_name="",
    transfer_id="",
    success=False,
    status="",
    message="",
    output="",
    node_inventory=None,
):
    """Send one Deploy/Update lifecycle result to the Dashboard."""
    if not component.dashboard_connected:
        return

    PARAMETERS = {
        "node_uid": node_uid,
        "plugin_name": plugin_name,
        "transfer_id": transfer_id,
        "success": bool(
            success
        ),
        "status": str(
            status
            or ""
        ),
        "message": str(
            message
            or ""
        ),
        "output": str(
            output
            or ""
        ),
        "hub_inventory": (
            plugin.get_local_plugin_inventory()
        ),
        "node_inventory": node_inventory,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "deployPluginResults",
        fissure.comms.MessageFields.PARAMETERS:
            PARAMETERS,
    }

    await component.dashboard_socket.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
    )


def _get_plugin_deployments(
    component: object,
):
    """Return/create HIPRFISR's pending plugin deployment map."""
    deployments = getattr(
        component,
        "_plugin_deployments",
        None,
    )

    if not isinstance(
        deployments,
        dict,
    ):
        deployments = {}
        component._plugin_deployments = (
            deployments
        )

    return deployments


async def _cancel_sensor_plugin_deployment(
    component: object,
    deployment: dict,
):
    """Release the Sensor Node reservation for a failed transfer."""
    node_uid = str(
        deployment.get(
            "node_uid",
            "",
        )
        or ""
    ).strip()

    node = (
        (component.nodes or {})
        .get(
            node_uid,
            {},
        )
        or {}
    )
    identity = node.get(
        "identity"
    )

    if identity is None:
        return

    PARAMETERS = {
        "plugin_name": str(
            deployment.get(
                "plugin_name",
                "",
            )
            or ""
        ),
        "transfer_id": str(
            deployment.get(
                "transfer_id",
                "",
            )
            or ""
        ),
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "cancelPluginDeployment",
        fissure.comms.MessageFields.PARAMETERS:
            PARAMETERS,
    }

    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[
            identity
        ],
    )


async def _stream_hub_plugin_package(
    component: object,
    deployment: dict,
):
    """Package one Hub plugin and stream it through the binary transfer plane."""
    node_uid = str(
        deployment.get(
            "node_uid",
            "",
        )
        or ""
    ).strip()
    plugin_name = str(
        deployment.get(
            "plugin_name",
            "",
        )
        or ""
    ).strip()
    transfer_id = str(
        deployment.get(
            "transfer_id",
            "",
        )
        or ""
    ).strip()

    package = None

    try:
        package = (
            plugin.create_plugin_package(
                plugin_name
            )
        )

        package_path = str(
            package.get(
                "package_path",
                "",
            )
            or ""
        )
        file_size = int(
            package.get(
                "file_size",
                0,
            )
            or 0
        )
        sha256 = str(
            package.get(
                "sha256",
                "",
            )
            or ""
        )

        hub_manifest = (
            plugin.get_plugin_manifest(
                plugin_name
            )
        )
        hub_version = str(
            hub_manifest.get(
                "version",
                "",
            )
            or ""
        )

        router = getattr(
            component,
            "artifact_transfer_router",
            None,
        )

        if router is None:
            raise RuntimeError(
                "HIPRFISR binary transfer router is unavailable"
            )

        if router.get_sensor_identity(
            node_uid
        ) is None:
            raise RuntimeError(
                "Remote Sensor Node is not connected "
                "to the binary transfer plane"
            )

        await router.send_local_start(
            node_uid,
            transfer_id,
            {
                "transfer_type":
                    "plugin_package_upload",
                "destination_node_uid":
                    node_uid,
                "plugin_name":
                    plugin_name,
                "hub_version":
                    hub_version,
                "filename":
                    os.path.basename(
                        package_path
                    ),
                "file_size":
                    file_size,
                "sha256":
                    sha256,
                "refresh_file_list":
                    False,
                "chunk_size":
                    fissure.comms.ARTIFACT_CHUNK_SIZE,
            },
        )

        sequence = 0
        bytes_sent = 0

        with open(
            package_path,
            "rb",
        ) as handle:
            while True:
                chunk = handle.read(
                    fissure.comms.ARTIFACT_CHUNK_SIZE
                )

                if not chunk:
                    break

                await router.send_local_chunk(
                    node_uid,
                    transfer_id,
                    sequence,
                    chunk,
                )

                sequence += 1
                bytes_sent += len(
                    chunk
                )

                await asyncio.sleep(
                    0
                )

        if bytes_sent != file_size:
            raise RuntimeError(
                "Hub plugin package changed during transfer"
            )

        await router.send_local_file_complete(
            node_uid,
            transfer_id,
            {
                "plugin_name":
                    plugin_name,
                "bytes_sent":
                    bytes_sent,
                "chunks_sent":
                    sequence,
                "sha256":
                    sha256,
            },
        )

        await router.send_local_complete(
            node_uid,
            transfer_id,
            {
                "plugin_name":
                    plugin_name,
                "bytes_sent":
                    bytes_sent,
                "chunks_sent":
                    sequence,
                "sha256":
                    sha256,
            },
        )

        component.logger.info(
            "Streamed Hub plugin package "
            "plugin=%s transfer_id=%s node_uid=%s "
            "bytes=%s chunks=%s",
            plugin_name,
            transfer_id,
            node_uid,
            bytes_sent,
            sequence,
        )

    except Exception as exc:
        deployments = (
            _get_plugin_deployments(
                component
            )
        )
        deployments.pop(
            transfer_id,
            None,
        )

        try:
            await _cancel_sensor_plugin_deployment(
                component,
                deployment,
            )
        except Exception:
            pass

        await _send_plugin_deploy_result(
            component,
            node_uid=node_uid,
            plugin_name=plugin_name,
            transfer_id=transfer_id,
            success=False,
            status="Transfer Failed",
            message=str(
                exc
            ),
        )

    finally:
        if package:
            package_path = str(
                package.get(
                    "package_path",
                    "",
                )
                or ""
            )

            if (
                package_path
                and os.path.isfile(
                    package_path
                )
            ):
                try:
                    os.remove(
                        package_path
                    )
                except OSError:
                    pass


async def deployPlugin(
    component: object,
    node_uid="",
    plugin_name="",
):
    """
    Begin one Hub -> remote Sensor Node Deploy/Update lifecycle.

    No package bytes are sent until the remote Sensor Node explicitly prepares.
    """
    node_uid = str(
        node_uid
        or ""
    ).strip()
    plugin_name = str(
        plugin_name
        or ""
    ).strip()

    hub_inventory = (
        plugin.get_local_plugin_inventory()
    )

    hub_plugin_entry = (
        hub_inventory.get(
            plugin_name,
            {},
        )
        or {}
    )

    required_plugins = [
        str(required_plugin).strip()
        for required_plugin in (
            hub_plugin_entry.get(
                "required_plugins",
                [],
            )
            or []
        )
        if str(required_plugin).strip()
    ]

    if plugin_name not in hub_inventory:
        await _send_plugin_deploy_result(
            component,
            node_uid=node_uid,
            plugin_name=plugin_name,
            success=False,
            status="Failed",
            message=(
                f"Hub plugin is not deployed: "
                f"{plugin_name}"
            ),
        )
        return

    node = (
        (component.nodes or {})
        .get(
            node_uid,
            {},
        )
        or {}
    )

    identity = node.get(
        "identity"
    )

    if identity is None:
        await _send_plugin_deploy_result(
            component,
            node_uid=node_uid,
            plugin_name=plugin_name,
            success=False,
            status="Failed",
            message=(
                "Selected Sensor Node is unavailable."
            ),
        )
        return

    if str(
        node.get(
            "network_type",
            "",
        )
        or ""
    ).strip().lower() != "ip":
        await _send_plugin_deploy_result(
            component,
            node_uid=node_uid,
            plugin_name=plugin_name,
            success=False,
            status="Failed",
            message=(
                "Plugin deployment currently requires "
                "an IP Sensor Node."
            ),
        )
        return

    deployments = (
        _get_plugin_deployments(
            component
        )
    )

    for pending in deployments.values():
        if not isinstance(
            pending,
            dict,
        ):
            continue

        if (
            pending.get(
                "node_uid"
            )
            == node_uid
            and pending.get(
                "plugin_name"
            )
            == plugin_name
        ):
            await _send_plugin_deploy_result(
                component,
                node_uid=node_uid,
                plugin_name=plugin_name,
                success=False,
                status="Blocked",
                message=(
                    f"{plugin_name} already has "
                    "a deployment in progress."
                ),
            )
            return

    transfer_id = str(
        uuid.uuid4()
    )

    deployment = {
        "node_uid":
            node_uid,
        "plugin_name":
            plugin_name,
        "transfer_id":
            transfer_id,
        "started_at":
            time.time(),
    }

    deployments[
        transfer_id
    ] = deployment

    PARAMETERS = {
        "plugin_name":
            plugin_name,
        "transfer_id":
            transfer_id,
        "required_plugins":
            required_plugins,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "preparePluginDeployment",
        fissure.comms.MessageFields.PARAMETERS:
            PARAMETERS,
    }

    try:
        await component.sensor_node_router.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
            target_ids=[
                identity
            ],
        )

    except Exception as exc:
        deployments.pop(
            transfer_id,
            None,
        )

        await _send_plugin_deploy_result(
            component,
            node_uid=node_uid,
            plugin_name=plugin_name,
            transfer_id=transfer_id,
            success=False,
            status="Failed",
            message=(
                "Could not prepare Sensor Node "
                f"for plugin deployment: {exc}"
            ),
        )


async def preparePluginDeploymentResults(
    component: object,
    node_uid="",
    plugin_name="",
    transfer_id="",
    success=False,
    message="",
):
    """Stream package bytes only after the remote Sensor Node approves."""
    deployments = (
        _get_plugin_deployments(
            component
        )
    )

    deployment = deployments.get(
        transfer_id
    )

    if not isinstance(
        deployment,
        dict,
    ):
        component.logger.warning(
            "Ignoring unknown plugin deployment preparation "
            "transfer_id=%s",
            transfer_id,
        )
        return

    if (
        deployment.get(
            "node_uid"
        )
        != node_uid
        or deployment.get(
            "plugin_name"
        )
        != plugin_name
    ):
        deployments.pop(
            transfer_id,
            None,
        )

        await _send_plugin_deploy_result(
            component,
            node_uid=node_uid,
            plugin_name=plugin_name,
            transfer_id=transfer_id,
            success=False,
            status="Failed",
            message=(
                "Plugin deployment preparation "
                "did not match the pending request."
            ),
        )
        return

    if not success:
        deployments.pop(
            transfer_id,
            None,
        )

        await _send_plugin_deploy_result(
            component,
            node_uid=node_uid,
            plugin_name=plugin_name,
            transfer_id=transfer_id,
            success=False,
            status="Blocked",
            message=str(
                message
                or "Sensor Node rejected plugin deployment."
            ),
        )
        return

    await _stream_hub_plugin_package(
        component,
        deployment,
    )


async def finalizePluginDeploymentResults(
    component: object,
    node_uid="",
    plugin_name="",
    transfer_id="",
    success=False,
    status="",
    message="",
    output="",
    node_inventory=None,
):
    """Complete one pending deployment and return the refreshed inventory."""
    deployments = (
        _get_plugin_deployments(
            component
        )
    )

    deployments.pop(
        transfer_id,
        None,
    )

    await _send_plugin_deploy_result(
        component,
        node_uid=node_uid,
        plugin_name=plugin_name,
        transfer_id=transfer_id,
        success=success,
        status=status,
        message=message,
        output=output,
        node_inventory=node_inventory,
    )


async def _send_plugin_remove_result(
    component: object,
    *,
    node_uid="",
    plugin_name="",
    success=False,
    status="",
    message="",
    output="",
    node_inventory=None,
):
    """Send one managed Remove result and current Hub inventory to Dashboard."""
    if not component.dashboard_connected:
        return

    PARAMETERS = {
        "node_uid": node_uid,
        "plugin_name": plugin_name,
        "success": bool(
            success
        ),
        "status": str(
            status
            or ""
        ),
        "message": str(
            message
            or ""
        ),
        "output": str(
            output
            or ""
        ),
        "hub_inventory": (
            plugin.get_local_plugin_inventory()
        ),
        "node_inventory": node_inventory,
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "removeManagedPluginResults",
        fissure.comms.MessageFields.PARAMETERS:
            PARAMETERS,
    }

    await component.dashboard_socket.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
    )


async def removeManagedPlugin(
    component: object,
    node_uid="",
    plugin_name="",
):
    """Request managed plugin removal on the selected Sensor Node."""
    node_uid = str(
        node_uid
        or ""
    ).strip()

    plugin_name = str(
        plugin_name
        or ""
    ).strip()

    node = (
        (component.nodes or {})
        .get(
            node_uid,
            {},
        )
        or {}
    )

    identity = node.get(
        "identity"
    )

    if identity is None:
        await _send_plugin_remove_result(
            component,
            node_uid=node_uid,
            plugin_name=plugin_name,
            success=False,
            status="Failed",
            message="Selected Sensor Node is unavailable.",
        )
        return

    PARAMETERS = {
        "plugin_name":
            plugin_name,
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "removeManagedPlugin",
        fissure.comms.MessageFields.PARAMETERS:
            PARAMETERS,
    }

    try:
        await component.sensor_node_router.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
            target_ids=[
                identity
            ],
        )

    except Exception as exc:
        await _send_plugin_remove_result(
            component,
            node_uid=node_uid,
            plugin_name=plugin_name,
            success=False,
            status="Failed",
            message=(
                f"Could not request plugin removal: {exc}"
            ),
        )


async def removeManagedPluginResults(
    component: object,
    node_uid="",
    plugin_name="",
    success=False,
    status="",
    message="",
    output="",
    node_inventory=None,
):
    """Forward one managed plugin-removal result to the Dashboard."""
    await _send_plugin_remove_result(
        component,
        node_uid=node_uid,
        plugin_name=plugin_name,
        success=success,
        status=status,
        message=message,
        output=output,
        node_inventory=node_inventory,
    )


async def stop_plugin_operation(component: object, node_uid: str, operation_id: str):
    """Stop a running plugin operation on the sensor node.

    Parameters
    ----------
    component : object
        Component
    node_uid : str
        Sensor node UID
    operation_id : str
        Unique identifier for the operation to stop
    """
    PARAMETERS = {
        "operation_id": operation_id,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "stop_plugin_operation",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def stop_all_plugin_operations(
    component: object,
    requester_uid: str,
    requester_type: str,
    node_uids: List[str],
):
    """Stop all running plugin operations on selected sensor nodes.

    Parameters
    ----------
    component : object
        Component.
    requester_uid : str
        Requesting client UID.
    requester_type : str
        dashboard, tak, or broadcast.
    node_uids : List[str]
        List of sensor node UIDs.
    """
    if not node_uids:
        component.logger.warning(
            "No node UIDs provided for stop_all_plugin_operations."
        )
        return

    for node_uid in node_uids:
        component.logger.info(
            f"Stopping all plugin operations on sensor node {node_uid}"
        )

        node_record = component.nodes.get(node_uid)
        if not node_record:
            component.logger.warning(
                f"Cannot stop plugin operations for unknown node UID: {node_uid}"
            )
            continue

        identity = node_record.get("identity", None)
        if identity is None:
            component.logger.warning(
                f"Cannot stop plugin operations for node {node_uid}: missing identity."
            )
            continue

        PARAMETERS = {
            "requester_uid": requester_uid,
            "requester_type": requester_type,
        }

        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "stop_all_plugin_operations",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }

        await component.sensor_node_router.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
            target_ids=[identity],
        )


async def sendPluginNamesTak(
    component: object, 
    requester_uid: str, 
    requester_type: str, 
    node_uid: str, 
    tak_context: str
):
    """Request Sensor Node plugin names for TAK

    Parameters
    ----------
    component : object
        Component
    requester_uid : str
        TAK unique identifier
    requester_type : str
        dashboard, tak, or broadcast
    node_uid : str
        Sensor node UUID
    tak_context : str
        node or ecosystem
    """
    PARAMETERS = {
        "requester_uid": requester_uid,
        "requester_type": requester_type,
        "node_uid": node_uid,
        "tak_context": tak_context
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "sendPluginNamesTak",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def sendPluginNamesTakResults(
    component: object, 
    requester_uid: str, 
    requester_type: str, 
    node_uid: str, 
    plugin_names: List[str], 
    tak_context: str
):
    """Handle Sensor Node plugin names for TAK

    Parameters
    ----------
    component : object
        Component
    requester_uid : str
        TAK unique identifier
    requester_type : str
        dashboard, tak, or broadcast        
    node_uid : str
        Sensor node UID
    plugin_names : List[str]
        Plugin names
    tak_context : str
        node or ecosystem
    """
    component.logger.debug(f"Preparing to send TAK plugin names for TAK UID: {requester_uid}")

    event_uid = f"{requester_uid}-pluginlist-{int(time.time()*1000)}"

    if tak_context == "ecosystem":
        msg = {
            "msg_type": "event",
            "uid": event_uid,
            "data": {
                "event_type": "ecosystem_plugin_list",
                "plugins": plugin_names
            }
        }
    else:
        msg = {
            "msg_type": "event",
            "uid": event_uid,
            "data": {
                "event_type": "plugin_list",
                "plugins": plugin_names
            }
        }

    await fissure.utils.tak_messages.send(component, msg, requester_type, requester_uid)


async def sendPluginActionNamesTak(
    component: object, 
    requester_uid: str, 
    requester_type: str, 
    plugin_name: str, 
    node_uid: str, 
    tak_context: str
):
    """Request Sensor Node plugin action names for TAK

    Parameters
    ----------
    component : object
        Component
    requester_uid : str
        TAK unique identifier
    requester_type : str
        dashboard, tak, or broadcast         
    plugin_name : str
        Plugin name
    node_uid : str
        Sensor node UID
    tak_context : str
        node or ecosystem
    """
    PARAMETERS = {
        "requester_uid": requester_uid,
        "requester_type": requester_type,
        "plugin_name": plugin_name,
        "node_uid": node_uid,
        "tak_context": tak_context
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "sendPluginActionNamesTak",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )


async def sendPluginActionNamesTakResults(
    component: object, 
    requester_uid: str, 
    requester_type: str, 
    node_uid: str, 
    plugin_name: str, 
    action_names: List[str], 
    tak_context: str
):
    """Handle Sensor Node plugin action names for TAK

    Parameters
    ----------
    component : object
        Component
    requester_uid : str
        TAK unique identifier
    node_uid : str
        Sensor node UID
    requester_type : str
        dashboard, tak, or broadcast       
    plugin_name : str
        Plugin name
    action_names : List[str]
        Plugin action names
    tak_context : str
        node or ecosystem
    """
    component.logger.debug(f"Preparing to send TAK plugin action names for TAK UID: {requester_uid}")

    # Generate unique event UID
    event_uid = f"{requester_uid}-actions-{int(time.time() * 1000)}"

    if tak_context == "ecosystem":
        msg = {
            "msg_type": "event",
            "uid": event_uid,
            "data": {
                "event_type": "ecosystem_plugin_actions",   # <plugin_actions> in XML
                "plugin_name": plugin_name,       # scalar
                "actions": action_names           # list
            }
        }
    else:
        msg = {
            "msg_type": "event",
            "uid": event_uid,
            "data": {
                "event_type": "plugin_actions",   # <plugin_actions> in XML
                "plugin_name": plugin_name,       # scalar
                "actions": action_names           # list
            }
        }

    await fissure.utils.tak_messages.send(component, msg, requester_type, requester_uid)


async def sendPluginActionTak(
    component: object,
    requester_uid: str,
    requester_type: str,
    node_uids: List[str],
    plugin_name: str,
    action_name: str,
    parameters: dict,
):
    """Request Sensor Node plugin action for selected sensor nodes.

    Parameters
    ----------
    component : object
        Component.
    requester_uid : str
        Requesting client UID.
    requester_type : str
        dashboard, tak, or broadcast.
    node_uids : List[str]
        List of sensor node UIDs.
    plugin_name : str
        Plugin name.
    action_name : str
        Plugin action name.
    parameters : dict
        Plugin action parameters.
    """
    if not node_uids:
        component.logger.warning("No node UIDs provided for sendPluginActionTak.")
        return

    for node_uid in node_uids:
        component.logger.info(
            f"Requesting plugin action '{plugin_name}.{action_name}' "
            f"from node {node_uid}"
        )

        node_record = component.nodes.get(node_uid)
        if not node_record:
            component.logger.warning(
                f"Cannot execute plugin action for unknown node UID: {node_uid}"
            )
            continue

        identity = node_record.get("identity", None)
        if identity is None:
            component.logger.warning(
                f"Cannot execute plugin action for node {node_uid}: missing identity."
            )
            continue

        PARAMETERS = {
            "requester_uid": requester_uid,
            "requester_type": requester_type,
            "plugin_name": plugin_name,
            "action_name": action_name,
            "parameters": parameters,
        }

        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "plugin_action",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }

        await component.sensor_node_router.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
            target_ids=[identity],
        )


async def sendPluginActionParametersTak(
    component: object, 
    requester_uid: str, 
    requester_type: str, 
    node_uid: str, 
    plugin_name: str, 
    action_name: str, 
    tak_context: str
):
    """Request Sensor Node plugin action parameters for TAK

    Parameters
    ----------
    component : object
        Component
    requester_uid : str
        TAK unique identifier
    requester_type : str
        dashboard, tak, or broadcast               
    node_uid : str
        Sensor node UID
    plugin_name : str
        Plugin name
    action_name : str
        Plugin action name
    tak_context : str
        node or ecosystem
    """
    PARAMETERS = {
        "requester_uid": requester_uid,
        "requester_type": requester_type,
        "plugin_name": plugin_name,
        "action_name": action_name,
        "node_uid": node_uid,
        "tak_context": tak_context
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "sendPluginActionParametersTak",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    # Resolve Identity
    identity = component.nodes[node_uid].get("identity", None)
    if identity is None:
        return
    
    # Send through ROUTER
    await component.sensor_node_router.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
        target_ids=[identity]
    )    


async def updateArtifact(
    component: object,
    artifact: dict,
) -> None:
    """
    Store and publish one canonical manifest-only Artifact record.

    HIPRFISR does not rewrite Sensor Node paths, create sensor:// URIs, or
    inspect payload files. The declared files manifest is authoritative.
    """
    if not isinstance(artifact, dict):
        component.logger.error(
            "Invalid artifact update: artifact is not a dict"
        )
        return

    artifact_id = str(
        artifact.get("id", "")
        or ""
    ).strip()

    if not artifact_id:
        component.logger.error(
            "Artifact missing 'id' field"
        )
        return

    files = artifact.get("files")
    relations = artifact.get("relations")
    metadata = artifact.get("metadata")

    if not isinstance(files, list):
        component.logger.error(
            "Artifact %s has no valid files manifest",
            artifact_id,
        )
        return

    if not isinstance(relations, list):
        component.logger.error(
            "Artifact %s has no valid relations list",
            artifact_id,
        )
        return

    if not isinstance(metadata, dict):
        component.logger.error(
            "Artifact %s has no valid metadata object",
            artifact_id,
        )
        return

    try:
        component.artifact_tracker.update_artifact(
            artifact
        )
    except Exception:
        component.logger.exception(
            "Failed storing artifact %s",
            artifact_id,
        )
        return

    source_id = str(
        artifact.get("source_id", "")
        or ""
    ).strip()

    if component.dashboard_connected:
        dashboard_msg = {
            fissure.comms.MessageFields.IDENTIFIER:
                component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME:
                "sendArtifactsListTakReturn",
            fissure.comms.MessageFields.PARAMETERS: {
                "node_uid": source_id,
                "artifacts": [artifact],
            },
        }

        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            dashboard_msg,
        )

    name = str(
        artifact.get("name", "")
        or ""
    ).strip()
    timestamp = str(
        artifact.get("modified_at", "")
        or artifact.get("created_at", "")
        or ""
    ).strip()

    if not name or not timestamp:
        component.logger.error(
            "Artifact %s cannot emit TAK metadata "
            "without name and timestamp",
            artifact_id,
        )
        return

    msg = {
        "msg_type": "event",
        "uid": (
            f"{source_id or 'unknown-source'}"
            f"-artifact_metadata-"
            f"{int(time.time() * 1000)}"
        ),
        "data": {
            "event_type": "artifact_metadata",
            "name": name,
            "timestamp": timestamp,
            "artid": artifact_id,
            "operation_id": str(
                artifact.get(
                    "operation_id",
                    "",
                )
                or ""
            ),
            "source_id": source_id,
            "artifact_type": str(
                artifact.get(
                    "artifact_type",
                    "",
                )
                or ""
            ),
            "file_count": int(
                artifact.get(
                    "file_count",
                    len(files),
                )
                or len(files)
            ),
            "total_size": int(
                artifact.get(
                    "total_size",
                    sum(
                        int(
                            item.get("size", 0)
                            or 0
                        )
                        for item in files
                        if isinstance(
                            item,
                            dict,
                        )
                    ),
                )
                or 0
            ),
        },
    }

    await fissure.utils.tak_messages.send(
        component,
        msg,
    )


async def requestDashboardArtifactTransfer(
        component: object,
        transfer_id: str,
        artifact_id: str,
    ) -> None:
    """Coordinate one Sensor Node-to-Dashboard artifact stream."""
    artifact = component.artifact_tracker.get_artifact(artifact_id)
    if artifact is None:
        await _send_dashboard_artifact_status(
            component, transfer_id, artifact_id, False, "Artifact metadata not found"
        )
        return

    source_id = artifact.source_id
    identity = component.nodes.get(source_id, {}).get("identity")
    if identity is None:
        await _send_dashboard_artifact_status(
            component, transfer_id, artifact_id, False, "Source Sensor Node is unavailable"
        )
        return

    if not component.artifact_transfer_router.register_transfer(
        transfer_id, fissure.comms.ROLE_DASHBOARD
    ):
        await _send_dashboard_artifact_status(
            component, transfer_id, artifact_id, False, "Dashboard transfer channel is unavailable"
        )
        return

    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "streamArtifact",
        fissure.comms.MessageFields.PARAMETERS: {
            "transfer_id": transfer_id,
            "artifact_id": artifact_id,
        },
    }
    try:
        await component.sensor_node_router.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
            target_ids=[identity],
        )
    except Exception as exc:
        component.artifact_transfer_router.remove_transfer(transfer_id)
        await _send_dashboard_artifact_status(
            component, transfer_id, artifact_id, False, f"Unable to request artifact stream: {exc}"
        )


async def _send_dashboard_artifact_status(
        component: object,
        transfer_id: str,
        artifact_id: str,
        success: bool,
        message: str,
    ) -> None:
    if not component.dashboard_connected:
        return
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "dashboardArtifactTransferStatus",
        fissure.comms.MessageFields.PARAMETERS: {
            "transfer_id": transfer_id,
            "artifact_id": artifact_id,
            "success": success,
            "message": message,
        },
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


def _collect_record_artifact_ids(
    record: dict,
) -> List[str]:
    """
    Return deduplicated artifact IDs from modern and compatibility fields.
    """
    if not isinstance(record, dict):
        return []

    artifact_ids = []

    def add_artifact_id(value):
        artifact_id = str(
            value or ""
        ).strip()

        if (
            artifact_id
            and artifact_id not in artifact_ids
        ):
            artifact_ids.append(
                artifact_id
            )

    modern_ids = record.get(
        "artifact_ids"
    )

    if isinstance(modern_ids, list):
        for artifact_id in modern_ids:
            add_artifact_id(
                artifact_id
            )

    modern_links = record.get(
        "artifact_links"
    )

    if isinstance(modern_links, list):
        for link in modern_links:
            if isinstance(link, dict):
                add_artifact_id(
                    link.get("artifact_id")
                    or link.get("id")
                )
            else:
                add_artifact_id(
                    link
                )

    compatibility_id = record.get(
        "artifact_id"
    )

    add_artifact_id(
        compatibility_id
    )

    return artifact_ids


def _render_record_text(
    value,
    indent: int = 0,
) -> List[str]:
    """
    Render nested record data into a readable plain-text snapshot.
    """
    prefix = " " * indent
    lines = []

    if isinstance(value, dict):
        for key, child_value in value.items():
            label = str(key)

            if isinstance(
                child_value,
                (dict, list),
            ):
                lines.append(
                    f"{prefix}{label}:"
                )

                lines.extend(
                    _render_record_text(
                        child_value,
                        indent + 2,
                    )
                )
            else:
                lines.append(
                    f"{prefix}{label}: {child_value}"
                )

        return lines

    if isinstance(value, list):
        if not value:
            return [
                f"{prefix}[]"
            ]

        for index, child_value in enumerate(
            value
        ):
            if isinstance(
                child_value,
                (dict, list),
            ):
                lines.append(
                    f"{prefix}[{index}]"
                )

                lines.extend(
                    _render_record_text(
                        child_value,
                        indent + 2,
                    )
                )
            else:
                lines.append(
                    f"{prefix}[{index}] {child_value}"
                )

        return lines

    return [
        f"{prefix}{value}"
    ]


def _write_record_snapshots(
    staging_root: str,
    record_name: str,
    record: dict,
) -> None:
    json_path = os.path.join(
        staging_root,
        f"{record_name}_details.json",
    )

    text_path = os.path.join(
        staging_root,
        f"{record_name}_details.txt",
    )

    with open(
        json_path,
        "w",
        encoding="utf-8",
    ) as json_handle:
        json.dump(
            record,
            json_handle,
            indent=2,
            sort_keys=False,
            default=str,
        )

    text_lines = _render_record_text(
        record
    )

    with open(
        text_path,
        "w",
        encoding="utf-8",
    ) as text_handle:
        text_handle.write(
            "\n".join(text_lines)
        )
        text_handle.write("\n")


async def _ensure_hiprfisr_artifact_cached(
    component: object,
    artifact_id: str,
    timeout_seconds: float = 60.0,
) -> str:
    """
    Reuse a verified HIPRFISR cache entry or request the artifact and wait for
    the existing transfer controller to commit it.
    """
    artifact_id = str(
        artifact_id or ""
    ).strip()

    if not artifact_id:
        raise ValueError(
            "artifact_id is required"
        )

    controller = (
        component.artifact_transfer_controller
    )

    local_path = (
        controller.get_local_path(
            artifact_id
        )
    )

    if local_path:
        return local_path

    await transferArtifactRequest(
        component,
        artifact_id,
        "hiprfisr",
    )

    loop = asyncio.get_running_loop()
    deadline = (
        loop.time()
        + timeout_seconds
    )

    while loop.time() < deadline:
        local_path = (
            controller.get_local_path(
                artifact_id
            )
        )

        if local_path:
            return local_path

        await asyncio.sleep(
            0.1
        )

    raise TimeoutError(
        "Timed out waiting for artifact "
        f"{artifact_id}"
    )


def _copy_cached_artifact_to_staging(
    component: object,
    artifact_id: str,
    artifacts_root: str,
) -> None:
    """
    Copy one complete verified cached artifact into the disposable package tree.
    """
    controller = (
        component.artifact_transfer_controller
    )

    cache_record = (
        controller.local_cache.get(
            artifact_id,
            {},
        )
    )

    artifact_destination = (
        os.path.join(
            artifacts_root,
            artifact_id,
        )
    )

    artifact_root = ""

    if isinstance(cache_record, dict):
        artifact_root = str(
            cache_record.get(
                "artifact_root",
                "",
            )
            or ""
        ).strip()

    if (
        artifact_root
        and os.path.isdir(
            artifact_root
        )
    ):
        shutil.copytree(
            artifact_root,
            artifact_destination,
        )
        return

    local_path = (
        controller.get_local_path(
            artifact_id
        )
    )

    if not local_path:
        raise RuntimeError(
            "Verified artifact cache path missing: "
            f"{artifact_id}"
        )

    if os.path.isdir(
        local_path
    ):
        shutil.copytree(
            local_path,
            artifact_destination,
        )
        return

    os.makedirs(
        artifact_destination,
        exist_ok=True,
    )

    shutil.copy2(
        local_path,
        os.path.join(
            artifact_destination,
            os.path.basename(
                local_path
            ),
        ),
    )


async def _send_record_package_tak(
    component: object,
    record_type: str,
    record_id: str,
    record: dict,
    requester_uid: str = "",
) -> None:
    """
    Rebuild and transmit one fresh SOI or Target Mission Package.
    """
    record_type = str(
        record_type or ""
    ).strip().lower()

    record_id = str(
        record_id or ""
    ).strip()

    if record_type not in (
        "soi",
        "target",
    ):
        raise ValueError(
            f"Unsupported record type: {record_type}"
        )

    if not record_id:
        raise ValueError(
            f"{record_type} ID is required"
        )

    if not isinstance(
        record,
        dict,
    ):
        raise TypeError(
            f"{record_type} record must be a dictionary"
        )

    artifact_ids = (
        _collect_record_artifact_ids(
            record
        )
    )

    for artifact_id in artifact_ids:
        await _ensure_hiprfisr_artifact_cached(
            component,
            artifact_id,
        )

    staging_root = tempfile.mkdtemp(
        prefix=(
            f"fissure_{record_type}_"
            f"{record_id[:16]}_"
        )
    )

    try:
        _write_record_snapshots(
            staging_root,
            record_type,
            record,
        )

        if artifact_ids:
            artifacts_root = os.path.join(
                staging_root,
                "artifacts",
            )

            os.makedirs(
                artifacts_root,
                exist_ok=True,
            )

            for artifact_id in artifact_ids:
                _copy_cached_artifact_to_staging(
                    component,
                    artifact_id,
                    artifacts_root,
                )

        package_name = (
            f"FISSURE_{record_type.upper()}_"
            f"{record_id}"
        )

        package_uid = (
            f"{record_type}-{record_id}-"
            f"{uuid.uuid4()}"
        )

        await (
            fissure.utils.tak_messages
            .send_fissure_record_data_package(
                component,
                package_uid=package_uid,
                package_name=package_name,
                source_root=staging_root,
                sender_source_id=(
                    record.get("node_uid")
                    or component.identifier
                ),
                destination="tak",
                requester_uid=(
                    requester_uid
                    or None
                ),
            )
        )

    finally:
        shutil.rmtree(
            staging_root,
            ignore_errors=True,
        )


async def sendSoiEvidencePackageTak(
    component: object,
    soi_id: str,
    requester_uid: str = "",
) -> None:
    """
    Send a freshly rebuilt package for the complete authoritative SOI.
    """
    soi_id = str(
        soi_id or ""
    ).strip()

    if not soi_id:
        raise ValueError(
            "soi_id is required"
        )

    soi_store = (
        getattr(
            component,
            "sois",
            {},
        )
        or {}
    )

    record = None

    if isinstance(
        soi_store,
        dict,
    ):
        direct_record = (
            soi_store.get(
                soi_id
            )
        )

        if isinstance(
            direct_record,
            dict,
        ):
            record = direct_record
        else:
            for candidate in soi_store.values():
                if (
                    isinstance(candidate, dict)
                    and str(
                        candidate.get(
                            "soi_id",
                            "",
                        )
                        or ""
                    ).strip()
                    == soi_id
                ):
                    record = candidate
                    break

    elif isinstance(
        soi_store,
        list,
    ):
        for candidate in soi_store:
            if (
                isinstance(candidate, dict)
                and str(
                    candidate.get(
                        "soi_id",
                        "",
                    )
                    or ""
                ).strip()
                == soi_id
            ):
                record = candidate
                break

    if not isinstance(
        record,
        dict,
    ):
        raise KeyError(
            f"SOI not found: {soi_id}"
        )

    await _send_record_package_tak(
        component,
        record_type="soi",
        record_id=soi_id,
        record=dict(record),
        requester_uid=requester_uid,
    )


async def sendTargetDataPackageTak(
    component: object,
    target_id: str,
    requester_uid: str = "",
) -> None:
    """
    Send a freshly rebuilt package for the complete authoritative Target.

    Only Target-owned artifact_ids/artifact_links are included. source_soi_id
    is preserved in the snapshot but source SOI artifacts are not traversed.
    """
    target_id = str(
        target_id or ""
    ).strip()

    if not target_id:
        raise ValueError(
            "target_id is required"
        )

    target_store = (
        getattr(
            component,
            "targets",
            {},
        )
        or {}
    )

    record = None

    if isinstance(
        target_store,
        dict,
    ):
        direct_record = (
            target_store.get(
                target_id
            )
        )

        if isinstance(
            direct_record,
            dict,
        ):
            record = direct_record
        else:
            for candidate in target_store.values():
                if (
                    isinstance(candidate, dict)
                    and str(
                        candidate.get(
                            "target_id",
                            "",
                        )
                        or ""
                    ).strip()
                    == target_id
                ):
                    record = candidate
                    break

    if not isinstance(
        record,
        dict,
    ):
        raise KeyError(
            f"Target not found: {target_id}"
        )

    await _send_record_package_tak(
        component,
        record_type="target",
        record_id=target_id,
        record=dict(record),
        requester_uid=requester_uid,
    )


async def transferArtifactRequest(
    component: object,
    artifact_id: str,
    destination: str,
) -> None:
    """
    Retrieve a complete artifact for HIPRFISR or TAK through the dedicated
    binary data plane.

    Inline payload bytes are no longer accepted.
    """
    artifact = (
        component.artifact_tracker
        .get_artifact(
            artifact_id
        )
    )

    if artifact is None:
        component.logger.error(
            "Artifact metadata not found: %s",
            artifact_id,
        )
        return

    local_path = (
        component.artifact_transfer_controller
        .get_local_path(
            artifact_id
        )
    )

    if local_path is not None:
        if destination == "tak":
            await (
                component.artifact_transfer_controller
                ._send_cached_artifact_to_tak(
                    artifact
                )
            )

        elif destination == "hiprfisr":
            component.logger.info(
                "Artifact %s is already cached at HIPRFISR",
                artifact_id,
            )

        return

    source_id = artifact.source_id
    identity = component.nodes.get(
        source_id,
        {},
    ).get("identity")

    if identity is None:
        component.logger.error(
            "Could not resolve Sensor Node identity for %s",
            source_id,
        )
        return

    transfer_id = str(uuid.uuid4())

    component.artifact_transfer_controller.register_request(
        transfer_id=transfer_id,
        artifact_id=artifact_id,
        destination=destination,
    )

    if not component.artifact_transfer_router.register_transfer(
        transfer_id,
        fissure.comms.ROLE_HIPRFISR,
    ):
        component.artifact_transfer_controller.fail(
            transfer_id,
            "Unable to register HIPRFISR artifact receiver",
        )
        return

    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "streamArtifact",
        fissure.comms.MessageFields.PARAMETERS: {
            "transfer_id": transfer_id,
            "artifact_id": artifact_id,
        },
    }

    try:
        await component.sensor_node_router.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
            target_ids=[identity],
        )

    except Exception as exc:
        component.artifact_transfer_router.remove_transfer(
            transfer_id
        )
        component.artifact_transfer_controller.fail(
            transfer_id,
            str(exc),
        )


def _merge_soi_artifact_links(
    existing_links,
    incoming_links,
):
    """
    Merge SOI artifact links while preserving insertion order.

    artifact_id is the stable identity. Repeated updates for the same artifact
    enrich the existing link instead of creating duplicate entries. The link
    remains intentionally field-agnostic so operations may attach whatever
    relationship context they need.
    """
    merged = []
    index_by_artifact_id = {}

    for source in (
        existing_links,
        incoming_links,
    ):
        if not isinstance(source, list):
            continue

        for link in source:
            if not isinstance(link, dict):
                continue

            artifact_id = str(
                link.get("artifact_id", "")
                or ""
            ).strip()

            if not artifact_id:
                continue

            if artifact_id in index_by_artifact_id:
                merged[
                    index_by_artifact_id[artifact_id]
                ].update(link)
                continue

            normalized_link = dict(link)
            normalized_link["artifact_id"] = artifact_id

            index_by_artifact_id[artifact_id] = len(merged)
            merged.append(normalized_link)

    return merged


def _merge_soi_detection_snapshots(
    existing_snapshots,
    incoming_snapshots,
):
    """
    Append complete detection snapshots while suppressing duplicate callbacks.

    A stable detection/event identifier is preferred. When none exists, the
    complete normalized snapshot is used as the duplicate key so unkeyed but
    distinct detections are still preserved.
    """
    merged = []
    seen_keys = set()

    def snapshot_key(snapshot):
        for key in (
            "detection_id",
            "event_uid",
            "uid",
            "event_id",
        ):
            value = str(snapshot.get(key, "") or "").strip()
            if value:
                return (key, value)

        try:
            return (
                "snapshot",
                json.dumps(
                    snapshot,
                    sort_keys=True,
                    default=str,
                ),
            )
        except Exception:
            return ("snapshot", repr(snapshot))

    for source in (
        existing_snapshots,
        incoming_snapshots,
    ):
        if not isinstance(source, list):
            continue

        for snapshot in source:
            if not isinstance(snapshot, dict):
                continue

            key = snapshot_key(snapshot)
            if key in seen_keys:
                continue

            seen_keys.add(key)
            merged.append(dict(snapshot))

    return merged


def _merge_soi_analysis_history(
    existing_history,
    incoming_history,
):
    """
    Append operation-supplied SOI analysis records.

    Each execution normally has a unique operation_id. Receiving the same
    operation_id again is treated as a duplicate/update callback and enriches
    that entry rather than duplicating it. Records without an operation_id are
    preserved and deduplicated by their complete content.
    """
    merged = []
    index_by_key = {}

    def history_key(entry):
        operation_id = str(
            entry.get("operation_id", "")
            or ""
        ).strip()

        if operation_id:
            return ("operation_id", operation_id)

        analysis_id = str(
            entry.get("analysis_id", "")
            or ""
        ).strip()

        if analysis_id:
            return ("analysis_id", analysis_id)

        try:
            return (
                "entry",
                json.dumps(
                    entry,
                    sort_keys=True,
                    default=str,
                ),
            )
        except Exception:
            return ("entry", repr(entry))

    for source in (
        existing_history,
        incoming_history,
    ):
        if not isinstance(source, list):
            continue

        for entry in source:
            if not isinstance(entry, dict):
                continue

            key = history_key(entry)

            if key in index_by_key:
                merged[index_by_key[key]].update(entry)
                continue

            index_by_key[key] = len(merged)
            merged.append(dict(entry))

    return merged


async def soiUpdate(component: object,
                    node_uid="",
                    soi_id="",
                    frequency_mhz=None,
                    status="",
                    operation_id="",
                    artifact_id="",
                    summary=None,
                    lat=None,
                    lon=None,
                    alt=None,
                    observation_time=None
                    ):
    """
    Store an authoritative, cumulative SOI record at HIPRFISR.

    SOIs are append-oriented investigation records:
    - artifact links accumulate by artifact_id;
    - detection snapshots accumulate by detection/event identity;
    - analysis history contains only records explicitly supplied by operations;
    - partial updates do not erase previously known values.

    Location contract:
    SensorNode.send_soi_update() resolves True to live node GPS/time values.
    This hub callback receives concrete values and preserves prior values only
    when a field is omitted or empty.

    Merge an SOI update into HIPRFISR's canonical SOI store and emit the
    resulting record through the Tactical/TAK SOI path.
    """
    if summary is None or not isinstance(summary, dict):
        summary = {}

    if soi_id:
        soi_key = f"{node_uid}:{soi_id}"
    else:
        soi_key = f"{node_uid}:{operation_id or 'unknown'}"

    now = time.time()
    existing = component.sois.get(soi_key, {})

    if not isinstance(existing, dict):
        existing = {}

    existing_summary = existing.get("summary", {})
    if not isinstance(existing_summary, dict):
        existing_summary = {}

    stage_supplied = "stage" in summary
    stage_order_supplied = "stage_order" in summary

    incoming_stage = summary.get("stage")
    incoming_stage_order = summary.get("stage_order")

    try:
        incoming_stage_order = (
            int(incoming_stage_order)
            if incoming_stage_order is not None
            else None
        )
    except Exception:
        incoming_stage_order = None

    previous_stage_order = existing.get("stage_order")
    try:
        previous_stage_order = (
            int(previous_stage_order)
            if previous_stage_order is not None
            else None
        )
    except Exception:
        previous_stage_order = None

    if (
        stage_order_supplied
        and incoming_stage_order is not None
        and previous_stage_order is not None
        and incoming_stage_order < previous_stage_order
    ):
        component.logger.info(
            "Ignoring out-of-order SOI update "
            f"(new={incoming_stage_order} < prev={previous_stage_order})"
        )
        return

    merged_summary = dict(existing_summary)

    collection_keys = {
        "artifact_links",
        "artifact_ids",
        "detection_snapshots",
        "detection_ids",
        "analysis_history",
    }

    for key, value in summary.items():
        if key not in collection_keys:
            merged_summary[key] = value

    existing_artifact_links = existing.get(
        "artifact_links",
        existing_summary.get("artifact_links", []),
    )
    incoming_artifact_links = summary.get("artifact_links", [])

    merged_artifact_links = _merge_soi_artifact_links(
        existing_artifact_links,
        incoming_artifact_links,
    )

    incoming_artifact_ids = summary.get("artifact_ids", [])
    if not isinstance(incoming_artifact_ids, list):
        incoming_artifact_ids = [incoming_artifact_ids]

    compatibility_links = []

    for linked_artifact_id in incoming_artifact_ids:
        linked_artifact_id = str(
            linked_artifact_id or ""
        ).strip()

        if linked_artifact_id:
            compatibility_links.append({
                "artifact_id": linked_artifact_id,
                "operation_id": operation_id,
            })

    artifact_id = str(artifact_id or "").strip()

    if artifact_id:
        compatibility_links.append({
            "artifact_id": artifact_id,
            "operation_id": operation_id,
        })

    merged_artifact_links = _merge_soi_artifact_links(
        merged_artifact_links,
        compatibility_links,
    )

    artifact_ids = []
    for link in merged_artifact_links:
        linked_artifact_id = str(
            link.get("artifact_id", "")
            or ""
        ).strip()

        if (
            linked_artifact_id
            and linked_artifact_id not in artifact_ids
        ):
            artifact_ids.append(linked_artifact_id)

    existing_detection_snapshots = existing.get(
        "detection_snapshots",
        existing_summary.get("detection_snapshots", []),
    )
    incoming_detection_snapshots = summary.get(
        "detection_snapshots",
        [],
    )

    if not isinstance(incoming_detection_snapshots, list):
        incoming_detection_snapshots = [
            incoming_detection_snapshots
        ]

    merged_detection_snapshots = _merge_soi_detection_snapshots(
        existing_detection_snapshots,
        incoming_detection_snapshots,
    )

    detection_ids = []
    for snapshot in merged_detection_snapshots:
        detection_id = ""

        for key in (
            "detection_id",
            "event_uid",
            "uid",
            "event_id",
        ):
            detection_id = str(
                snapshot.get(key, "")
                or ""
            ).strip()

            if detection_id:
                break

        if detection_id and detection_id not in detection_ids:
            detection_ids.append(detection_id)

    existing_analysis_history = existing.get(
        "analysis_history",
        existing_summary.get("analysis_history", []),
    )
    incoming_analysis_history = summary.get(
        "analysis_history",
        [],
    )

    if not isinstance(incoming_analysis_history, list):
        incoming_analysis_history = [incoming_analysis_history]

    merged_analysis_history = _merge_soi_analysis_history(
        existing_analysis_history,
        incoming_analysis_history,
    )

    merged_summary["artifact_links"] = merged_artifact_links
    merged_summary["artifact_ids"] = artifact_ids
    merged_summary["detection_snapshots"] = merged_detection_snapshots
    merged_summary["detection_ids"] = detection_ids
    merged_summary["analysis_history"] = merged_analysis_history

    record = dict(existing)

    record.update({
        "soi_key": soi_key,
        "node_uid": node_uid or existing.get("node_uid", ""),
        "soi_id": soi_id or existing.get("soi_id", ""),
        "summary": merged_summary,
        "artifact_links": merged_artifact_links,
        "artifact_ids": artifact_ids,
        "detection_snapshots": merged_detection_snapshots,
        "detection_ids": detection_ids,
        "analysis_history": merged_analysis_history,
        "updated_at": now,
    })

    if frequency_mhz not in (None, "", "None"):
        record["frequency_mhz"] = frequency_mhz

        database_classification_result = (
            fissure.utils.library.classifyFrequencyFromTextDirect(
                str(frequency_mhz),
                True,
            )
        )
        record["database_classification"] = (
            database_classification_result
        )
        component.logger.info(database_classification_result)

    if status not in (None, "", "None"):
        record["status"] = status

    if operation_id not in (None, "", "None"):
        record["operation_id"] = operation_id

    if artifact_id:
        record["artifact_id"] = artifact_id
    elif "artifact_id" not in record:
        record["artifact_id"] = ""

    if stage_supplied:
        record["stage"] = incoming_stage

    if stage_order_supplied:
        record["stage_order"] = incoming_stage_order

    if "model_classification" in summary:
        model_classification = summary.get("model_classification")
        if model_classification in (None, "None"):
            model_classification = ""
        record["model_classification"] = model_classification

    if "model_confidence" in summary:
        model_confidence = summary.get("model_confidence")
        try:
            if model_confidence is not None:
                model_confidence = int(round(float(model_confidence)))
        except Exception:
            model_confidence = None
        record["model_confidence"] = model_confidence

    # SensorNode.send_soi_update() resolves True location/time requests to
    # concrete values before this callback is sent. At the hub, omitted/empty
    # values mean preserve the existing SOI value.
    if lat not in (None, "", "None"):
        record["lat"] = lat

    if lon not in (None, "", "None"):
        record["lon"] = lon

    if alt not in (None, "", "None"):
        record["hae_m"] = alt

    if observation_time not in (None, "", "None"):
        record["observation_time"] = observation_time

    if "created_at" not in record:
        record["created_at"] = now

    component.sois[soi_key] = record

    uid_core = (
        record.get("soi_id")
        or record.get("operation_id")
        or soi_key
    )
    tak_uid = f"fissure-soi-{record.get('node_uid', '')}-{uid_core}"

    tak_data = {
        "event_type": "soi",
        "node_uid": record.get("node_uid", ""),
        "soi_id": record.get("soi_id", ""),
        "frequency_mhz": record.get("frequency_mhz"),
        "status": record.get("status", ""),
        "operation_id": record.get("operation_id", ""),
        "artifact_id": record.get("artifact_id", ""),
        "artifact_ids": list(record.get("artifact_ids", []) or []),
        "model_classification": record.get(
            "model_classification",
            "",
        ),
        "model_confidence": record.get("model_confidence"),
        "database_classification": record.get(
            "database_classification",
            "",
        ),
        "stage": record.get("stage"),
        "stage_order": record.get("stage_order"),
        "record_json": json.dumps(record, default=str, separators=(",", ":")),
    }

    if merged_summary:
        tak_data["summary"] = merged_summary

    await fissure.utils.tak_messages.send(component, {
        "msg_type": "event",
        "uid": tak_uid,
        "data": tak_data,
        "tak_icon": "r-x-fissure-soi",
        "lat": record.get("lat", 0.0),
        "lon": record.get("lon", 0.0),
        "alt": record.get("hae_m", 0.0),
    })

# ---- Measurement aggregation support (sensor nodes can send raw samples via targetUpdate) ----
def _fissure_geo_process_measurement(component, *, target_id, frequency_hz, node_uid, lat, lon, rssi_db, observation_time):
    """Store a raw measurement, run multilateration + CE when ready, and return (est_lat, est_lon, ce_m) or None."""
    try:
        # from fissure_geo import Sample, PathLossModel, MultilaterationEstimator, estimate_ce_from_samples
        from fissure.utils.geo import (
            Sample,
            PathLossModel,
            MultilaterationEstimator,
            estimate_ce_from_samples,
        )
    except Exception:
        return None

    # Allow wifi/no-frequency measurements
    try:
        if frequency_hz is None:
            freq_bin_hz = -1.0
        else:
            # Frequency binning to fuse slightly different reported center freqs (default 1 kHz bins)
            freq_bin_hz = float(round(float(frequency_hz) / 1000.0) * 1000.0)
    except Exception:
        freq_bin_hz = -1.0

    key = (str(target_id), float(freq_bin_hz))

    if not hasattr(component, "_geo_targets"):
        component._geo_targets = {}

    st = component._geo_targets.get(key)
    if st is None:
        # Defaults; you can tune per target type later
        model = PathLossModel(n=2.2, p0_db=-40.0)
        est = MultilaterationEstimator(max_samples=120)
        st = {"model": model, "est": est, "last_ce": 0.0, "ce_cached": 75.0}
        component._geo_targets[key] = st

    model = st["model"]
    est = st["est"]

    # Add sample
    try:
        est.add_measurement(lat=float(lat), lon=float(lon), rssi_db=float(rssi_db), t=0.0, model=model)
    except Exception:
        try:
            est.add_sample(Sample(float(lat), float(lon), float(rssi_db), 0.0))
        except Exception:
            return None

    if not getattr(est, "ready", False):
        return None

    # Estimate
    try:
        out = est.estimate_latlon(model)
        if not out:
            return None
        est_lat, est_lon = out
    except Exception:
        return None

    # CE (throttle)
    import time as _time
    now = _time.time()
    if (now - float(st.get("last_ce", 0.0))) >= 6.0:
        try:
            samples_ref = getattr(est, "_samples", None) or getattr(est, "samples", None) or []
            ce = estimate_ce_from_samples(samples_ref[-30:], model, confidence=0.90)
            if ce is not None:
                st["ce_cached"] = float(ce)
        except Exception:
            pass
        st["last_ce"] = now

    return (float(est_lat), float(est_lon), float(st.get("ce_cached", 75.0)))

    # component.logger.info(f"HIPRFISR targetUpdate received target_id={target_id} state={state}")


def _get_known_wifi_target_ids(component) -> List[str]:
    """
    Return target_ids for targets that look like known Wi-Fi targets.
    """
    out = []

    for target_id, target in (component.targets or {}).items():
        if not isinstance(target, dict):
            continue

        classification = target.get("classification") or {}
        display_label = str(classification.get("display_label") or "").strip().lower()

        candidate_labels = []
        for candidate in classification.get("candidates", []):
            if isinstance(candidate, dict):
                label = str(candidate.get("label") or "").strip().lower()
                if label:
                    candidate_labels.append(label)

        label_text = " ".join([display_label] + candidate_labels)

        wifi = target.get("wifi") or {}
        bssid = str(wifi.get("bssid") or "").strip()

        if bssid or "wifi" in label_text or "802.11" in label_text:
            out.append(str(target_id))

    return out


async def targetUpdate(
    component: object,
    node_uid="",
    target_id="",
    source_soi_id="",
    frequency_hz=None,
    frequency_mhz=None,
    state="",
    artifact_id="",
    classification=None,
    location=None,
    history_entry=None,
    summary=None,
    lat=None,
    lon=None,
    alt=None,
    observation_time=None,
):
    """
    Target update callback (node -> HIPRFISR).

    Stores/updates target state at the hub and emits a TAK EVENT.

    Wire format (TAK)
    -----------------
    Sends ONE flat format that matches your existing targets_list parsing:
      <target>
        <display_label>...</display_label>
        <lat>...</lat> <lon>...</lon> <hae_m>...</hae_m> <ce_m>...</ce_m>
      </target>

    Internal format (hub store)
    ---------------------------
    Keeps your canonical nested dict:
      record["classification"] (nested)
      record["location"] (nested)
      record["history"]
    """
    if not target_id:
        component.logger.info("Ignoring target update with empty target_id")
        return


    # If this is a raw measurement update (no estimate yet), aggregate and compute on HIPRFISR.
    # Convention: state="measurement" OR location contains rssi_db.
    freq_hz = None
    try:
        if frequency_hz not in (None, ""):
            freq_hz = float(frequency_hz)
        elif frequency_mhz not in (None, ""):
            freq_hz = float(frequency_mhz) * 1e6
    except Exception:
        freq_hz = None

    is_measurement = (state == "measurement") or (isinstance(location, dict) and ("rssi_db" in location))
    if is_measurement:
        # Pull measurement fields (prefer nested location dict)
        mlat = None
        mlon = None
        mrssi = None

        if isinstance(location, dict):
            mlat = location.get("lat", lat)
            mlon = location.get("lon", lon)
            mrssi = location.get("rssi_db", None)

        if mrssi is None and isinstance(summary, dict):
            mrssi = summary.get("rssi_db", None)

        if (mlat is not None) and (mlon is not None) and (mrssi is not None):
            est_out = _fissure_geo_process_measurement(
                component,
                target_id=target_id,
                frequency_hz=freq_hz,
                node_uid=node_uid,
                lat=mlat,
                lon=mlon,
                rssi_db=mrssi,
                observation_time=observation_time,
            )
            if est_out is None:
                return  # stored only, not enough samples yet

            est_lat, est_lon, ce_m = est_out

            # Convert to a normal tracking update that will emit TAK below
            state = "tracking"
            lat = est_lat
            lon = est_lon
            if location is None or not isinstance(location, dict):
                location = {}
            location.update({
                "lat": float(est_lat),
                "lon": float(est_lon),
                "ce_m": float(ce_m),
                "source": "hiprfisr_multilateration",
            })
            if isinstance(summary, dict):
                summary["ce_m"] = float(ce_m)

    if classification is None or not isinstance(classification, dict):
        classification = {}
    if location is None or not isinstance(location, dict):
        location = {}
    if history_entry is None or not isinstance(history_entry, dict):
        history_entry = {}
    if summary is None or not isinstance(summary, dict):
        summary = {}

    # Prefer observation_time if provided; else use now
    if isinstance(observation_time, str) and observation_time:
        ts_iso = observation_time.replace(" ", "T")
    else:
        ts_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    now_epoch = time.time()

    existing = component.targets.get(target_id, {})
    record = dict(existing) if existing else {}

    created_time = record.get("created_time") or ts_iso

    # -----------------------------
    # Merge location (canonical)
    # -----------------------------
    loc = dict(record.get("location") or {})
    if location:
        loc.update(location)

    # If explicit coords provided, they win and update timestamp
    if lat is not None and lon is not None:
        loc.setdefault("source", "node_last_known")
        loc["lat"] = float(lat)
        loc["lon"] = float(lon)
        if alt is not None:
            loc["hae_m"] = float(alt)
        loc["timestamp"] = ts_iso

    # -----------------------------
    # Merge classification (canonical)
    # -----------------------------
    cls = dict(record.get("classification") or {})
    if classification:
        cls.update(classification)

    # -----------------------------
    # History append (canonical)
    # -----------------------------
    hist = list(record.get("history") or [])
    if history_entry:
        if "timestamp" not in history_entry:
            history_entry["timestamp"] = ts_iso
        hist.append(history_entry)

    # -----------------------------
    # Upsert record
    # -----------------------------
    record.update({
        "target_id": target_id,
        "node_uid": node_uid,
        "source_soi_id": source_soi_id,

        "created_time": created_time,
        "last_update_time": ts_iso,

        "frequency_mhz": frequency_mhz,
        "classification": cls,
        "location": loc,

        "state": state or record.get("state", "") or "detected",
        "history": hist,

        # optional debugging blob
        "summary": summary,

        # optional internal timing
        "updated_at": now_epoch,
    })
    component.targets[target_id] = record

    # -----------------------------
    # TAK EVENT (flat format ONLY)
    # -----------------------------
    # Pull display_label + location from canonical store, but emit flat.
    display_label = ""
    try:
        display_label = (cls.get("display_label") or "").strip()
    except Exception:
        display_label = ""

    out_lat = loc.get("lat")
    out_lon = loc.get("lon")
    out_hae = loc.get("hae_m")
    out_ce = loc.get("ce_m")
    out_loc_ts = loc.get("timestamp") or ts_iso

    tak_uid = f"fissure-target-{node_uid}-{target_id}"

    tak_data = {
        "event_type": "target",
        "node_uid": node_uid,
        "target_id": target_id,
        "source_soi_id": source_soi_id,

        "display_label": display_label,
        "state": record.get("state"),
        "frequency_mhz": frequency_mhz,
        "artifact_id": artifact_id or "",

        # Flat location fields (what your WinTAK parser expects)
        "lat": out_lat,
        "lon": out_lon,
        "hae_m": out_hae,
        "ce_m": out_ce,
        "timestamp": out_loc_ts,
    }

    await fissure.utils.tak_messages.send(component, {
        "msg_type": "event",
        "uid": tak_uid,
        "data": tak_data,
        "tak_icon": "r-x-fissure-target",
        # also populate CoT <point> for TAK-native consumers
        "lat": out_lat,
        "lon": out_lon,
        "alt": out_hae,
    })


def _deep_merge_dict(dst: dict, src: dict) -> dict:
    """
    Deep-merge src into dst in place.
    Nested dicts are merged; scalars/lists overwrite.
    """
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dst.get(key), dict):
            _deep_merge_dict(dst[key], value)
        else:
            dst[key] = value
    return dst


def _default_geolocate_block() -> dict:
    return {
        "status": "idle",
        "mode": "",
        "plugin": "",
        "action": "",
        "node_uids": [],
        "error": "",
        "updated_time": "",
    }


def _normalize_target_record(
    record: dict,
    target_id: str,
) -> dict:
    """
    Ensure required canonical Target fields exist and have sane types.

    Target artifacts represent work performed on the Target after promotion.
    Investigative SOI evidence remains reachable through source_soi_id.
    """
    if not isinstance(
        record.get("classification"),
        dict,
    ):
        record["classification"] = {}

    if not isinstance(
        record.get("identity"),
        dict,
    ):
        record["identity"] = {}

    if not isinstance(
        record.get("location"),
        dict,
    ):
        record["location"] = {}

    if not isinstance(
        record.get("geolocate"),
        dict,
    ):
        record["geolocate"] = (
            _default_geolocate_block()
        )
    else:
        merged_geo = (
            _default_geolocate_block()
        )
        merged_geo.update(
            record["geolocate"]
        )
        record["geolocate"] = (
            merged_geo
        )

    if not isinstance(
        record.get("history"),
        list,
    ):
        record["history"] = []

    if not isinstance(
        record.get("recommendations"),
        list,
    ):
        record["recommendations"] = []        

    if not isinstance(
        record.get("artifact_ids"),
        list,
    ):
        existing_artifact_ids = (
            record.get("artifact_ids")
        )

        if isinstance(
            existing_artifact_ids,
            (tuple, set),
        ):
            record["artifact_ids"] = list(
                existing_artifact_ids
            )
        else:
            record["artifact_ids"] = []

    if not isinstance(
        record.get("artifact_links"),
        list,
    ):
        existing_artifact_links = (
            record.get("artifact_links")
        )

        if isinstance(
            existing_artifact_links,
            dict,
        ):
            record["artifact_links"] = [
                existing_artifact_links
            ]
        else:
            record["artifact_links"] = []

    record.setdefault(
        "target_id",
        target_id,
    )
    record.setdefault(
        "node_uid",
        "",
    )
    record.setdefault(
        "source_soi_id",
        "",
    )
    record.setdefault(
        "frequency_mhz",
        None,
    )
    record.setdefault(
        "state",
        "detected",
    )
    record.setdefault(
        "artifact_id",
        "",
    )

    return record


def upsert_target_patch(
    component,
    *,
    target_id: str,
    patch: dict,
    history_entry: dict = None,
    artifact_id: str = "",
):
    """
    Merge a canonical Target patch into the authoritative hub record.

    Target-owned artifacts and operation history are cumulative. Duplicate
    delivery of the same callback does not create duplicate relationships.
    """
    if not target_id:
        return None

    if not isinstance(
        patch,
        dict,
    ):
        patch = {}

    if (
        history_entry is None
        or not isinstance(
            history_entry,
            dict,
        )
    ):
        history_entry = {}

    ts_iso = (
        datetime.now(timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    now_epoch = time.time()

    existing = component.targets.get(
        target_id,
        {},
    )

    record = (
        dict(existing)
        if existing
        else {}
    )

    created_time = (
        record.get("created_time")
        or patch.get("created_time")
        or ts_iso
    )

    existing_geolocate = (
        record.get("geolocate")
    )

    existing_history = list(
        record.get("history", [])
        if isinstance(
            record.get("history"),
            list,
        )
        else []
    )

    existing_artifact_ids = list(
        record.get("artifact_ids", [])
        if isinstance(
            record.get("artifact_ids"),
            list,
        )
        else []
    )

    existing_artifact_links = list(
        record.get("artifact_links", [])
        if isinstance(
            record.get("artifact_links"),
            list,
        )
        else []
    )

    incoming_artifact_ids = []

    patch_artifact_ids = patch.get(
        "artifact_ids",
        [],
    )

    if isinstance(
        patch_artifact_ids,
        (list, tuple, set),
    ):
        incoming_artifact_ids.extend(
            patch_artifact_ids
        )

    patch_artifact_links = patch.get(
        "artifact_links",
        [],
    )

    if isinstance(
        patch_artifact_links,
        dict,
    ):
        patch_artifact_links = [
            patch_artifact_links
        ]

    if not isinstance(
        patch_artifact_links,
        (list, tuple),
    ):
        patch_artifact_links = []

    patch_without_cumulative = dict(
        patch
    )
    patch_without_cumulative.pop(
        "history",
        None,
    )
    patch_without_cumulative.pop(
        "artifact_ids",
        None,
    )
    patch_without_cumulative.pop(
        "artifact_links",
        None,
    )

    _normalize_target_record(
        record,
        target_id,
    )

    _deep_merge_dict(
        record,
        patch_without_cumulative,
    )

    _normalize_target_record(
        record,
        target_id,
    )

    if (
        "geolocate" not in patch
        and existing_geolocate
    ):
        record["geolocate"] = (
            existing_geolocate
        )

    latest_artifact_id = str(
        artifact_id
        or patch.get("artifact_id")
        or ""
    ).strip()

    if latest_artifact_id:
        incoming_artifact_ids.append(
            latest_artifact_id
        )
        record["artifact_id"] = (
            latest_artifact_id
        )

    merged_artifact_ids = []
    seen_artifact_ids = set()

    for candidate in (
        existing_artifact_ids
        + incoming_artifact_ids
    ):
        candidate_text = str(
            candidate or ""
        ).strip()

        if (
            not candidate_text
            or candidate_text
            in seen_artifact_ids
        ):
            continue

        seen_artifact_ids.add(
            candidate_text
        )
        merged_artifact_ids.append(
            candidate_text
        )

    record["artifact_ids"] = (
        merged_artifact_ids
    )

    merged_artifact_links = []
    seen_artifact_links = set()

    for link in (
        existing_artifact_links
        + list(patch_artifact_links)
    ):
        if isinstance(link, dict):
            normalized_link = dict(link)
            link_artifact_id = str(
                normalized_link.get(
                    "artifact_id",
                    "",
                )
                or ""
            ).strip()

            if not link_artifact_id:
                continue

            normalized_link[
                "artifact_id"
            ] = link_artifact_id

            link_key = (
                link_artifact_id,
                str(
                    normalized_link.get(
                        "operation_id",
                        "",
                    )
                    or ""
                ).strip(),
                str(
                    normalized_link.get(
                        "role",
                        "",
                    )
                    or ""
                ).strip(),
            )
        else:
            link_artifact_id = str(
                link or ""
            ).strip()

            if not link_artifact_id:
                continue

            normalized_link = {
                "artifact_id":
                    link_artifact_id,
            }
            link_key = (
                link_artifact_id,
                "",
                "",
            )

        if link_key in seen_artifact_links:
            continue

        seen_artifact_links.add(
            link_key
        )
        merged_artifact_links.append(
            normalized_link
        )

        if (
            link_artifact_id
            not in seen_artifact_ids
        ):
            seen_artifact_ids.add(
                link_artifact_id
            )
            record[
                "artifact_ids"
            ].append(
                link_artifact_id
            )

    if latest_artifact_id:
        latest_link_key = (
            latest_artifact_id,
            str(
                history_entry.get(
                    "operation_id",
                    "",
                )
                or ""
            ).strip(),
            "",
        )

        if (
            latest_link_key
            not in seen_artifact_links
        ):
            merged_artifact_links.append(
                {
                    "artifact_id":
                        latest_artifact_id,
                    "operation_id":
                        history_entry.get(
                            "operation_id",
                            "",
                        ),
                }
            )

    record["artifact_links"] = (
        merged_artifact_links
    )

    record["history"] = (
        existing_history
    )

    if history_entry:
        entry = dict(
            history_entry
        )
        entry.setdefault(
            "timestamp",
            ts_iso,
        )

        entry_operation_id = str(
            entry.get(
                "operation_id",
                "",
            )
            or ""
        ).strip()

        duplicate_history = False

        for existing_entry in (
            record["history"]
        ):
            if not isinstance(
                existing_entry,
                dict,
            ):
                continue

            existing_operation_id = str(
                existing_entry.get(
                    "operation_id",
                    "",
                )
                or ""
            ).strip()

            if (
                entry_operation_id
                and existing_operation_id
                == entry_operation_id
            ):
                duplicate_history = True
                break

            if existing_entry == entry:
                duplicate_history = True
                break

        if not duplicate_history:
            record["history"].append(
                entry
            )

    record["target_id"] = (
        target_id
    )
    record["created_time"] = (
        created_time
    )
    record["last_update_time"] = (
        ts_iso
    )
    record["updated_at"] = (
        now_epoch
    )

    component.targets[target_id] = (
        record
    )

    return record


async def targetPatch(
    component: object,
    target_id="",
    patch=None,
    history_entry=None,
    artifact_id="",
):
    """
    Canonical target patch callback (node -> HIPRFISR).

    Stores or updates the authoritative Target record, then emits a flat TAK
    Target event. Flexible identity, cumulative Target-owned artifacts, and
    Target history are serialized as JSON strings for Dashboard and WinTAK
    consumers while preserving the existing flat fields.
    """
    if not target_id:
        component.logger.info(
            "Ignoring target patch with empty target_id"
        )
        return

    patch = patch or {}
    history_entry = history_entry or {}

    record = upsert_target_patch(
        component,
        target_id=target_id,
        patch=patch,
        history_entry=history_entry,
        artifact_id=artifact_id or "",
    )

    if not record:
        return

    geo = record.get("geolocate") or {}

    # Mark that this Target received observations while geolocation is active.
    # Empty hub-only UI or status refreshes do not count as observations.
    if geo.get("status") in (
        "starting",
        "running",
        "stopping",
    ):
        loc_patch = patch.get("location") or {}
        rf_patch = patch.get("rf") or {}
        wifi_patch = patch.get("wifi") or {}

        had_observation = any(
            [
                bool(history_entry),
                bool(artifact_id),
                (
                    "lat" in loc_patch
                    and "lon" in loc_patch
                ),
                "ce_m" in loc_patch,
                "frequency_mhz" in patch,
                "last_observation_time" in rf_patch,
                "last_observation_time" in wifi_patch,
                "rssi_dbm" in wifi_patch,
            ]
        )

        if had_observation:
            geo["had_detections"] = True
            record["geolocate"] = geo

    classification = (
        record.get("classification")
        or {}
    )
    location = (
        record.get("location")
        or {}
    )
    identity = (
        record.get("identity")
        or {}
    )

    display_label = ""

    try:
        display_label = (
            record.get("display_label")
            or classification.get("display_label")
            or ""
        ).strip()
    except Exception:
        display_label = ""

    out_lat = location.get("lat")
    out_lon = location.get("lon")
    out_hae = location.get("hae_m")
    out_ce = location.get("ce_m")
    out_loc_ts = (
        location.get("timestamp")
        or record.get("last_update_time")
    )

    node_uid = record.get(
        "node_uid",
        "",
    )
    tak_uid = (
        f"fissure-target-{node_uid}-{target_id}"
    )

    wifi = record.get("wifi") or {}

    tak_data = {
        "event_type": "target",
        "node_uid": node_uid,
        "target_id": target_id,
        "source_soi_id": record.get(
            "source_soi_id",
            "",
        ),
        "display_label": display_label,
        "state": record.get("state"),
        "notes": record.get("notes", ""),
        "frequency_mhz": record.get(
            "frequency_mhz"
        ),
        "artifact_id": record.get(
            "artifact_id",
            "",
        ),
        "identity_json": json.dumps(
            identity,
            default=str,
        ),
        "artifact_ids_json": json.dumps(
            record.get("artifact_ids") or [],
            default=str,
        ),
        "artifact_links_json": json.dumps(
            record.get("artifact_links") or [],
            default=str,
        ),
        "history_json": json.dumps(
            record.get("history") or [],
            default=str,
        ),
        "recommendations_json": json.dumps(
            record.get("recommendations") or [],
            default=str,
        ),
        "geolocation_status": geo.get(
            "status",
            "idle",
        ),
        "lat": out_lat,
        "lon": out_lon,
        "hae_m": out_hae,
        "ce_m": out_ce,
        "timestamp": out_loc_ts,

        # Wi-Fi extras for UI/operator display
        "ssid": wifi.get("ssid", ""),
        "bssid": wifi.get("bssid", ""),
        "channel": wifi.get("channel"),
        "band": wifi.get("band", ""),
        "rssi_dbm": wifi.get("rssi_dbm"),
        "encryption": wifi.get(
            "encryption",
            "",
        ),
        "last_observation_time": wifi.get(
            "last_observation_time",
            "",
        ),
    }

    await fissure.utils.tak_messages.send(
        component,
        {
            "msg_type": "event",
            "uid": tak_uid,
            "data": tak_data,
            "tak_icon": "r-x-fissure-target",
            "lat": out_lat,
            "lon": out_lon,
            "alt": out_hae,
        },
    )


async def targetRecommendation(
    component: object,
    target_id="",
    mode="add",
    recommendation=None,
    recommendation_id="",
):
    """Add or remove a structured recommended action on an authoritative Target."""
    target_id = str(target_id or "").strip()
    mode = str(mode or "add").strip().lower()
    recommendation = recommendation if isinstance(recommendation, dict) else {}
    recommendation_id = str(
        recommendation_id
        or recommendation.get("recommendation_id")
        or ""
    ).strip()

    if not target_id or target_id not in (getattr(component, "targets", {}) or {}):
        component.logger.warning(f"Ignoring Target recommendation for unknown target: {target_id}")
        return

    target = component.targets.get(target_id) or {}
    current = [dict(value) for value in (target.get("recommendations") or []) if isinstance(value, dict)]

    if mode == "remove":
        if not recommendation_id:
            return
        updated = [
            value for value in current
            if str(value.get("recommendation_id") or "").strip() != recommendation_id
        ]
        if len(updated) == len(current):
            return

        history_entry = {
            "event": "recommended_action_removed",
            "recommendation_id": recommendation_id,
            "requester": "dashboard",
        }
        await targetPatch(
            component,
            target_id=target_id,
            patch={"recommendations": updated},
            history_entry=history_entry,
            artifact_id="",
        )
        return

    plugin_name = str(recommendation.get("plugin") or "").strip()
    action_name = str(recommendation.get("action") or "").strip()
    if not plugin_name or not action_name:
        component.logger.warning("Ignoring Target recommendation without plugin/action.")
        return

    parameters = recommendation.get("parameters") or {}
    if not isinstance(parameters, dict):
        parameters = {}

    normalized = dict(recommendation)
    normalized["plugin"] = plugin_name
    normalized["action"] = action_name
    normalized["parameters"] = dict(parameters)
    normalized["reason"] = str(normalized.get("reason") or "").strip()
    normalized.setdefault(
        "timestamp",
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    match_index = None
    if recommendation_id:
        for index, existing in enumerate(current):
            if str(existing.get("recommendation_id") or "").strip() == recommendation_id:
                match_index = index
                break

    if match_index is None:
        candidate_key = (
            plugin_name,
            action_name,
            json.dumps(parameters, sort_keys=True, default=str),
            normalized["reason"],
        )
        for index, existing in enumerate(current):
            existing_key = (
                str(existing.get("plugin") or "").strip(),
                str(existing.get("action") or "").strip(),
                json.dumps(existing.get("parameters") or {}, sort_keys=True, default=str),
                str(existing.get("reason") or "").strip(),
            )
            if existing_key == candidate_key:
                # An analysis action may encounter the same condition repeatedly.
                # Keep one recommendation instead of growing the Target forever.
                return

    if not recommendation_id:
        recommendation_id = str(uuid.uuid4())
    normalized["recommendation_id"] = recommendation_id

    if match_index is None:
        current.append(normalized)
    else:
        current[match_index] = normalized

    history_entry = {
        "event": "action_recommended",
        "recommendation_id": recommendation_id,
        "plugin": plugin_name,
        "action": action_name,
        "reason": normalized["reason"],
        "source_operation_id": str(
            normalized.get("operation_id")
            or normalized.get("source_operation_id")
            or ""
        ).strip(),
        "node_uid": str(normalized.get("node_uid") or "").strip(),
    }

    await targetPatch(
        component,
        target_id=target_id,
        patch={"recommendations": current},
        history_entry=history_entry,
        artifact_id="",
    )


async def sendTargetsListTak(
    component: object,
    requester_uid: str = "",
    requester_type: str = "tak",
    request_id: str = "",
    requester_callsign: str = "",
) -> None:
    """
    Respond to a TAK targets_list request by emitting one event per Target.

    Existing flat fields remain available. Flexible identity, cumulative
    Target-owned artifacts, and Target operation history are included as JSON
    strings so Dashboard and WinTAK can reconstruct the complete record.
    """
    try:
        targets = (
            getattr(
                component,
                "targets",
                {},
            )
            or {}
        )
    except Exception:
        targets = {}

    for target_id, target in targets.items():
        try:
            classification = (
                target.get("classification")
                or {}
            )
            location = (
                target.get("location")
                or {}
            )
            identity = (
                target.get("identity")
                or {}
            )

            lat = location.get("lat")
            lon = location.get("lon")

            event_uid = (
                f"fissure-target-{target_id}-"
                f"{int(time.time() * 1000)}"
            )

            display_label = (
                target.get("display_label")
                or classification.get(
                    "display_label"
                )
                or ""
            )

            tak_data = {
                "event_type": "target",
                "target_id": target_id,
                "node_uid": target.get(
                    "node_uid"
                ),
                "source_soi_id": target.get(
                    "source_soi_id"
                ),
                "display_label": display_label,
                "state": target.get("state"),
                "notes": target.get("notes", ""),
                "frequency_mhz": target.get(
                    "frequency_mhz"
                ),
                "artifact_id": target.get(
                    "artifact_id"
                ),
                "identity_json": json.dumps(
                    identity,
                    default=str,
                ),
                "artifact_ids_json": json.dumps(
                    target.get("artifact_ids")
                    or [],
                    default=str,
                ),
                "artifact_links_json": json.dumps(
                    target.get("artifact_links")
                    or [],
                    default=str,
                ),
                "history_json": json.dumps(
                    target.get("history")
                    or [],
                    default=str,
                ),
                "recommendations_json": json.dumps(
                    target.get("recommendations")
                    or [],
                    default=str,
                ),
                "request_id": request_id,
                "requester_uid": requester_uid,
                "requester_callsign":
                    requester_callsign,
            }

            # -------------------------------------------------------------
            # Optional location
            # -------------------------------------------------------------
            if (
                lat is not None
                and lon is not None
            ):
                tak_data["lat"] = lat
                tak_data["lon"] = lon
                tak_data["ce_m"] = (
                    location.get("ce_m")
                )
                tak_data["hae_m"] = (
                    location.get("hae_m")
                )

            # -------------------------------------------------------------
            # Remove empty core fields
            # -------------------------------------------------------------
            tak_data = {
                key: value
                for key, value in tak_data.items()
                if value is not None
                and not (
                    isinstance(value, str)
                    and value.strip() == ""
                )
            }

            # -------------------------------------------------------------
            # Wi-Fi fields remain unprefixed for compatibility
            # -------------------------------------------------------------
            for (
                key,
                value,
            ) in (
                target.get("wifi")
                or {}
            ).items():
                if (
                    value is not None
                    and not (
                        isinstance(value, str)
                        and value.strip() == ""
                    )
                ):
                    tak_data[key] = value

            # -------------------------------------------------------------
            # RF fields remain prefixed
            # -------------------------------------------------------------
            for (
                key,
                value,
            ) in (
                target.get("rf")
                or {}
            ).items():
                if (
                    value is not None
                    and not (
                        isinstance(value, str)
                        and value.strip() == ""
                    )
                ):
                    tak_data[
                        f"rf_{key}"
                    ] = value

            # -------------------------------------------------------------
            # Geolocation fields remain prefixed
            # -------------------------------------------------------------
            for (
                key,
                value,
            ) in (
                target.get("geolocate")
                or {}
            ).items():
                if (
                    value is not None
                    and not (
                        isinstance(value, str)
                        and value.strip() == ""
                    )
                ):
                    tak_data[
                        f"geolocate_{key}"
                    ] = value

            await fissure.utils.tak_messages.send(
                component,
                {
                    "msg_type": "event",
                    "uid": event_uid,
                    "data": tak_data,
                },
                requester_type,
                requester_uid,
            )

        except Exception as exc:
            component.logger.error(
                "Failed sending target "
                f"{target_id} to TAK: {exc}"
            )


async def refresh_status(
    component: object,
    requester_uid: str,
    requester_type: str,
    node_uids: List[str],
):
    """Request position/status updates from selected sensor nodes.

    Parameters
    ----------
    component : object
        Component.
    requester_uid : str
        Requesting client UID.
    requester_type : str
        dashboard, tak, or broadcast.
    node_uids : List[str]
        List of sensor node UIDs.
    """
    if not node_uids:
        component.logger.warning("No node UIDs provided for refresh_status.")
        return

    for node_uid in node_uids:
        component.logger.info(
            f"Requesting position/status update from node {node_uid}"
        )

        node_record = component.nodes.get(node_uid)
        if not node_record:
            component.logger.warning(
                f"Cannot refresh status for unknown node UID: {node_uid}"
            )
            continue

        identity = node_record.get("identity", None)
        if identity is None:
            component.logger.warning(
                f"Cannot refresh status for node {node_uid}: missing identity."
            )
            continue

        PARAMETERS = {
            "requester_uid": requester_uid,
            "requester_type": requester_type,
        }

        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "refresh_status",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }

        await component.sensor_node_router.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
            target_ids=[identity],
        )


async def sendPluginActionParametersResultsTak(
    component: object,
    plugin_name: str,
    action_name: str,
    node_uid: str,
    schema: dict,
    tak_context: str
):
    """Handle Sensor Node plugin action parameter schema for TAK

    Parameters
    ----------
    component : object
        Component
    plugin_name : str
        Plugin name
    action_name : str
        Plugin action name
    node_uid : str
        Sensor node UID
    schema : dict
        Action schema dict (expects {"params": [...]})
    tak_context : str
        node or ecosystem
    """

    component.logger.debug(
        f"Preparing to send TAK action schema for {plugin_name}.{action_name}"
    )

    # Normalize schema to predictable shape
    if not isinstance(schema, dict):
        schema = {"params": []}
    if "params" not in schema or not isinstance(schema.get("params"), list):
        schema["params"] = []

    event_uid = f"actionschema-{plugin_name}-{action_name}-{int(time.time()*1000)}"

    if tak_context == "ecosystem":
        msg = {
            "msg_type": "event",
            "uid": event_uid,
            "data": {
                "event_type": "ecosystem_plugin_action_schema",
                "plugin_name": plugin_name,
                "action_name": action_name,
                "node_uid": node_uid,
                "schema": schema,
            },
        }
    else:
        msg = {
            "msg_type": "event",
            "uid": event_uid,
            "data": {
                "event_type": "plugin_action_schema",
                "plugin_name": plugin_name,
                "action_name": action_name,
                "node_uid": node_uid,
                "schema": schema,
            },
        }

    await fissure.utils.tak_messages.send(component, msg)


async def sendPluginTargetActionsTak(
    component: object,
    requester_uid: str,
    requester_type: str,
    plugin_name: str,
    node_uid: str,
    target_id: str,
):
    """Request filtered plugin action names for a target context."""
    try:
        if not target_id:
            component.logger.error("query_target_actions missing target_id")
            return

        target = component.targets.get(target_id)
        if not target:
            component.logger.error(f"Target not found for target_id={target_id}")
            return

        classification_candidates = []

        classification_info = (
            target.get("type")
            or target.get("classification")
            or target.get("display_label")
        )

        # Case 1: simple string
        if isinstance(classification_info, str):
            label = classification_info.strip()
            if label:
                classification_candidates.append(label)

        # Case 2: structured dict like your example
        elif isinstance(classification_info, dict):
            display_label = str(classification_info.get("display_label", "")).strip()
            if display_label:
                classification_candidates.append(display_label)

            for candidate in classification_info.get("candidates", []):
                if not isinstance(candidate, dict):
                    continue
                label = str(candidate.get("label", "")).strip()
                if label:
                    classification_candidates.append(label)

        # Remove duplicates while preserving order
        seen = set()
        classification_candidates = [
            c for c in classification_candidates
            if not (c in seen or seen.add(c))
        ]

        component.logger.info(
            f"Target action lookup for target_id={target_id}, "
            f"classification_candidates={classification_candidates}"
        )

        PARAMETERS = {
            "requester_uid": requester_uid,
            "requester_type": requester_type,
            "plugin_name": plugin_name,
            "target_id": target_id,
            "node_uid": node_uid,
            "classification_candidates": classification_candidates,
        }

        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "sendPluginTargetActionsTak",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }

        identity = component.nodes.get(node_uid, {}).get("identity", None)
        if identity is None:
            component.logger.error(f"No identity for node_uid={node_uid}")
            return

        await component.sensor_node_router.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
            target_ids=[identity]
        )

    except Exception as e:
        component.logger.error(f"Error in sendPluginTargetActionsTak: {e}")
        component.logger.debug(traceback.format_exc())


async def geolocate_target_start(
    component: object,
    requester_uid: str,
    requester_type: str = "tak",    
    parameters: dict = None,
):
    """Select nearest nodes and start appropriate geolocation-related action."""
    try:
        component.logger.info(f"geolocate_target_start called with parameters={parameters}")

        if parameters is None:
            parameters = {}

        target_id = parameters.get("target_id")
        if not target_id:
            component.logger.error("geolocate_target_start missing target_id")
            return

        target = component.targets.get(target_id)
        if not target:
            component.logger.error(f"Target not found for target_id={target_id}")
            return

        current_geo = target.get("geolocate") or {}
        current_status = current_geo.get("status", "")

        if current_status in ("starting", "running", "stopping"):
            component.logger.warning(
                f"Target {target_id} geolocation already active (status={current_status})"
            )
            await targetPatch(component, target_id=target_id, patch={})
            return

        search_similar_targets = bool(parameters.get("search_similar_targets", False))

        target_location = target.get("location") or {}
        target_lat = target_location.get("lat")
        target_lon = target_location.get("lon")

        if not fissure.utils.is_valid_lat_lon(target_lat, target_lon):
            msg = "invalid_target_location"
            component.logger.error(
                f"Target {target_id} missing valid location: lat={target_lat}, lon={target_lon}"
            )
            _set_target_geolocate_status(
                target,
                status="error",
                error=msg,
            )
            await targetPatch(component, target_id=target_id, patch={})
            return

        nearest_nodes = fissure.utils.get_nearest_nodes_to_target(
            component,
            target,
            max_nodes=3,
        )

        if not nearest_nodes:
            msg = "no_eligible_nodes"
            component.logger.warning(
                f"No eligible nodes with valid positions for target_id={target_id}"
            )
            _set_target_geolocate_status(
                target,
                status="error",
                error=msg,
            )
            await targetPatch(component, target_id=target_id, patch={})
            return

        component.logger.info(
            f"Nearest nodes for target_id={target_id}: "
            + ", ".join(
                f"{n['uid']} ({n['distance_m']:.1f} m)"
                for n in nearest_nodes
            )
        )

        config = _get_target_geolocate_action_config(
            component,
            target,
            search_similar_targets=search_similar_targets,
        )
        if not config:
            msg = "unsupported_target_type"
            component.logger.warning(
                f"No geolocate mapping for target_id={target_id}"
            )
            _set_target_geolocate_status(
                target,
                status="unsupported",
                error=msg,
            )
            await targetPatch(component, target_id=target_id, patch={})
            return

        plugin_name = config["plugin_name"]
        action_name = config["action_name"]
        action_parameters = dict(config.get("parameters", {}))
        mode = config.get("mode", "")

        if "target_id" not in action_parameters and "target_ids" not in action_parameters:
            action_parameters["target_id"] = target_id

        if "search_similar_targets" not in action_parameters:
            action_parameters["search_similar_targets"] = search_similar_targets

        node_uid_list = [n["uid"] for n in nearest_nodes]

        previous_state = target.get("state", "") or "imported"

        _set_target_geolocate_status(
            target,
            status="starting",
            mode=mode,
            plugin=plugin_name,
            action=action_name,
            node_uids=node_uid_list,
            error="",
        )
        target["geolocate"]["previous_state"] = previous_state
        target["geolocate"]["had_detections"] = False
        target["state"] = "tracking"

        await targetPatch(component, target_id=target_id, patch={})

        launched_nodes = []

        try:
            launched_nodes = list(node_uid_list)

            component.logger.info(
                f"Launching {action_name} for target_id={target_id} "
                f"on nodes={launched_nodes}"
            )

            await sendPluginActionTak(
                component,
                requester_uid,
                requester_type,
                node_uid_list,
                plugin_name,
                action_name,
                action_parameters,
            )

        except Exception as launch_err:
            component.logger.error(
                f"Failed launching geolocate actions: {launch_err}"
            )
            component.logger.debug(traceback.format_exc())

        target = component.targets.get(target_id)
        if not target:
            component.logger.error(f"Target disappeared before running update: target_id={target_id}")
            return

        if not launched_nodes:
            msg = "launch_failed"

            component.logger.warning(
                f"Geolocate start failed for target_id={target_id}"
            )

            _set_target_geolocate_status(
                target,
                status="error",
                mode=mode,
                plugin=plugin_name,
                action=action_name,
                node_uids=[],
                error=msg,
            )
            # restore pre-start state if nothing launched
            previous_state = (target.get("geolocate") or {}).get("previous_state", "") or "imported"
            target["state"] = previous_state

            await targetPatch(component, target_id=target_id, patch={})
            return

        component.logger.info(
            f"Geolocate running for target_id={target_id} on nodes={launched_nodes}"
        )

        _set_target_geolocate_status(
            target,
            status="running",
            mode=mode,
            plugin=plugin_name,
            action=action_name,
            node_uids=launched_nodes,
            error="",
        )
        await targetPatch(component, target_id=target_id, patch={})

    except Exception as e:
        component.logger.error(f"Error in geolocate_target_start: {e}")
        component.logger.debug(traceback.format_exc())

        target_id = parameters.get("target_id")
        if target_id:
            target = component.targets.get(target_id)
            if target:
                _set_target_geolocate_status(
                    target,
                    status="error",
                    error="exception",
                )
                previous_state = (target.get("geolocate") or {}).get("previous_state", "")
                if previous_state:
                    target["state"] = previous_state
                await targetPatch(component, target_id=target_id, patch={})


def _get_target_geolocate_action_config(
    component: object,
    target: dict,
    *,
    search_similar_targets: bool = False,
):
    """
    Resolve which plugin action should be launched for this target.

    Returns:
        {
            "mode": "wifi_target" | "wifi_all" | "lfm_beacon" | "fixed_detection",
            "plugin_name": "...",
            "action_name": "...",
            "parameters": {...},
        }

    Returns None if no supported mapping exists.
    """
    target_id = target.get("target_id", "")
    classification = target.get("classification") or {}

    display_label = str(classification.get("display_label") or "").strip().lower()

    candidate_labels = []
    for candidate in classification.get("candidates", []):
        if isinstance(candidate, dict):
            label = str(candidate.get("label") or "").strip().lower()
            if label:
                candidate_labels.append(label)

    labels = [display_label] + candidate_labels
    label_text = " ".join(labels)

    frequency_mhz = target.get("frequency_mhz")

    WIFI_PLUGIN = "WiFi"
    BASE_PLUGIN = "Base"

    if "wifi" in label_text or "802.11" in label_text:
        if search_similar_targets:
            return {
                "mode": "wifi_all",
                "plugin_name": WIFI_PLUGIN,
                "action_name": "wifi_geolocate_all",
                "parameters": {
                    "target_ids": _get_known_wifi_target_ids(component),
                    "search_similar_targets": True,
                },
            }

        return {
            "mode": "wifi_target",
            "plugin_name": WIFI_PLUGIN,
            "action_name": "wifi_geolocate_target",
            "parameters": {
                "target_id": target_id,
                "search_similar_targets": False,
            },
        }

    if "lfm" in label_text or "beacon" in label_text:
        return {
            "mode": "lfm_beacon",
            "plugin_name": BASE_PLUGIN,
            "action_name": "lfm_beacon_geolocate",
            "parameters": {
                "target_id": target_id,
                "freq_mhz": float(frequency_mhz) if frequency_mhz not in (None, "") else 433.0,
                "min_detection_interval_s": 1.0,
            },
        }

    if frequency_mhz not in (None, ""):
        return {
            "mode": "generic_frequency",
            "plugin_name": BASE_PLUGIN,
            "action_name": "usrp_b2x0_geolocate",
            "parameters": {
                "target_id": target_id,
                "frequency_mhz": float(frequency_mhz) if frequency_mhz not in (None, "") else 2412.0,
                "emit_every_s": 1.0,
                "meas_every_s": 0.20,
                "sample_rate": 1e6,
                "gain_db": 65.0,
                "detect_frequency": True,
                "description": f"Generic frequency geolocation for {target_id}",
            },
        }

    return None


def _set_target_geolocate_status(
    target: dict,
    *,
    status: str = "",
    mode: str = "",
    plugin: str = "",
    action: str = "",
    node_uids=None,
    error: str = "",
) -> None:
    """
    Update compact hub-side geolocation state stored on the target record.
    """
    if node_uids is None:
        node_uids = []

    geo = dict(target.get("geolocate") or {})
    geo.update({
        "status": status,
        "mode": mode,
        "plugin": plugin,
        "action": action,
        "node_uids": list(node_uids),
        "error": error,
        "updated_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    target["geolocate"] = geo


def _clear_target_geolocate_status(target: dict) -> None:
    """
    Reset geolocation state on the target to a known idle baseline.
    """
    target["geolocate"] = {
        "status": "idle",
        "mode": "",
        "plugin": "",
        "action": "",
        "node_uids": [],
        "error": "",
        "updated_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


async def geolocate_target_stop(
    component: object,
    requester_uid: str,
    requester_type: str = "tak",
    parameters: dict = None,
):
    """Stop geolocation for a target across all associated nodes."""
    try:
        component.logger.info(
            f"geolocate_target_stop called with parameters={parameters}"
        )

        if parameters is None:
            parameters = {}

        target_id = parameters.get("target_id")

        if not target_id:
            component.logger.error(
                "geolocate_target_stop missing target_id"
            )
            return

        target = component.targets.get(target_id)

        if not target:
            component.logger.error(
                f"Target not found for target_id={target_id}"
            )
            return

        geolocate = target.get("geolocate") or {}

        node_uid_list = list(
            geolocate.get("node_uids") or []
        )

        if not node_uid_list:
            component.logger.warning(
                f"No geolocate node_uids recorded for "
                f"target_id={target_id}"
            )

            previous_state = (
                geolocate.get("previous_state", "")
                or target.get("state", "")
                or "imported"
            )

            had_detections = bool(
                geolocate.get("had_detections", False)
            )

            target["state"] = (
                "detected"
                if had_detections
                else previous_state
            )

            _set_target_geolocate_status(
                target,
                status="idle",
                mode="",
                plugin="",
                action="",
                node_uids=[],
                error="",
            )

            target["geolocate"]["previous_state"] = ""
            target["geolocate"]["had_detections"] = False

            await targetPatch(
                component,
                target_id=target_id,
                patch={},
            )

            return

        _set_target_geolocate_status(
            target,
            status="stopping",
            mode=geolocate.get("mode", ""),
            plugin=geolocate.get("plugin", ""),
            action=geolocate.get("action", ""),
            node_uids=node_uid_list,
            error="",
        )

        await targetPatch(
            component,
            target_id=target_id,
            patch={},
        )

        stopped_nodes = []
        failed_nodes = []

        try:
            component.logger.info(
                f"Stopping geolocation for target_id={target_id} "
                f"on node_uids={node_uid_list}"
            )

            await stop_all_plugin_operations(
                component,
                requester_uid,
                requester_type,
                node_uid_list,
            )

            stopped_nodes = list(node_uid_list)

        except Exception as stop_err:
            component.logger.error(
                f"Failed stopping geolocation for "
                f"target_id={target_id}: {stop_err}"
            )

            component.logger.debug(
                traceback.format_exc()
            )

            failed_nodes = list(node_uid_list)

        target = component.targets.get(target_id)

        if not target:
            component.logger.error(
                f"Target disappeared before final idle update: "
                f"target_id={target_id}"
            )
            return

        geolocate = target.get("geolocate") or {}

        previous_state = (
            geolocate.get("previous_state", "")
            or "imported"
        )

        had_detections = bool(
            geolocate.get("had_detections", False)
        )

        if failed_nodes and not stopped_nodes:
            _set_target_geolocate_status(
                target,
                status="error",
                mode=geolocate.get("mode", ""),
                plugin=geolocate.get("plugin", ""),
                action=geolocate.get("action", ""),
                node_uids=node_uid_list,
                error="stop_failed",
            )

            await targetPatch(
                component,
                target_id=target_id,
                patch={},
            )

            return

        target["state"] = (
            "detected"
            if had_detections
            else previous_state
        )

        _set_target_geolocate_status(
            target,
            status="idle",
            mode="",
            plugin="",
            action="",
            node_uids=[],
            error=(
                ""
                if not failed_nodes
                else f"partial_stop_failed:{','.join(failed_nodes)}"
            ),
        )

        target["geolocate"]["previous_state"] = ""
        target["geolocate"]["had_detections"] = False

        await targetPatch(
            component,
            target_id=target_id,
            patch={},
        )

        component.logger.info(
            f"Geolocate stopped for target_id={target_id}; "
            f"stopped_nodes={stopped_nodes}, "
            f"failed_nodes={failed_nodes}, "
            f"restored_state={target.get('state')}, "
            f"had_detections={had_detections}"
        )

    except Exception as e:
        component.logger.error(
            f"Error in geolocate_target_stop: {e}"
        )

        component.logger.debug(
            traceback.format_exc()
        )

        target_id = (
            parameters.get("target_id")
            if parameters
            else None
        )

        if target_id:
            target = component.targets.get(target_id)

            if target:
                _set_target_geolocate_status(
                    target,
                    status="error",
                    error="exception",
                )

                await targetPatch(
                    component,
                    target_id=target_id,
                    patch={},
                )


def _normalize_promoted_detection(detection):
    """
    Normalize structured detections from WinTAK, Tactical, or TSI.

    Every non-empty detector-defined field is retained. Common Dashboard and
    parsed-CoT aliases are also copied into stable canonical keys so promotion
    behavior is identical regardless of which interface initiated it.
    """
    if not isinstance(detection, dict):
        return {}

    raw_keys = {
        "raw_xml",
        "cot_xml",
        "xml",
        "raw_message",
        "raw_payload",
    }

    normalized = {}

    for key, value in detection.items():
        key_text = str(
            key or ""
        ).strip()

        if not key_text:
            continue

        if key_text.lower() in raw_keys:
            continue

        if value is None:
            continue

        if isinstance(value, str):
            value = value.strip()

            if not value or value == "None":
                continue

        normalized[key_text] = value

        if key_text.startswith("detection_"):
            canonical_key = key_text[
                len("detection_"):
            ]

            if canonical_key:
                normalized.setdefault(
                    canonical_key,
                    value,
                )

    alias_map = {
        "uid": "event_uid",
        "frequency": "frequency_mhz",
        "lat": "latitude",
        "lon": "longitude",
        "hae_m": "hae_meters",
        "operation_id": "opid",
    }

    for source_key, canonical_key in alias_map.items():
        value = normalized.get(
            source_key
        )

        if value not in (
            None,
            "",
            "None",
        ):
            normalized.setdefault(
                canonical_key,
                value,
            )

    return normalized


def _promoted_detection_float(detection, *keys):
    for key in keys:
        value = detection.get(key)

        if value in (None, ""):
            continue

        try:
            return float(value)
        except Exception:
            continue

    return None


def _promoted_detection_frequency_mhz(detection):
    frequency_mhz = _promoted_detection_float(
        detection,
        "frequency_mhz",
        "freq_mhz",
    )

    if frequency_mhz is not None:
        return frequency_mhz

    frequency_hz = _promoted_detection_float(
        detection,
        "frequency_hz",
        "freq_hz",
    )

    if frequency_hz is not None:
        return frequency_hz / 1e6

    return None


def _promoted_detection_label(detection):
    """Pick a useful initial display label without making the record Wi-Fi-specific."""
    for key in (
        "display_label",
        "classification",
        "label",
        "ssid",
        "bssid",
        "mac",
        "detector",
    ):
        value = str(detection.get(key) or "").strip()
        if value:
            return value

    return "Promoted Detection"


def _promoted_detection_location(
    component,
    detection,
    node_uid,
):
    """
    Resolve a valid TAK point for a promoted detection.

    Priority:
      1. Location carried by the detection
      2. Latest HIPRFISR node location
      3. Valid suppressed 0/0/0 point
    """
    lat = _promoted_detection_float(
        detection,
        "latitude",
        "lat",
        "point_lat",
        "point_latitude",
    )

    lon = _promoted_detection_float(
        detection,
        "longitude",
        "lon",
        "point_lon",
        "point_longitude",
    )

    alt = _promoted_detection_float(
        detection,
        "hae_meters",
        "hae_m",
        "hae",
        "alt",
        "altitude",
        "point_hae",
    )

    node_record = {}

    try:
        node_record = (
            getattr(component, "nodes", {})
            or {}
        ).get(
            node_uid,
            {},
        ) or {}
    except Exception:
        node_record = {}

    if lat is None:
        lat = _promoted_detection_float(
            node_record,
            "lat",
            "latitude",
        )

    if lon is None:
        lon = _promoted_detection_float(
            node_record,
            "lon",
            "longitude",
        )

    if alt is None:
        alt = _promoted_detection_float(
            node_record,
            "alt",
            "altitude",
            "hae_m",
            "hae",
        )

    # A CoT event must always contain numeric point values. A zero point with
    # high uncertainty is preferable to emitting lat="None"/lon="None".
    if lat is None or lon is None:
        lat = 0.0
        lon = 0.0

    if alt is None:
        alt = 0.0

    return (
        float(lat),
        float(lon),
        float(alt),
    )


async def promoteDetectionToSoi(
    component: object,
    detection=None,
    requester_uid: str = "",
    requester_callsign: str = "",
):
    """
    Promote one complete structured detection into a new authoritative SOI.

    The textual detection is retained as a snapshot. Any artifact references
    already present on the detection are linked to the SOI without duplicating
    artifact metadata.
    """
    detection = _normalize_promoted_detection(detection)

    if not detection:
        component.logger.warning(
            "promoteDetectionToSoi received an empty detection"
        )
        return

    node_uid = str(detection.get("node_uid") or "").strip()
    frequency_mhz = _promoted_detection_frequency_mhz(detection)

    if not node_uid:
        component.logger.warning(
            "promoteDetectionToSoi detection missing node_uid"
        )
        return

    if frequency_mhz is None:
        component.logger.warning(
            "promoteDetectionToSoi detection missing a valid frequency"
        )
        return

    soi_id = str(uuid.uuid4())
    operation_id = str(
        detection.get("opid")
        or detection.get("operation_id")
        or ""
    ).strip()

    observation_time = (
        detection.get("timestamp")
        or detection.get("observation_time")
        or datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
    )

    lat, lon, alt = _promoted_detection_location(
        component,
        detection,
        node_uid,
    )

    artifact_ids = []

    for candidate in (
        detection.get("artifact_ids", []),
        detection.get("artifact_id", ""),
    ):
        values = candidate if isinstance(candidate, list) else [candidate]

        for value in values:
            value = str(value or "").strip()
            if value and value not in artifact_ids:
                artifact_ids.append(value)

    artifact_links = []

    for link in detection.get("artifact_links", []) or []:
        if not isinstance(link, dict):
            continue

        linked_artifact_id = str(
            link.get("artifact_id", "")
            or ""
        ).strip()

        if not linked_artifact_id:
            continue

        artifact_links.append(dict(link))

        if linked_artifact_id not in artifact_ids:
            artifact_ids.append(linked_artifact_id)

    for linked_artifact_id in artifact_ids:
        if any(
            str(link.get("artifact_id", "") or "").strip()
            == linked_artifact_id
            for link in artifact_links
        ):
            continue

        artifact_links.append({
            "artifact_id": linked_artifact_id,
            "operation_id": operation_id,
        })

    summary = {
        "source": "detection_promotion",
        "promoted_by_uid": requester_uid or "",
        "promoted_by_callsign": requester_callsign or "",
        "detection_snapshots": [dict(detection)],
        "artifact_ids": artifact_ids,
        "artifact_links": artifact_links,
        "stage": "PROMOTED",
        "stage_order": 5,
    }

    await soiUpdate(
        component,
        node_uid=node_uid,
        soi_id=soi_id,
        frequency_mhz=frequency_mhz,
        status="PROMOTED",
        operation_id=operation_id,
        artifact_id=(artifact_ids[-1] if artifact_ids else ""),
        summary=summary,
        lat=lat,
        lon=lon,
        alt=alt,
        observation_time=observation_time,
    )

    component.logger.info(
        "Promoted detection to SOI "
        f"soi_id={soi_id}, node_uid={node_uid}"
    )


async def promoteDetectionToTarget(
    component: object,
    detection=None,
    requester_uid: str = "",
    requester_callsign: str = "",
):
    """
    Convert an existing structured detection directly into an authoritative target.
    No plugin action or Sensor Node execution is involved.
    """
    detection = _normalize_promoted_detection(detection)

    if not detection:
        component.logger.warning(
            "promoteDetectionToTarget received an empty detection"
        )
        return

    node_uid = str(detection.get("node_uid") or "").strip()

    if not node_uid:
        component.logger.warning(
            "promoteDetectionToTarget detection missing node_uid"
        )
        return

    target_id = str(uuid.uuid4())
    frequency_mhz = _promoted_detection_frequency_mhz(detection)

    observation_time = (
        detection.get("timestamp")
        or detection.get("observation_time")
        or datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
    )

    lat = _promoted_detection_float(
        detection,
        "latitude",
        "lat",
    )

    lon = _promoted_detection_float(
        detection,
        "longitude",
        "lon",
    )

    alt = _promoted_detection_float(
        detection,
        "hae_meters",
        "hae_m",
        "alt",
    )

    location = {}

    if lat is not None:
        location["lat"] = lat

    if lon is not None:
        location["lon"] = lon

    if alt is not None:
        location["hae_m"] = alt

    if observation_time:
        location["timestamp"] = observation_time

    location["source"] = "wintak_detection_promotion"

    display_label = _promoted_detection_label(detection)

    classification = {
        "display_label": display_label,
        "confidence": None,
        "source": "promoted_detection",
        "candidates": [],
    }

    summary = {
        "source": "detection_promotion",
        "promoted_by_uid": requester_uid or "",
        "promoted_by_callsign": requester_callsign or "",
        "detection_event_uid": str(
            detection.get("event_uid") or ""
        ),
        "attributes": dict(detection),
    }

    history_entry = {
        "event": "promoted_from_detection",
        "source": "detection_promotion",
        "requester_uid": requester_uid or "",
        "requester_callsign": requester_callsign or "",
        "detection_event_uid": str(
            detection.get("event_uid") or ""
        ),
        "timestamp": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
    }

    await targetUpdate(
        component,
        node_uid=node_uid,
        target_id=target_id,
        source_soi_id="",
        frequency_mhz=frequency_mhz,
        state="detected",
        artifact_id="",
        classification=classification,
        location=location,
        history_entry=history_entry,
        summary=summary,
        lat=lat,
        lon=lon,
        alt=alt,
        observation_time=observation_time,
    )

    component.logger.info(
        f"Promoted detection to target "
        f"target_id={target_id}, node_uid={node_uid}"
    )


async def deleteSoi(
    component: object,
    soi_key: str = "",
    node_uid: str = "",
    soi_id: str = "",
):
    """Delete one authoritative SOI record while preserving artifacts."""
    soi_key = str(soi_key or "").strip()
    node_uid = str(node_uid or "").strip()
    soi_id = str(soi_id or "").strip()

    if not soi_key and soi_id:
        soi_key = f"{node_uid}:{soi_id}"

    removed = None

    if soi_key:
        removed = component.sois.pop(soi_key, None)

    if removed is None and soi_id:
        for candidate_key, candidate in list(component.sois.items()):
            if not isinstance(candidate, dict):
                continue

            if str(candidate.get("soi_id", "") or "").strip() != soi_id:
                continue

            candidate_node_uid = str(
                candidate.get("node_uid", "")
                or ""
            ).strip()

            if node_uid and candidate_node_uid != node_uid:
                continue

            soi_key = candidate_key
            removed = component.sois.pop(candidate_key, None)
            break

    parameters = {
        "soi_key": soi_key,
        "node_uid": node_uid,
        "soi_id": soi_id,
        "success": removed is not None,
    }

    message = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "soiDeleted",
        fissure.comms.MessageFields.PARAMETERS:
            parameters,
    }

    if component.dashboard_connected:
        await component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            message,
        )

    if removed is not None:
        component.logger.info(
            "Deleted SOI record "
            f"soi_key={soi_key}, soi_id={soi_id}"
        )


async def sendSoisListTak(
    component: object,
    requester_uid: str = "",
    requester_type: str = "tak",
    node_uid: str = "",
    request_id: str = "",
    requester_callsign: str = "",
) -> None:
    """
    Return HIPRFISR's authoritative merged SOI records.

    Dashboard receives one structured list over ZMQ. TAK receives one normal
    SOI CoT event per record so WinTAK can reuse its existing SOI parser/upsert
    path.
    """
    records = []

    try:
        soi_store = getattr(component, "sois", {}) or {}

        if isinstance(soi_store, dict):
            iterable = soi_store.values()
        elif isinstance(soi_store, list):
            iterable = soi_store
        else:
            iterable = []

        for soi in iterable:
            if not isinstance(soi, dict):
                continue

            soi_node_uid = str(
                soi.get("node_uid", "")
                or ""
            ).strip()

            if node_uid and soi_node_uid != str(node_uid).strip():
                continue

            records.append(dict(soi))

        records.sort(
            key=lambda record: float(
                record.get("updated_at")
                or record.get("created_at")
                or 0
            ),
            reverse=True,
        )

    except Exception:
        component.logger.exception("sendSoisListTak failed")
        records = []

    # -------------------------------------------------------------
    # Dashboard response: structured list over ZMQ
    # -------------------------------------------------------------
    if requester_type == "dashboard":
        PARAMETERS = {
            "node_uid": node_uid,
            "sois": records,
        }

        msg = {
            fissure.comms.MessageFields.IDENTIFIER:
                component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME:
                "sendSoisListTakReturn",
            fissure.comms.MessageFields.PARAMETERS:
                PARAMETERS,
        }

        if component.dashboard_connected:
            await component.dashboard_socket.send_msg(
                fissure.comms.MessageTypes.COMMANDS,
                msg,
            )

        return

    # -------------------------------------------------------------
    # TAK response: replay normal SOI CoT events
    # -------------------------------------------------------------
    for record in records:
        try:
            soi_node_uid = str(
                record.get("node_uid", "")
                or node_uid
                or ""
            ).strip()

            soi_id = str(
                record.get("soi_id", "")
                or ""
            ).strip()

            operation_id = str(
                record.get("operation_id", "")
                or ""
            ).strip()

            soi_key = str(
                record.get("soi_key", "")
                or ""
            ).strip()

            uid_core = soi_id or operation_id or soi_key

            if not soi_node_uid or not uid_core:
                component.logger.warning(
                    "sendSoisListTak: skipping malformed SOI record "
                    f"node_uid={soi_node_uid!r}, soi_id={soi_id!r}, "
                    f"operation_id={operation_id!r}"
                )
                continue

            tak_uid = (
                f"fissure-soi-{soi_node_uid}-{uid_core}-"
                f"refresh-{int(time.time() * 1000)}"
            )

            summary = record.get("summary") or {}

            if not isinstance(summary, dict):
                summary = {}

            tak_data = {
                "event_type": "soi",
                "node_uid": soi_node_uid,
                "soi_id": soi_id,
                "frequency_mhz": record.get("frequency_mhz"),
                "status": record.get("status", ""),
                "operation_id": operation_id,
                "artifact_id": record.get("artifact_id", ""),

                "model_classification":
                    record.get("model_classification", ""),
                "model_confidence":
                    record.get("model_confidence"),
                "database_classification":
                    record.get("database_classification", ""),

                "stage": record.get("stage"),
                "stage_order": record.get("stage_order"),

                "request_id": request_id,
                "requester_uid": requester_uid,
                "requester_callsign": requester_callsign,
            }

            if summary:
                tak_data["summary"] = summary

            tak_data = {
                key: value
                for key, value in tak_data.items()
                if value is not None
                and not (
                    isinstance(value, str)
                    and value.strip() == ""
                )
            }

            await fissure.utils.tak_messages.send(
                component,
                {
                    "msg_type": "event",
                    "uid": tak_uid,
                    "data": tak_data,
                    "tak_icon": "r-x-fissure-soi",
                    "lat": record.get("lat"),
                    "lon": record.get("lon"),
                    "alt": record.get("hae_m"),
                },
                requester_type,
                requester_uid,
            )

        except Exception:
            component.logger.exception(
                "sendSoisListTak: failed emitting SOI refresh event"
            )
      

def _artifact_metadata_for_tak(metadata):
    """Return XML-safe, display-oriented Artifact metadata for TAK clients."""
    if not isinstance(metadata, dict):
        return {}

    normalized = {}

    for raw_key, value in metadata.items():
        key = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(raw_key)).strip("_.-")
        if not key:
            key = "field"
        if key[0].isdigit():
            key = "field_" + key

        base_key = key
        suffix = 2
        while key in normalized:
            key = f"{base_key}_{suffix}"
            suffix += 1

        if isinstance(value, (dict, list, tuple)):
            try:
                normalized[key] = json.dumps(value, sort_keys=True, default=str)
            except Exception:
                normalized[key] = str(value)
        elif value is not None:
            normalized[key] = str(value)

    return normalized


def _artifact_tak_data(
    record,
    request_id="",
    requester_uid="",
    requester_callsign="",
):
    """
    Build manifest-only artifact metadata for TAK clients.
    """
    metadata = record.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    files = record.get("files")
    if not isinstance(files, list):
        files = []

    relations = record.get("relations")
    if not isinstance(relations, list):
        relations = []

    source_id = str(
        record.get("source_id", "")
        or ""
    )

    file_count = int(
        record.get(
            "file_count",
            len(files),
        )
        or len(files)
    )

    total_size = int(
        record.get(
            "total_size",
            sum(
                int(
                    item.get("size", 0)
                    or 0
                )
                for item in files
                if isinstance(item, dict)
            ),
        )
        or 0
    )

    file_summaries = []

    for file_record in files:
        if not isinstance(file_record, dict):
            continue

        file_summaries.append(
            {
                "id": str(
                    file_record.get("id", "")
                    or ""
                ),
                "name": str(
                    file_record.get("name", "")
                    or ""
                ),
                "relative_path": str(
                    file_record.get(
                        "relative_path",
                        "",
                    )
                    or ""
                ),
                "size": int(
                    file_record.get("size", 0)
                    or 0
                ),
                "sha256": str(
                    file_record.get("sha256", "")
                    or ""
                ),
                "role": str(
                    file_record.get("role", "")
                    or ""
                ),
                "content_type": str(
                    file_record.get(
                        "content_type",
                        "",
                    )
                    or ""
                ),
            }
        )

    data = {
        "event_type": "artifact_metadata",
        "name": record.get("name") or "",
        "timestamp": (
            record.get("modified_at")
            or record.get("created_at")
            or ""
        ),
        "artid": (
            record.get("id")
            or record.get("artifact_id")
            or ""
        ),
        "operation_id":
            record.get("operation_id") or "",
        "source_id": source_id,
        "artifact_type":
            record.get("artifact_type") or "",
        "file_count": file_count,
        "total_size": total_size,
        "created_at":
            record.get("created_at") or "",
        "modified_at":
            record.get("modified_at") or "",
        "files": file_summaries,
        "relations": relations,
        "metadata":
            _artifact_metadata_for_tak(
                metadata
            ),
        "request_id": request_id,
        "requester_uid": requester_uid,
        "requester_callsign":
            requester_callsign,
    }

    return {
        key: value
        for key, value in data.items()
        if value is not None
        and value != {}
        and value != []
        and not (
            isinstance(value, str)
            and value.strip() == ""
        )
    }


async def sendArtifactsListTak(
    component: object,
    requester_uid: str = "",
    requester_type: str = "dashboard",
    node_uid: str = "",
    request_id: str = "",
    requester_callsign: str = "",
) -> None:
    """
    Return canonical artifact metadata to Dashboard or TAK clients.
    """
    tracker = getattr(
        component,
        "artifact_tracker",
        None,
    )

    if tracker is None:
        component.logger.warning(
            "sendArtifactsListTak: no artifact_tracker"
        )
        return

    node_uid = str(
        node_uid or ""
    ).strip()

    try:
        if node_uid:
            artifact_objects = (
                tracker.get_artifacts_source_id(
                    node_uid,
                    sortby="modified_at",
                )
            )
        else:
            artifact_objects = (
                tracker.get_all_artifacts()
            )

    except Exception:
        component.logger.exception(
            "sendArtifactsListTak: "
            "failed reading artifact tracker"
        )
        artifact_objects = []

    records = []

    for artifact in artifact_objects:
        try:
            if isinstance(artifact, dict):
                record = dict(artifact)
            elif hasattr(
                artifact,
                "to_dict",
            ):
                record = artifact.to_dict()
            else:
                continue

            artifact_id = str(
                record.get("id", "")
                or ""
            ).strip()

            source_id = str(
                record.get("source_id", "")
                or ""
            ).strip()

            if not artifact_id:
                continue

            if node_uid and source_id != node_uid:
                continue

            records.append(record)

        except Exception:
            component.logger.exception(
                "sendArtifactsListTak: "
                "failed normalizing artifact record"
            )

    records.sort(
        key=lambda record: str(
            record.get("modified_at")
            or record.get("created_at")
            or ""
        ),
        reverse=True,
    )

    if requester_type == "dashboard":
        parameters = {
            "node_uid": node_uid,
            "artifacts": records,
        }

        message = {
            fissure.comms.MessageFields.IDENTIFIER:
                component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME:
                "sendArtifactsListTakReturn",
            fissure.comms.MessageFields.PARAMETERS:
                parameters,
        }

        if component.dashboard_connected:
            await component.dashboard_socket.send_msg(
                fissure.comms.MessageTypes.COMMANDS,
                message,
            )

        return

    for record in records:
        artifact_id = str(
            record.get("id", "")
            or ""
        ).strip()
        name = str(
            record.get("name", "")
            or ""
        ).strip()
        timestamp = str(
            record.get("modified_at")
            or record.get("created_at")
            or ""
        ).strip()
        source_id = str(
            record.get("source_id", "")
            or ""
        ).strip()

        if (
            not artifact_id
            or not name
            or not timestamp
        ):
            component.logger.warning(
                "sendArtifactsListTak: "
                "skipping malformed artifact %s",
                artifact_id,
            )
            continue

        event_uid = (
            f"{source_id or node_uid or 'unknown-source'}"
            f"-artifact_metadata-"
            f"{artifact_id}-refresh-"
            f"{int(time.time() * 1000)}"
        )

        await fissure.utils.tak_messages.send(
            component,
            {
                "msg_type": "event",
                "uid": event_uid,
                "data": _artifact_tak_data(
                    record,
                    request_id=request_id,
                    requester_uid=requester_uid,
                    requester_callsign=
                        requester_callsign,
                ),
            },
            requester_type,
            requester_uid,
        )
