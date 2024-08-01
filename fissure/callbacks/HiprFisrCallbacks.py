# from comms.FissureZMQNode import *
# from fissure.comms.constants import *
# from fissure_libutils import *
from typing import List

import binascii
import fissure.comms
import fissure.utils
import fissure.utils.library
import os
import time
import yaml
import asyncio
import socket

""" HiprFisr Specific Callback Functions """

DELAY_SHORT = 0.25  # seconds


async def addToLibrary(
    component: object,
    protocol_name="",
    packet_name="",
    packet_data="",
    soi_data="",
    statistical_data="",
    modulation_type="",
    demodulation_fg_data="",
    attack="",
    dissector="",
):
    """
    Adds new data to the library.
    """
    # Make a Backup of the Current Library
    stream = open(os.path.join(fissure.utils.YAML_DIR, "Library Backups", "library_backup_add.yaml"), "w")
    yaml.dump(component.library, stream, default_flow_style=False, indent=5)

    # Check Protocol
    protocol_exists = False
    for protocol in fissure.utils.library.getProtocols(component.library):
        # Existing Protocol
        if protocol == protocol_name:
            protocol_exists = True

            # Add New Modulation Type
            if len(modulation_type) > 0:
                if modulation_type not in fissure.utils.library.getModulations(component.library, protocol):
                    fissure.utils.library.addModulation(component.library, protocol, modulation_type)

            # Add New Packet Type
            if len(packet_data) > 0:
                all_new_fields = {}
                for n in range(0, len(packet_data)):
                    field_name = packet_data[n][0]
                    field_length = packet_data[n][1]
                    field_default = packet_data[n][2]
                    field_order = n + 1
                    is_crc = packet_data[n][3]
                    crc_range = packet_data[n][4]

                    field_to_add = fissure.utils.library.newField(
                        field_name, field_default, field_length, field_order, is_crc, crc_range
                    )
                    all_new_fields.update(field_to_add)

                # Create New Packet Type
                packet_to_add = fissure.utils.library.newPacket(packet_name, all_new_fields)
                packet_to_add[packet_name]["Sort Order"] = (
                    len(fissure.utils.library.getPacketTypes(component.library, protocol)) + 1
                )  # Makes the packet appear on the bottom of any list

                # Add it to the Protocol
                fissure.utils.library.addPacketType(component.library, protocol, packet_to_add)
                fissure.utils.library.addDissector(component.library, protocol, packet_name, None, None)

            # Add Dissector
            if len(dissector) > 0:
                fissure.utils.library.addDissector(
                    component.library, protocol, packet_name, dissector[0], dissector[1]
                )

            # Add SOI Data
            if len(soi_data) > 0:
                soi = fissure.utils.library.newSOI(
                    soi_data[0],
                    soi_data[1],
                    soi_data[2],
                    soi_data[3],
                    soi_data[4],
                    soi_data[5],
                    soi_data[6],
                    soi_data[7],
                )
                fissure.utils.library.addSOI(component.library, protocol, soi)

            # Add Demodulation Flow Graph
            if len(demodulation_fg_data) > 0:
                if (
                    (len(demodulation_fg_data[0]) > 0)
                    and (len(demodulation_fg_data[1]) > 0)
                    and (len(demodulation_fg_data[2]) > 0)
                    and (len(demodulation_fg_data[3]) > 0)
                ):
                    fissure.utils.library.addDemodulationFlowGraph(
                        component.library,
                        protocol,
                        demodulation_fg_data[0],
                        demodulation_fg_data[1],
                        demodulation_fg_data[2],
                        demodulation_fg_data[3],
                    )  # [0] = mod. type, [1] = flow graph name, [2] = hardware

            # Add Attack
            if len(attack) > 0:
                # attack_dict = {attack[0]: {attack[1]: {attack[2]: {attack[3]: {attack[4]: attack[5]}}}}}
                fissure.utils.library.addAttack(component.library, protocol_name, attack)

    # New Protocol
    if not protocol_exists:
        make_new_protocol = fissure.utils.library.newProtocol(protocolname=protocol_name)
        fissure.utils.library.addProtocol(component.library, make_new_protocol)

    # Save File
    fissure.utils.save_library(component.library, component.os_info)

    # Send Message to PD to Update Library
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "setFullLibrary",
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])
    
    # Send Message to Dashboard to Update Library
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "setFullLibrary",
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def removeDemodulationFlowGraph(
    component: object, protocol_name="", modulation_type="", hardware="", demodulation_fg=""
):
    """
    Removes demodulation flow graph from the library.
    """
    # Make a Backup of the Current Library
    stream = open(os.path.join(fissure.utils.YAML_DIR, "Library Backups", "library_backup_remove.yaml"), "w")
    yaml.dump(component.library, stream, default_flow_style=False, indent=5)

    # Delete Demodulation Flow Graph From Library
    fissure.utils.library.removeDemodulationFlowGraph(component.library, protocol_name, modulation_type, hardware, demodulation_fg)

    # Delete Files (*.py, *.pyc, *.grc) from Flow Graph Library
    if demodulation_fg is not None:
        try:
            os.remove(os.path.join(fissure.utils.get_fg_library_dir(component.os_info), "PD Flow Graphs", demodulation_fg))
        except:
            pass
        try:
            os.remove(os.path.join(fissure.utils.get_fg_library_dir(component.os_info), "PD Flow Graphs", demodulation_fg.replace(".py", ".pyc")))
        except:
            pass
        try:
            os.remove(os.path.join(fissure.utils.get_fg_library_dir(component.os_info), "PD Flow Graphs", demodulation_fg.replace(".py", ".grc")))
        except:
            pass

    # Save File
    fissure.utils.save_library(component.library, component.os_info)

    # Send Message to PD to Update Library
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "setFullLibrary",
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])
    
    # Send Message to Dashboard to Update Library
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "setFullLibrary",
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def removeSOI(component: object, protocol_name="", soi=""):
    """
    Removes SOI from the library.
    """
    # Make a Backup of the Current Library
    stream = open(os.path.join(fissure.utils.YAML_DIR, "Library Backups", "library_backup_remove.yaml"), "w")
    yaml.dump(component.library, stream, default_flow_style=False, indent=5)

    # Delete SOI From Library
    fissure.utils.library.removeSOI(component.library, protocol_name, soi)

    # Save File
    fissure.utils.save_library(component.library, component.os_info)

    # Send Message to PD to Update Library
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "setFullLibrary",
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])
    
    # Send Message to Dashboard to Update Library
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "setFullLibrary",
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def removePacketType(component: object, protocol_name="", packet_type=""):
    """
    Removes packet type from the library.
    """
    # Make a Backup of the Current Library
    stream = open(os.path.join(fissure.utils.YAML_DIR, "Library Backups", "library_backup_remove.yaml"), "w")
    yaml.dump(component.library, stream, default_flow_style=False, indent=5)

    # Delete Packet Type From Library
    fissure.utils.library.removePacketType(component.library, protocol_name, packet_type)

    # Save File
    fissure.utils.save_library(component.library, component.os_info)

    # Send Message to PD to Update Library
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "setFullLibrary",
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])
    
    # Send Message to Dashboard to Update Library
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "setFullLibrary",
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def removeModulationType(component: object, protocol_name="", modulation_type=""):
    """Removes modulation type from the library."""
    # Make a Backup of the Current Library
    stream = open(os.path.join(fissure.utils.YAML_DIR, "Library Backups", "library_backup_remove.yaml"), "w")
    yaml.dump(component.library, stream, default_flow_style=False, indent=5)

    # Delete Modulation Type From Library
    fissure.utils.library.removeModulationType(component.library, protocol_name, modulation_type)

    # Save File
    fissure.utils.save_library(component.library, component.os_info)

    # Send Message to PD to Update Library
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "setFullLibrary",
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])
    
    # Send Message to Dashboard to Update Library
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "setFullLibrary",
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def removeAttackFromLibrary(
    component: object,
    protocol_name="",
    attacks=[],
    modulations=[],
    hardware=[],
    all_content=False,
    remove_flow_graphs=False,
):
    """
    Removes attacks from the library.
    """
    # Make a Backup of the Current Library
    stream = open(os.path.join(fissure.utils.YAML_DIR, "Library Backups", "library_backup_remove.yaml"), "w")
    yaml.dump(component.library, stream, default_flow_style=False, indent=5)

    # Delete Attacks From Library
    flow_graph_delete_list = []
    for a in attacks:
        for m in modulations:
            if len(component.library["Protocols"][protocol_name]["Attacks"][a]) > 0:
                if m in component.library["Protocols"][protocol_name]["Attacks"][a]:
                    for h in hardware:
                        if len(component.library["Protocols"][protocol_name]["Attacks"][a][m]) > 0:
                            if h in list(
                                component.library["Protocols"][protocol_name]["Attacks"][a][m]["Hardware"].keys()
                            ):
                                # Get the Flow Graph Name
                                get_file_type = list(
                                    component.library["Protocols"][protocol_name]["Attacks"][a][m]["Hardware"][
                                        h
                                    ].keys()
                                )[0]
                                flow_graph_delete_list.append(
                                    component.library["Protocols"][protocol_name]["Attacks"][a][m]["Hardware"][h][
                                        get_file_type
                                    ]
                                )
                                del component.library["Protocols"][protocol_name]["Attacks"][a][m]["Hardware"][h]
                                if (
                                    len(component.library["Protocols"][protocol_name]["Attacks"][a][m]["Hardware"])
                                    == 0
                                ):
                                    del component.library["Protocols"][protocol_name]["Attacks"][a][m]["Hardware"]
                    if len(component.library["Protocols"][protocol_name]["Attacks"][a][m]) == 0:
                        del component.library["Protocols"][protocol_name]["Attacks"][a][m]
        if len(component.library["Protocols"][protocol_name]["Attacks"][a]) == 0:
            del component.library["Protocols"][protocol_name]["Attacks"][a]
    try:
        if len(component.library["Protocols"][protocol_name]["Attacks"]) == 0:
            del component.library["Protocols"][protocol_name]["Attacks"]
    except:
        # Avoids ["Attacks"] Key Errors
        pass

    # Determine if Deleted Attack was the Last of its Name
    no_more_attacks = len(attacks) * [False]
    for n in range(0, len(attacks)):
        try:
            if len(component.library["Protocols"][protocol_name]["Attacks"][n]) == 0:
                no_more_attacks[n] = True
        except KeyError:
            no_more_attacks[n] = True

    # Delete Attacks from Library Tree
    for n in range(0, len(no_more_attacks)):
        if no_more_attacks[n] is True:
            try:
                component.library["Attacks"]["Single-Stage Attacks"].remove(
                    [
                        item
                        for item in component.library["Attacks"]["Single-Stage Attacks"]
                        if item.split(",")[0] == attacks[n]
                    ][0]
                )
                component.library["Attacks"]["Multi-Stage Attacks"].remove(
                    [
                        item
                        for item in component.library["Attacks"]["Multi-Stage Attacks"]
                        if item.split(",")[0] == attacks[n]
                    ][0]
                )
                component.library["Attacks"]["Fuzzing Attacks"].remove(
                    [
                        item
                        for item in component.library["Attacks"]["Fuzzing Attacks"]
                        if item.split(",")[0] == attacks[n]
                    ][0]
                )
            except:
                pass

    # Delete Files (*.py, *.pyc, *.grc) from Flow Graph Library
    if remove_flow_graphs is True:
        if len(flow_graph_delete_list) > 0:
            for f in flow_graph_delete_list:
                if f != "None":
                    try:
                        os.remove(os.path.join(fissure.utils.get_fg_library_dir(component.os_info), "Single-Stage Flow Graphs", f))
                    except:
                        pass
                    try:
                        os.remove(os.path.join(fissure.utils.get_fg_library_dir(component.os_info), "Single-Stage Flow Graphs", f.replace(".py", ".pyc")))
                    except:
                        pass
                    try:
                        os.remove(os.path.join(fissure.utils.get_fg_library_dir(component.os_info), "Single-Stage Flow Graphs", f.replace(".py", ".grc")))
                    except:
                        pass

    # Delete All Protocol Content
    if all_content is True:
        del component.library["Protocols"][protocol_name]

    # Save File
    fissure.utils.save_library(component.library, component.os_info)

    # Send Message to PD to Update Library
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "setFullLibrary",
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])
    
    # Send Message to Dashboard to Update Library
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "setFullLibrary",
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def shutdown(component: object, identifiers: List[str]):
    """
    Process `shutdown` commands

    :param identifier: Identifier of the fissure component to shutdown
    :type identifier: str
    """
    component.logger.info(f"received shutdown command for {identifiers}")
    for identifier in identifiers:
        if identifier == component.identifier:
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

            pd_running = True
            tsi_running = True
            while pd_running or tsi_running:
                msg = await component.backend_router.recv_msg()

                if msg is not None:
                    msg_type = msg.get(fissure.comms.MessageFields.TYPE)
                    msg_name = msg.get(fissure.comms.MessageFields.MESSAGE_NAME)
                    sender = msg.get(fissure.comms.MessageFields.IDENTIFIER)
                    if msg_type == fissure.comms.MessageTypes.STATUS and msg_name == "Shutting Down":
                        if sender == fissure.comms.Identifiers.PD:
                            pd_running = False
                        if sender == fissure.comms.Identifiers.TSI:
                            tsi_running = False
            component.shutdown = True
        else:
            # forward 'Shutdown' command to specified fissure component(s)
            pass


async def disconnect(component: object):
    ack = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "Disconnect OK",
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.STATUS, ack)
    component.logger.debug("Dashboard Disconnecting")
    component.dashboard_connected = False
    component.session_active = False
    component.heartbeats.update({fissure.comms.Identifiers.DASHBOARD: None})
    component.connect_loop = True


async def clearWidebandList(component: object):
    """Clears the Wideband List"""
    component.logger.debug("Executing Callback: Clear Wideband List")
    component.wideband_list = []


# #################### To Multiple Components ############################


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


# #################### From Multiple Components ##########################


# ############################# To PD ####################################


async def startPD(component: object, sensor_node_id=0):
    """Sends a message to PD and sensor node to start processing on any incoming bits."""
    # Forward Message to PD
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "startPD",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])

    # Send Message to Sensor Node
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def stopPD(component: object, sensor_node_id=0):
    """
    Signals to PD and sensor node to stop protocol discovery.
    """
    # Forward Message to PD
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "stopPD",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.pd_id])

    # Send Message to Sensor Node
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


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


# ############################### From PD ################################

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
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


# ############################ To TSI ####################################


async def addBlacklist(component: object, start_frequency=0, end_frequency=0):
    """
    Forwards Add Blacklist message to TSI.
    """
    # Send Message to TSI
    PARAMETERS = {"start_frequency": start_frequency, "end_frequency": end_frequency}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "addBlacklist",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.tsi_id])


async def removeBlacklist(component: object, start_frequency=0, end_frequency=0):
    """
    Forwards Remove Blacklist message to TSI.
    """
    # Send Message to TSI
    PARAMETERS = {"start_frequency": start_frequency, "end_frequency": end_frequency}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "removeBlacklist",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.tsi_id])


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
    sensor_node_id=0,
    common_parameter_names=[],
    common_parameter_values=[],
    method_parameter_names=[],
    method_parameter_values=[],
):
    """
    Signals to TSI to start TSI Conditioner.
    """
    # Forward Message to TSI
    PARAMETERS = {
        "sensor_node_id": sensor_node_id,
        "common_parameter_names": common_parameter_names,
        "common_parameter_values": common_parameter_values,
        "method_parameter_names": method_parameter_names,
        "method_parameter_values": method_parameter_values,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "startTSI_Conditioner",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.tsi_id])


async def stopTSI_Conditioner(component, sensor_node_id=0):
    """
    Signals to TSI to stop TSI conditioner.
    """
    # Forward Message to TSI
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "stopTSI_Conditioner",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.backend_router.send_msg(fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.tsi_id])


# ############################# From TSI #################################


async def conditionerProgressBarReturn(component: object, progress=0, file_index=0):
    """."""
    # Forward Message to Dashboard
    PARAMETERS = {"progress": progress, "file_index": file_index}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "conditionerProgressBarReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def tsiConditionerFinished(component: object, table_strings=[]):
    """."""
    # Forward Message to Dashboard
    PARAMETERS = {"table_strings": table_strings}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "tsiConditionerFinished",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def feProgressBarReturn(component: object, progress=0, file_index=0):
    """."""
    # Forward Message to Dashboard
    PARAMETERS = {"progress": progress, "file_index": file_index}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "feProgressBarReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
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
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


# ########################## To Sensor Node ##############################


async def scanHardware(component: object, tab_index=0, hardware_list=[]):
    """
    Sends a message to a sensor node to scan for hardware information.
    """
    # Forward the Message
    PARAMETERS = {"tab_index": tab_index, "hardware_list": hardware_list}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "scanHardware",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[int(tab_index)].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def probeHardware(component: object, tab_index, table_row_text):
    """
    Sends a message to a sensor node to probe select hardware.
    """
    # Forward the Message
    PARAMETERS = {"tab_index": tab_index, "table_row_text": table_row_text}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "probeHardware",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[int(tab_index)].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def guessHardware(component: object, tab_index=0, table_row=[], table_row_text="", guess_index=0):
    """
    Sends a message to a sensor node to guess details for select hardware.
    """
    # Forward the Message
    PARAMETERS = {
        "tab_index": tab_index,
        "table_row": table_row,
        "table_row_text": table_row_text,
        "guess_index": guess_index,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "guessHardware",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[int(tab_index)].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def transferSensorNodeFile(
    component: object, sensor_node_id=0, local_file="", remote_folder="", refresh_file_list=False
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
        "sensor_node_id": sensor_node_id,
        "local_file_data": get_data,
        "remote_filepath": remote_filepath,
        "refresh_file_list": refresh_file_list,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "transferSensorNodeFile",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def deleteArchiveReplayFiles(component: object, sensor_node_id=0):
    """
    Deletes all the files in the Archive_Replay folder on the sensor node ahead of file transfer for replay.
    """
    # Send Message
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "deleteArchiveReplayFiles",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def refreshSensorNodeFiles(component: object, sensor_node_id=0, sensor_node_folder=""):
    """
    Signals to sensor node to return file details for a specified folder.
    """
    # Send Message
    PARAMETERS = {"sensor_node_id": sensor_node_id, "sensor_node_folder": sensor_node_folder}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "refreshSensorNodeFiles",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def deleteSensorNodeFile(component: object, sensor_node_id=0, sensor_node_file=""):
    """
    Signals to sensor node to delete a file or folder for a specified file path.
    """
    # Send Message
    PARAMETERS = {"sensor_node_id": sensor_node_id, "sensor_node_file": sensor_node_file}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "deleteSensorNodeFile",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def downloadSensorNodeFile(component: object, sensor_node_id=0, sensor_node_file="", download_folder=""):
    """
    Signals to sensor node to transfer a copy of a file or folder for saving it to a specified file path.
    """
    # Send Message
    PARAMETERS = {
        "sensor_node_id": sensor_node_id,
        "sensor_node_file": sensor_node_file,
        "download_folder": download_folder,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "downloadSensorNodeFile",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def overwriteDefaultAutorunPlaylist(component: object, sensor_node_id=0, playlist_dict={}):
    """Signals to sensor node to overwrite the default autorun playlist."""
    # Send Message
    PARAMETERS = {"sensor_node_id": sensor_node_id, "playlist_dict": playlist_dict}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "overwriteDefaultAutorunPlaylist",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def autorunPlaylistStart(component: object, sensor_node_id=0, playlist_dict={}, trigger_values=[]):
    """Signals to sensor node to start autorun playlist."""
    # Send Message
    PARAMETERS = {"sensor_node_id": sensor_node_id, "playlist_dict": playlist_dict, "trigger_values": trigger_values}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistStart",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def autorunPlaylistStop(component: object, sensor_node_id=0):
    """Signals to sensor node to stop autorun playlist."""
    # Send Message
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistStop",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def physicalFuzzingStart(
    component: object,
    sensor_node_id=0,
    fuzzing_variables=[],
    fuzzing_type="",
    fuzzing_min=0,
    fuzzing_max=0,
    fuzzing_update_period=0,
    fuzzing_seed_step=0,
):
    """Command for starting physical fuzzing on a running flow graph."""
    # Send Message to Sensor Node
    PARAMETERS = {
        "sensor_node_id": sensor_node_id,
        "fuzzing_variables": fuzzing_variables,
        "fuzzing_type": fuzzing_type,
        "fuzzing_min": fuzzing_min,
        "fuzzing_max": fuzzing_max,
        "fuzzing_update_period": fuzzing_update_period,
        "fuzzing_seed_step": fuzzing_seed_step,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "physicalFuzzingStart",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def physicalFuzzingStop(component: object, sensor_node_id=0):
    """Sends message to Sensor Node to stop the physical fuzzing thread being performed on a running flow graph."""
    # Send Message to sensor_node,PD
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "physicalFuzzingStop",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def multiStageAttackStart(
    component: object,
    sensor_node_id=0,
    filenames=[],
    variable_names=[],
    variable_values=[],
    durations=[],
    repeat=False,
    file_types=[],
    autorun_index=0,
    trigger_values=[]
):
    """
    Sends message to Sensor Node/PD to start multi-stage attack.
    """
    # Send Message to Sensor Node
    PARAMETERS = {
        "sensor_node_id": sensor_node_id,
        "filenames": filenames,
        "variable_names": variable_names,
        "variable_values": variable_values,
        "durations": durations,
        "repeat": repeat,
        "file_types": file_types,
        "autorun_index": autorun_index,
        "trigger_values": trigger_values
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "multiStageAttackStart",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def multiStageAttackStop(component: object, sensor_node_id=0, autorun_index=0):
    """
    Sends message to Sensor Node/PD to stop multi-stage attack.
    """
    # Send Message to Sensor Node
    PARAMETERS = {
        "sensor_node_id": sensor_node_id,
        # "parameter": parameter,
        "autorun_index": autorun_index,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "multiStageAttackStop",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def archivePlaylistStart(
    component: object,
    sensor_node_id=0,
    flow_graph="",
    filenames=[],
    frequencies=[],
    sample_rates=[],
    formats=[],
    channels=[],
    gains=[],
    durations=[],
    repeat=False,
    ip_address="",
    serial="",
    trigger_values=[]
):
    """
    Sends message to Sensor Node to start the archive playlist.
    """
    # Send Message to Sensor Node
    PARAMETERS = {
        "sensor_node_id": sensor_node_id,
        "flow_graph": flow_graph,
        "filenames": filenames,
        "frequencies": frequencies,
        "sample_rates": sample_rates,
        "formats": formats,
        "channels": channels,
        "gains": gains,
        "durations": durations,
        "repeat": repeat,
        "ip_address": ip_address,
        "serial": serial,
        "trigger_values": trigger_values
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "archivePlaylistStart",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def archivePlaylistStop(component: object, sensor_node_id=0):
    """
    Sends message to Sensor Node to stop the archive playlist.
    """
    # Send Message to Sensor Node
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "archivePlaylistStop",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def attackFlowGraphStop(component: object, sensor_node_id=0, parameter="", autorun_index=0):
    """
    Sends message to Sensor Node to stop a running attack flow graph.
    """
    # Send Message to Sensor Node
    PARAMETERS = {"sensor_node_id": sensor_node_id, "parameter": parameter, "autorun_index": autorun_index}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "attackFlowGraphStop",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def attackFlowGraphStart(
    component: object,
    sensor_node_id=0,
    flow_graph_filepath="",
    variable_names=[],
    variable_values=[],
    file_type="",
    run_with_sudo=False,
    autorun_index=0,
    trigger_values=[]
):
    """Command for loading an attack."""
    # Send Message to Sensor Node
    PARAMETERS = {
        "sensor_node_id": sensor_node_id,
        "flow_graph_filepath": flow_graph_filepath,
        "variable_names": variable_names,
        "variable_values": variable_values,
        "file_type": file_type,
        "run_with_sudo": run_with_sudo,
        "autorun_index": autorun_index,
        "trigger_values": trigger_values
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "attackFlowGraphStart",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def iqFlowGraphStart(
    component: object, sensor_node_id=0, flow_graph_filepath="", variable_names=[], variable_values=[], file_type=""
):
    """
    Command for loading an IQ flow graph.
    """
    # Send Message to Sensor Node
    PARAMETERS = {
        "sensor_node_id": sensor_node_id,
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
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def iqFlowGraphStop(component: object, sensor_node_id=0, parameter=""):
    """
    Sends message to Sensor Node to stop a running attack flow graph.
    """
    # Send Message to Sensor Node,PD
    # PARAMETERS = {"sensor_node_id": sensor_node_id, "parameter": parameter}
    PARAMETERS = {"parameter": parameter}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "iqFlowGraphStop",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def inspectionFlowGraphStart(
    component: object, sensor_node_id=0, flow_graph_filepath="", variable_names=[], variable_values=[], file_type=""
):
    """
    Command for starting an inspection flow graph.
    """
    # Send Message to Sensor Node
    PARAMETERS = {
        "sensor_node_id": sensor_node_id,
        "flow_graph_filepath": flow_graph_filepath,
        "variable_names": variable_names,
        "variable_values": variable_values,
        "file_type": file_type,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "inspectionFlowGraphStart",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def inspectionFlowGraphStop(component: object, sensor_node_id=0, parameter=""):
    """
    Command for stopping an inspection flow graph.
    """
    # Send Message to Sensor Node,PD
    PARAMETERS = {"parameter": parameter}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "inspectionFlowGraphStop",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def snifferFlowGraphStart(
    component: object, sensor_node_id=0, flow_graph_filepath="", variable_names=[], variable_values=[]
):
    """
    Starts a sniffer flow graph.
    """
    # Send Message to Sensor Node
    PARAMETERS = {
        "sensor_node_id": sensor_node_id,
        "flow_graph_filepath": flow_graph_filepath,
        "variable_names": variable_names,
        "variable_values": variable_values,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "snifferFlowGraphStart",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def snifferFlowGraphStop(component: object, sensor_node_id=0, parameter=""):
    """
    Stops a sniffer flow graph
    """
    # Send Message to Sensor Node,PD
    PARAMETERS = {"sensor_node_id": sensor_node_id, "parameter": parameter}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "snifferFlowGraphStop",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def startScapy(component: object, sensor_node_id=0, interface="", interval=0, loop=False, operating_system=""):
    """
    Signals to Sensor Node to start Scapy.
    """
    # Send Message
    PARAMETERS = {
        "sensor_node_id": sensor_node_id,
        "interface": interface,
        "interval": interval,
        "loop": loop,
        "operating_system": operating_system,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "startScapy",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def stopScapy(component: object, sensor_node_id=0):
    """Signals to Sensor Node to stop Scapy."""
    # Send Message
    # PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "stopScapy",  # ,
        # fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def setVariable(component: object, sensor_node_id=0, flow_graph="", variable="", value=""):
    """
    Sends a message to Sensor Node to change the variable of the running flow graph.
    """
    # Send Message to Sensor Node
    PARAMETERS = {"sensor_node_id": sensor_node_id, "flow_graph": flow_graph, "variable": variable, "value": value}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "setVariable",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def protocolDiscoveryFG_Start(
    component: object, sensor_node_id=0, flow_graph_filepath="", variable_names=[], variable_values=[]
):
    """
    Sends message to Sensor Node to run a flow graph.
    """
    # Send Message to Sensor Node
    PARAMETERS = {
        "sensor_node_id": sensor_node_id,
        "flow_graph_filepath": flow_graph_filepath,
        "variable_names": variable_names,
        "variable_values": variable_values,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "protocolDiscoveryFG_Start",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def protocolDiscoveryFG_Stop(component: object, sensor_node_id=0):
    """
    Sends message to Sensor Node to stop a running flow graph.
    """
    # Send Message to Sensor Node
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "protocolDiscoveryFG_Stop",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def updateConfiguration(
    component: object, sensor_node_id=0, start_frequency=0, end_frequency=0, step_size=0, dwell_time=0, detector_port=0
):
    """Forwards the Update Configuration message to TSI."""
    # Forward Message to Sensor Node
    PARAMETERS = {
        "sensor_node_id": sensor_node_id,
        "start_frequency": start_frequency,
        "end_frequency": end_frequency,
        "step_size": step_size,
        "dwell_time": dwell_time,
        "detector_port": detector_port,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "updateConfiguration",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    # component.tsi_hiprfisr_server.sendmsg(
    #     'Commands',
    #     Identifier='HIPRFISR',
    #     MessageName='Update Configuration',
    #     Parameters=[start_frequency, end_frequency, step_size, dwell_time]
    # )
    # component.backend_router.send_msg(
    #     fissure.comms.MessageTypes.COMMANDS,
    #     target_ids=[component.tsi_id],
    #     msg
    # )  # Future?
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def startTSI_Detector(component: object, sensor_node_id=0, detector="", variable_names=[], variable_values=[], detector_port=0):
    """
    Signals to sensor node to start TSI detector.
    """
    # Forward Message to Sensor Node
    PARAMETERS = {
        "sensor_node_id": sensor_node_id,
        "detector": detector,
        "variable_names": variable_names,
        "variable_values": variable_values,
        "detector_port": detector_port,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "startTSI_Detector",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    # component.tsi_hiprfisr_server.sendmsg(
    #     'Commands',
    #     Identifier='HIPRFISR',MessageName='Start TSI Detector', Parameters=[detector,variable_names,variable_values]
    # )
    # component.backend_router.send_msg(
    #     fissure.comms.MessageTypes.COMMANDS, target_ids=[component.tsi_id], msg
    # )  # Future?
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def stopTSI_Detector(component: object, sensor_node_id=0):
    """
    Signals to sensor node to stop TSI detector.
    """
    # Forward Message to Sensor Node
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "stopTSI_Detector",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    # component.tsi_hiprfisr_server.sendmsg('Commands', Identifier='HIPRFISR', MessageName='Stop TSI Detector')
    # component.backend_router.send_msg(
    #     fissure.comms.MessageTypes.COMMANDS, msg, target_ids=[component.tsi_id]
    # )  # Future?
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def terminateSensorNode(component: object, sensor_node_id):
    """
    Stops sensor_node.py for local operations.
    """
    # Send to Sensor Node
    sensor_node_id = int(sensor_node_id)
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "terminateSensorNode",
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    # Notify the Dashboard Immediately
    component.sensor_nodes[sensor_node_id].connected = False
    component.sensor_nodes[sensor_node_id].terminated = True  # To avoid heartbeat connection reset
    component.heartbeats[fissure.comms.Identifiers.SENSOR_NODE][sensor_node_id] = None
    PARAMETERS = {"component_name": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "componentDisconnected",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    # await asyncio.sleep(1)
    # component.sensor_nodes[sensor_node_id].__del__()
    # component.sensor_nodes[sensor_node_id].__init__()
    # component.sensor_nodes[sensor_node_id] = None


async def connectToSensorNode(component: object, sensor_node_id, ip_address, msg_port, hb_port, recall_settings):
    """
    Connects the HIPRFISR to a sensor node.
    """
    # Connect to Specified Sensor Node

    # Connect Sensor Node & HIPRFISR: DEALER-DEALER
    # if component.sensor_nodes[sensor_node_id].connected is False:
    sensor_node_id = int(sensor_node_id)
    # sensor_node_pair_port = str(msg_port)  # int(component.settings['sensor_node_hiprfisr_dealer_port'])
    # sensor_node_ip_address = ip_address
    # sensor_node_pub_port = str(pub_port)  # str(component.settings['sensor_node_pub_port'])

    #######################################################
    # comms_info = self.settings.get("hiprfisr")
    # self.hiprfisr_address = fissure.comms.Address(address_config=comms_info.get("backend"))
    # self.socket_id = f"{self.identifier}-{uuid.uuid4()}"
    # self.hiprfisr_socket = fissure.comms.Listener(sock_type=zmq.DEALER, name=f"{self.identifier}::backend")
    # self.hiprfisr_socket.set_identity(self.socket_id)
    #######################################################

    # Connect HiprFisr Listener to Sensor Node
    sensor_node_address = fissure.comms.Address(
        protocol="tcp", address=ip_address, hb_channel=int(hb_port), msg_channel=int(msg_port)
    )
    component.logger.info(f"connecting to HiprFisr @ {sensor_node_address}")

    # Test Connection to Heartbeat Port
    if ip_address != "127.0.0.1":
        try:
            with socket.create_connection((ip_address, hb_port), 10):
                component.logger.info(f"PUB socket is listening on {ip_address}:{hb_port}")

        # Timed Out
        except:
            component.logger.error(f"Failed to connect to {sensor_node_address}")
            PARAMETERS = {"sensor_node_id": sensor_node_id}
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: component.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: "sensorNodeConnectTimeout",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
            return

    connection_successful = await component.sensor_nodes[sensor_node_id].listener.connect(sensor_node_address, 15)
    component.sensor_nodes[sensor_node_id].terminated = False

    # Connected
    if connection_successful:  # Always successful
        # Recall Settings
        if recall_settings == "True":
            component.logger.info("Recalling settings...")
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: component.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: "recallSettings",
            }
            await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def disconnectFromSensorNode(component: object, sensor_node_id=0, ip_address="", msg_port=0, hb_port=0, delete_node=False):
    """
    Ends connections to sensor_node.py during remote operation.
    """
    # Notify the Dashboard Immediately
    sensor_node_id = int(sensor_node_id)
    component.sensor_nodes[sensor_node_id].connected = False
    component.sensor_nodes[sensor_node_id].terminated = True  # To avoid heartbeat connection reset
    PARAMETERS = {"component_name": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "componentDisconnected",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    # Notify the Sensor Node
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "hiprfisrDisconnecting",
    }
    await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    # Close the HIPRFISR Socket
    get_connections = component.sensor_nodes[sensor_node_id].listener.connections
    connections_copy = set(get_connections)
    for connection in connections_copy:
        component.sensor_nodes[sensor_node_id].listener.disconnect(connection)
    # component.sensor_nodes[sensor_node_id].listener.shutdown()

    # Remove the Connection Permanently
    if delete_node is True:
        component.sensor_nodes[sensor_node_id] = None

        # Shift Sensor Node Variables By One
        for n in range(sensor_node_id, len(component.sensor_nodes) - 1):
            component.sensor_nodes[n] = component.sensor_nodes[n + 1]
            component.heartbeats[fissure.comms.Identifiers.SENSOR_NODE][n] = component.heartbeats[
                fissure.comms.Identifiers.SENSOR_NODE
            ][n + 1]
            component.sensor_nodes[n].connected = component.sensor_nodes[n + 1].connected
            component.sensor_nodes[n].terminated = component.sensor_nodes[n + 1].terminated

            if component.sensor_nodes[n + 1] is not None:
                msg = {
                    fissure.comms.MessageFields.IDENTIFIER: component.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "componentConnected",
                    fissure.comms.MessageFields.PARAMETERS: n,
                }
                await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    # # Send to Sensor Node
    # sensor_node_id = int(sensor_node_id)
    # msg = {
    #     fissure.comms.MessageFields.IDENTIFIER: component.identifier,
    #     fissure.comms.MessageFields.MESSAGE_NAME: "terminateSensorNode",
    # }
    # await component.sensor_nodes[sensor_node_id].listener.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    # # Notify the Dashboard Immediately
    # component.sensor_nodes[sensor_node_id].connected = False
    # component.sensor_nodes[sensor_node_id].terminated = True  # To avoid heartbeat connection reset
    # component.heartbeats[fissure.comms.Identifiers.SENSOR_NODE][sensor_node_id] = None
    # PARAMETERS = {"component_name": sensor_node_id}
    # msg = {
    #     fissure.comms.MessageFields.IDENTIFIER: component.identifier,
    #     fissure.comms.MessageFields.MESSAGE_NAME: "componentDisconnected",
    #     fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    # }
    # await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    # await asyncio.sleep(1)
    # component.sensor_nodes[sensor_node_id].__del__()
    # component.sensor_nodes[sensor_node_id].__init__()


# ######################### From Sensor Node #############################
async def refreshSensorNodeFilesResults(
    component: object, sensor_node_id=0, filepaths=[], file_sizes=[], file_types=[], modified_dates=[]
):
    """
    Forwards the refresh sensor node files results to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {
        "sensor_node_id": sensor_node_id,
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
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def autorunPlaylistStarted(component: object, sensor_node_id=0):
    """
    Forwards the autorun playlist started message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistStarted",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def autorunPlaylistFinished(component: object, sensor_node_id=0):
    """
    Forwards the autorun playlist finished message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistFinished",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def flowGraphError(component: object, sensor_node_id=0, error=""):
    """
    Forwards the flow graph error message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id, "error": error}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphError",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def detectorFlowGraphError(component: object, sensor_node_id=0, error=""):
    """
    Forwards the detector flow graph error message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id, "error": error}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "detectorFlowGraphError",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def archivePlaylistFinished(component: object, sensor_node_id=0):
    """
    Forwards the Archive playlist finished message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "archivePlaylistFinished",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def archivePlaylistPosition(component: object, sensor_node_id=0, position=0):
    """
    Forwards the Archive playlist position to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id, "position": position}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "archivePlaylistPosition",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def multiStageAttackFinished(component: object, sensor_node_id=0):
    """
    Forwards the multi-stage attack finished message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "multiStageAttackFinished",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def flowGraphFinishedSniffer(component: object, sensor_node_id=0, category=""):
    """
    Forwards the flow graph finished sniffer message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id, "category": category}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedSniffer",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def flowGraphFinishedIQ_Inspection(component: object, sensor_node_id=0):
    """
    Forwards the flow graph finished IQ inspection message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedIQ_Inspection",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def flowGraphFinishedIQ_Playback(component: object, sensor_node_id=0):
    """
    Forwards the flow graph finished IQ playback message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedIQ_Playback",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def flowGraphFinishedIQ(component: object, sensor_node_id=0):
    """
    Forwards the flow graph finished IQ message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedIQ",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def flowGraphFinished(component: object, sensor_node_id=0, category=""):
    """
    Forwards the flow graph finished message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id, "category": category}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinished",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def flowGraphStartedSniffer(component: object, sensor_node_id=0, category=""):
    """
    Forwards the flow graph started IQ sniffer message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id, "category": category}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedSniffer",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def flowGraphStartedIQ_Inspection(component: object, sensor_node_id=0):
    """
    Forwards the flow graph started IQ inspection message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedIQ_Inspection",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def flowGraphStartedIQ_Playback(component: object, sensor_node_id=0):
    """
    Forwards the flow graph started IQ playback message to the Dasbhoard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedIQ_Playback",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def flowGraphStartedIQ(component: object, sensor_node_id=0):
    """
    Forwards the flow graph started IQ message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedIQ",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def flowGraphStarted(component: object, sensor_node_id=0, category=""):
    """
    Forwards the flow graph started message to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"sensor_node_id": sensor_node_id, "category": category}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStarted",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def recallSettingsReturn(component: object, settings_dict):
    """Connects the HIPRFISR to a sensor node."""
    # Send the Message
    PARAMETERS = {"settings_dict": settings_dict}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "recallSettingsReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def hardwareProbeResults(component: object, tab_index=0, output="", height_width=[]):
    """
    Forwards the hardware probe results message to the Dashboard.
    """
    # PARAMETERS = {"tab_index": tab_index, "output": eval(f'"{output}"'), "height_width": height_width}
    PARAMETERS = {"tab_index": tab_index, "output": output, "height_width": height_width}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "hardwareProbeResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def hardwareScanResults(component: object, tab_index=0, hardware_scan_results=[]):
    """
    Forwards the hardware scan results message to the Dashboard.
    """
    PARAMETERS = {"tab_index": tab_index, "hardware_scan_results": hardware_scan_results}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "hardwareScanResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def hardwareGuessResults(
    component: object, tab_index=0, table_row=[], hardware_type="", scan_results="", new_guess_index=0
):
    """
    Forwards sensnor node hardware guess results from HIPRFISR to Dashboard.
    """
    PARAMETERS = {
        "tab_index": tab_index,
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
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def bandID_Return(component: object, sensor_node_id=0, band_id=0, frequency=0):
    """
    Forwards the band ID return message for TSI detectors to the Dashboard.
    """
    PARAMETERS = {"sensor_node_id": sensor_node_id, "band_id": band_id, "frequency": frequency}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "bandID_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def detectorReturn(component: object, frequency_value=0, power_value=0, time_value=0.0):
    """
    Forwards the TSI Detector return message with signals of interest to the Dashboard.
    """
    # Send the Message
    PARAMETERS = {"frequency_value": frequency_value, "power_value": power_value, "time_value": time_value}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "detectorReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def saveFile(component: object, sensor_node_id=0, operation="", filepath="", data=""):
    """
    Saves a file from a remote sensor node to the local HIPRFISR computer.
    """
    # Save File and Send Message to Dashboard
    if operation == "IQ":
        # Save
        if len(filepath) > 0:
            with open(filepath, "wb") as file:
                file.write(binascii.a2b_hex(data))

        # Send Message to Dashboard
        PARAMETERS = {"sensor_node_id": sensor_node_id}
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedIQ",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    elif operation == "Download":
        # Save
        if len(filepath) > 0:
            with open(filepath, "wb") as file:
                file.write(binascii.a2b_hex(data))

            # Send Message to Dashboard
            PARAMETERS = {"sensor_node_id": sensor_node_id}
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: component.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: "fileDownloaded",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


# ##################### Outdated/Incomplete/Unused #######################


async def setTargetSOI(
    component: object, frequency=0, modulation="", bandwidth=0, continuous=False, start_frequency=0, end_frequency=0
):
    """The Dashboard has selected a target SOI to examine. This SOI will be looked up in the
    library to find a best-fit flow graph.
    """
    # Save the SOI
    component.settings["target_SOI"] = str(
        [frequency, modulation, bandwidth, continuous, start_frequency, end_frequency]
    )

    # System has now been Manually Triggered
    component.soi_manually_triggered = True

    component.process_sois = True


async def setSOI_SelectionMode(component: object, mode=0):
    """Sets the SOI selection mode for deciding when to load flow graphs."""
    component.settings["SOI_trigger_mode"] = int(mode)


async def setProcessSOIs(component: object, enabled=False, priorities=None, filters=None, parameters=None):
    """Enables/Disables SOI Check in the main event loop."""
    # Assign to Variables
    if enabled is True:
        component.process_sois = True
        component.soi_priorities = priorities
        component.soi_filters = filters
        component.soi_parameters = parameters
    elif enabled is False:
        component.process_sois = False


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


async def SOI_Check(component: object, trigger_mode=""):
    """The methods for deciding when to examine SOIs"""
    returned_SOI = None

    # Manual Selection
    if trigger_mode == 0:
        component.logger.info("TRIGGER MODE 0")
        if component.soi_manually_triggered is True:
            component.process_sois = False
            component.soi_manually_triggered = False
            component.logger.info("SOI Triggered Manually: New Target Selected")
            returned_SOI = component.settings["target_SOI"]

            # Search Library for Flow Graphs
            # ~ searchLibraryForFlowGraphs(
            #     [
            #         returned_SOI[0],
            #         returned_SOI[1],
            #         returned_SOI[2],
            #         returned_SOI[3],
            #         returned_SOI[4],
            #         returned_SOI[5],
            #         0,
            #         0,
            #         0,
            #         0
            #     ]
            # )
            component.searchLibraryForFlowGraphs(
                ["", returned_SOI[1], "", "", "", "", 0, 0, 0, 0], None
            )  # Modulation Only

    # Time Elapsed
    elif trigger_mode == 1:
        component.logger.info("TRIGGER MODE 1")
        current_time = time.time()
        if (current_time - float(component.settings["SOI_trigger_time"])) > float(
            component.settings["SOI_trigger_timeout"]
        ):  # SOI_trigger_time should not be in YAML
            component.settings["SOI_trigger_time"] = str(current_time)
            component.logger.info("SOI Timeout: Selecting New Target")

            if len(component.soi_list) > 0:  # If the SOI list is not empty
                # Choose SOI from the current list
                returned_SOI = component.SOI_AutoSelect(
                    component.soi_list, component.soi_priorities, component.soi_filters
                )  # What happens if nothing is returned?

                # Send Message to Dashboard to Check Radio Button
                PARAMETERS = {"returned_soi": returned_SOI}
                msg = {
                    fissure.comms.MessageFields.IDENTIFIER: component.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "SOI Chosen",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
                }
                component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    # SOI quantity reached
    elif trigger_mode == 2:
        if len(component.soi_list) >= int(component.settings["SOI_quantity_limit"]):
            component.process_sois = False
            component.logger.info("SOI Quantity Reached: Selecting New Target")
            # Choose SOI from the current list
            returned_SOI = component.SOI_AutoSelect(
                component.soi_list, component.soi_priorities, component.soi_filters
            )  # What happens if nothing is returned?

            # Send Message to Dashboard to Check Radio Button
            PARAMETERS = {"returned_soi": returned_SOI}
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: component.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: "SOI Chosen",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            component.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    return returned_SOI


async def ignoreSOIs(component: object, dashboard_soi_blacklist=[]):
    """
    Copies the Dashboard's blacklisted items to the HIPRFISR. These items will be removed from the HIPRFISR SOI list.
    """
    # Copy the Dashboard Blacklist
    component.soi_blacklist = dashboard_soi_blacklist

    # Remove Blacklisted SOIs from SOI List
    for soi in dashboard_soi_blacklist:
        for x in reversed(range(0, len(component.soi_list))):
            if soi == component.soi_list[x][1] + "," + component.soi_list[x][0]:
                del component.soi_list[x]
