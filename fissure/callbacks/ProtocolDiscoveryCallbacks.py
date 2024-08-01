from collections import Counter

import fissure.comms
import numpy as np
import threading
import zmq
import asyncio
import os


# ########################## From HIPRFISR ###############################
async def startPD(component: object, sensor_node_id=0):
    """
    Starts protocol discovery and bit listener.
    """
    # Start Processing Bits
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, component.startPD)


async def stopPD(component: object, sensor_node_id=0):
    """
    Stops the protocol discovery bit listener and processing.
    """
    # Call the Function used Multiple Times
    component.stopPD()


async def pdBitsReturn(component: object, bits_message=""):
    """
    Adds bits to the circular buffer.
    """
    # Store the Bits
    print("Received:", bits_message)
    if bits_message:
        if len(bits_message) > 3:
            formatted_bits = bits_message[3:]  # Part of ZMQ header (Command Length, Command)
    else:
        formatted_bits = ""
    component.circular_buffer += formatted_bits  # Buffer needs to be a string


async def searchLibraryForFlowGraphs(component: object, soi_data=[], hardware=""):
    """
    Calls searchLibraryForFlowGraphs() as a threaded callback.
    """
    # Search Library
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, component.searchLibraryForFlowGraphs, soi_data, hardware)


async def findPreambles(component: object, window_min=0, window_max=0, ranking=0, std_deviations=0):
    """
    Callback to send the current best estimate of preamble stats to HIPRFISR so user can
    see preamble candidates in the latest buffer.
    """
    # Update Window Parameters
    component.min_size = int(window_min)
    component.max_size = int(window_max)
    component.ranking = int(ranking)
    component.num_std = int(std_deviations)

    # Search Library
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, component.findPreambles)


async def searchLibrary(component: object, soi_data="", field_data=""):
    """
    Callback to search the library for matching SOI values, field values, and statistics.
    """
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, component.searchSOIsAndFields, soi_data, field_data)


async def setFullLibrary(component: object):
    """
    Reloads the FISSURE library after an update.
    """
    # Reload the Library
    component.pd_library = fissure.utils.load_library(component.os_info)


async def sliceByPreamble(component: object, preamble="", first_n=0, estimated_length=0):
    """
    This slices the buffer by a preamble and returns the lengths, the length counts,
    and the top N packets for each length.
    """
    # Convert Bits to Nibbles
    estimated_length = int(int(estimated_length) / 4)

    # Take a Snapshot of the Buffer
    current_buffer = component.circular_buffer

    # Get the Preamble Locations in the Data
    idxs = component.findAll(current_buffer, preamble)

    if len(idxs) > 0:
        # Get the Lengths and Occurrences
        idxs.append(len(current_buffer) - 1)  # Don't skip last match on the upcoming 'np.diff(idxs)'
        if estimated_length == 0:
            packet_lengths = Counter(
                np.diff(idxs)
            )  # Or leave a Counter object and find the most common when populating the table
            packet_lengths = packet_lengths.most_common()
        else:
            packet_lengths = Counter([estimated_length] * (len(idxs) - 1))
            packet_lengths = packet_lengths.most_common()

        # Convert packet_lengths to a Serializable Format
        packet_lengths = [(int(length), count) for length, count in packet_lengths]

        # Get First N Packets for each Length
        packet_dict = {}
        for n in range(0, len(packet_lengths)):
            packet_dict[packet_lengths[n][0]] = []

        # Guess the Estimated Length for Each Message
        buffer_index = idxs[0]
        if estimated_length == 0:
            for p_length in np.diff(idxs):
                if len(packet_dict[p_length]) < int(first_n):
                    packet_dict[p_length].append(current_buffer[buffer_index : buffer_index + p_length])
                buffer_index += p_length

        # Use the Provided Message Length
        else:
            for i in range(0, packet_lengths[0][1]):
                if i < int(first_n):
                    packet_dict[int(estimated_length)].append(current_buffer[idxs[i] : idxs[i] + estimated_length])

        # Send the Message to the HIPRFISR
        PARAMETERS = {"packet_lengths": packet_lengths, "packet_dict": packet_dict}
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "sliceByPreambleReturn",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    # No Matches Found
    else:
        # Send the Message to the HIPRFISR
        PARAMETERS = {"packet_lengths": [], "packet_dict": {}}
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "sliceByPreambleReturn",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def setBufferSize(component: object, min_buffer_size=0, max_buffer_size=0):
    """
    Sets the minimum and maximum sizes for the circular buffer.
    """
    component.min_buffer = int(min_buffer_size)
    component.max_buffer = int(max_buffer_size)


async def clearPD_Buffer(component: object):
    """Clears the contents of the Protocol Discovery buffer."""
    # # Cancel the Thread
    # component.gr_processing.set()

    # # Close the Socket
    # pd_bits_port = component.settings_dictionary["pd_bits_port"]
    # # pd_default_ip_address = "127.0.0.1"
    # component.pd_bit_sub_listener.disconnect(
    #     "tcp://" + component.bit_ip_address + ":" + str(pd_bits_port)
    # )  # 'localhost' causes issues with Sensor Node Flow Graphs for some reason

    # Flush the Buffer
    component.flush_buffer = True

    # # Restart the Socket
    # try:
    #     component.pd_bit_sub_listener.connect(
    #         "tcp://" + component.bit_ip_address + ":" + str(pd_bits_port)
    #     )  # 'localhost' causes issues with Sensor Node Flow Graphs for some reason
    #     component.pd_bit_sub_listener.setsockopt_string(zmq.SUBSCRIBE, "")

    #     # Set up Thread to Fill Read Buffer up to max_buffer
    #     component.gr_processing = threading.Event()
    #     component.gr_srv = threading.Thread(
    #         target=component.grRcvThread,
    #         args=(
    #             component.gr_processing,
    #             component.pd_bit_sub_listener,
    #         ),
    #     )
    #     component.gr_srv.setDaemon(True)
    #     component.gr_srv.start()

    # except KeyError:
    #     print("Unable to connect PD SUB to Sensor Node PUB")


async def findEntropy(component: object, message_length=0, preamble=""):
    """
    Calls the findEntropy() function in a new thread and returns a message on the pub socket when completed.
    """
    # Run Event and Do Not Block
    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        None, 
        component.findEntropy, 
        message_length,
        preamble,
    )


async def addPubSocket(component: object, ip_address="", port=0):
    """
    Connects the pd_bit_sub_listener to another ZMQ PUB socket for receiving bits.
    """
    pass
    # # Connect
    # component.pd_bit_sub_listener.connect("tcp://" + ip_address + ":" + port)


async def removePubSocket(component: object, address=""):
    """
    Removes the ZMQ PUB from the pd_bit_sub_listener.
    """
    pass
    # # Disconnect
    # component.pd_bit_sub_listener.disconnect("tcp://" + address)


async def updateLoggingLevels(component: object, new_console_level="", new_file_level=""):
    """ Update the logging levels on PD.
    """
    # Update New Levels for PD
    component.updateLoggingLevels(new_console_level, new_file_level)


async def updateFISSURE_Configuration(component: object, settings_dict={}):
    """ Reload fissure_config.yaml after changes.
    """
    # Update FISSURE Settings
    component.settings_dictionary = settings_dict  #self.loadConfiguration()

# ############################# Test #####################################
