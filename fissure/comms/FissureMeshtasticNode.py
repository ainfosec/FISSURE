import fissure.utils
from .constants import MessageFields, MessageTypes
import meshtastic
from meshtastic.serial_interface import SerialInterface
import json
import asyncio
from typing import Any, Dict, List, Optional, Set
import logging
from pubsub import pub
import time
import random
import string
from collections import deque
import msgpack
import binascii

POLL_TIMEOUT = 5  # Adjust as needed
ACK_TIMEOUT = 3  # Time to wait for an ACK
ID_EXPIRATION_SECONDS = 60  # Keep message IDs for 60 seconds

class FissureMeshtasticNode:
    """Handles communication via Meshtastic, integrating with existing ZMQ infrastructure."""

    def __init__(self, serial_port: str, name: str, context: object):
        """Initialize connection to Meshtastic device."""
        self.parent_component = name.split("::")[0] if "::" in name else name
        self.name = name.split("::")[1] if "::" in name else name
        self.logger = fissure.utils.get_logger(source=self.parent_component)

        self.loop = asyncio.get_event_loop()
        self.interface = SerialInterface(serial_port)
        self.message_queue = asyncio.Queue()  # Queue for received messages
        self.context = context  # Object containing the callback methods
        self.running = True  # Flag to control async processing
        
        # Cache for recently sent message IDs
        self.recent_message_ids = deque()
        
        pub.subscribe(self._handle_message, "meshtastic.receive.text")

        self.process_task = self.loop.create_task(self.process_messages())

    async def _enqueue_message(self, message: Dict):
        """Places received messages into the async queue."""
        try:
            await self.message_queue.put(message)
            # self.logger.info(f"Message enqueued: {message}")
            # self.logger.info(f"Queue size after put: {self.message_queue.qsize()}")
        except Exception as e:
            self.logger.warning(f"⚠️ Failed to enqueue message: {e}")

    async def recv_msg(self) -> Optional[Dict]:
        try:
            if self.message_queue.qsize() > 0:
                msgrcvd = await self.message_queue.get()
                self.logger.info(f"Message received: {msgrcvd}")
                return msgrcvd
            else:
                # self.logger.info("Message queue is empty, no message to receive.")
                return None
        except Exception as e:
            self.logger.warning(f"⚠️ Error while receiving message: {e}")
            return None

    async def process_messages(self):
        """Continuously processes messages from the queue using `run_callback`."""
        while self.running:
            # self.logger.debug(f"Process task running: {self.process_task and not self.process_task.done()}")

            if not self.process_task.done():
                msg = await self.message_queue.get()
                if msg:
                    self.logger.info("got message")
                    # self.logger.info(f"Preparing to execute callback for message: {msg}")
                    await self.run_callback(self.context, msg)
                else:
                    pass
                    # self.logger.warning("Received an empty or invalid message from the queue.")
            else:
                self.logger.error("Process task is not running as expected!")
            
            #await asyncio.sleep(0.2)

    def generate_short_uuid(self, length: int = 4) -> str:
        """Generate a short, random hexadecimal UUID."""
        return ''.join(random.choices(string.hexdigits.lower(), k=length))

    def cleanup_expired_message_ids(self):
        """Remove expired message IDs from the cache."""
        current_time = time.time()
        while self.recent_message_ids and (current_time - self.recent_message_ids[0][1]) > ID_EXPIRATION_SECONDS:
            self.recent_message_ids.popleft()

    def add_message_id(self, msg_id: str):
        """Add a message ID to the cache and clean up expired IDs."""
        self.cleanup_expired_message_ids()
        if msg_id not in [stored_id for stored_id, _ in self.recent_message_ids]:
            self.recent_message_ids.append((msg_id, time.time()))
        # self.logger.debug(f"Message ID Cache after adding {msg_id}: {self.recent_message_ids}")

    async def send_msg(self, msg_type: str, msg: Dict):
        msg_id = self.generate_short_uuid(4)  # Generate a 4-character short UUID

        # print("In the SEND!!")
        # print("Message Type:", msg_type)
        # print("Message Payload:", msg)

        source = msg.get(MessageFields.SOURCE, "U")  # Default source to 'U' for unknown
        destination = msg.get(MessageFields.DESTINATION, "0")  # Default destination to '0'
        msg_name = msg.get(MessageFields.MESSAGE_NAME, "")
        parameters = msg.get(MessageFields.PARAMETERS, {})

        msg_code = fissure.utils.MESSAGE_NAME_TO_CODE.get(msg_name, None)
        # print("Message Code:", msg_code)

        if not msg_code:
            self.logger.error(f"No message code mapping found for {msg_name}")
            return

        # Convert parameters to a binary format using msgpack
        if isinstance(parameters, dict):
            parameters_bytes = msgpack.packb(parameters, use_bin_type=True)
            parameters_str = binascii.hexlify(parameters_bytes).decode('utf-8')
        else:
            parameters_str = str(parameters) if parameters else ""

        # Format the message according to the new structure
        message = f"{source},{destination},{msg_code},{msg_id},{parameters_str}"
        
        self.add_message_id(msg_id)  # Store the ID to avoid processing if it bounces back
        await asyncio.get_running_loop().run_in_executor(None, self.interface.sendText, message)

        self.logger.info(f"Raw message sent: {message}")

    def _handle_message(self, packet, interface=None):
        """Handles incoming messages and decodes binary parameters if needed."""
        raw_text = packet.get("decoded", {}).get("text", "")
        
        if raw_text:
            try:
                components = raw_text.split(",", 4)  # Limit splits to avoid breaking the payload
                source = components[0]
                destination = components[1]
                msg_code = components[2]
                msg_id = components[3] if len(components) > 3 else ""
                parameters_hex = components[4] if len(components) > 4 else ""

                # Check for message ID duplication to prevent processing bounced messages
                self.cleanup_expired_message_ids()
                if any(msg_id == stored_id for stored_id, _ in self.recent_message_ids):
                    self.logger.info(f"Ignoring bounced message with ID: {msg_id}")
                    self.logger.debug(f"Current Message ID Cache: {self.recent_message_ids}")
                    return
                
                # Add the new message ID to avoid reprocessing if it bounces again
                self.add_message_id(msg_id)

                # Map the message code back to the appropriate callback name
                # print("AT THE HANDLE MESSAGE")
                # print("Message Code:", msg_code)
                msg_name = fissure.utils.MESSAGE_CODE_MAP.get(msg_code, "unknownMessage")
                # print("Message Name:", msg_name)

                # self.logger.info(f"Processing received message: {raw_text}")

                # Decode binary payload from hex to original dictionary
                parsed_parameters = {}
                if parameters_hex:
                    try:
                        parameters_bytes = binascii.unhexlify(parameters_hex)
                        parsed_parameters = msgpack.unpackb(parameters_bytes, raw=False)
                    except Exception as e:
                        self.logger.warning(f"⚠️ Failed to parse binary message parameters: {e}")
                        self.logger.warning(f"Raw parameters hex string: {parameters_hex}")
                        return

                # Normal message processing here
                parsed_data = {
                    "Identifier": source,
                    "MessageName": msg_name,
                    "Parameters": parsed_parameters,
                    "callback": msg_name
                }

                asyncio.run_coroutine_threadsafe(self._enqueue_message(parsed_data), self.loop)

            except Exception as e:
                self.logger.warning(f"⚠️ Failed to handle message: {e}")

    async def run_callback(self, context: object, parsed_command: Dict) -> Any:
        """
        Process and execute the callback with the provided parameters

        :param context: context to find the callback method
        :type context: object | Dict
        :param parsed_command: command containing the callback function to execute and (optional) parameters
        :type parsed_command: Dict
        :raises Exception: if the callback is not implemented in the provided context
        :return: result of the executed callback
        :rtype: any
        """
        print("In the run_callback of fissuremeshtasticnode!")
        print("Context:", context)
        print("Parsed Command:", parsed_command)

        cb_name = parsed_command.get("callback")
        try:
            cb = context.callbacks.get(cb_name)
        except AttributeError:  # pragma: no cover
            cb = context.get(cb_name)

        if cb is None:  # pragma: no cover
            raise Exception(f"method {cb_name} not implemented in context {context}")

        params = parsed_command.get("Parameters")

        # Ignore Message Parameters in Logging
        if cb_name in fissure.utils.BANNED_MESSAGE_NAMES:
            self.logger.debug(f"executing callback: {cb_name}")
        else:
            self.logger.debug(f"executing callback: {cb_name} with parameters: {params}")

        # Process parameters and execute callback function
        if params is None:
            # No Parameters
            return await cb(context)
        elif len(params) == 0:
            # Empty Parameters
            return await cb(context, *params)
        else:
            if isinstance(params, dict):  # Dictionary Params
                return await cb(context, **params)
            elif isinstance(params, list):  # List Params
                return await cb(context, *params)
            elif isinstance(params, str):  # Space Separated String Params
                return await cb(context, *(params.split()))
            else:  # pragma: no cover
                self.logger.warning(
                    f"[{self.name}] received callback ({cb_name}) with unrecognized parameters: {params}"
                )


    async def disconnect(self):
        """Gracefully disconnects from the Meshtastic device and stops message processing."""
        self.logger.info(f"Disconnecting Meshtastic node [{self.name}]...")
        
        # Stop message processing
        self.running = False

        # Cancel processing task if it exists
        if hasattr(self, "process_task") and self.process_task:
            self.process_task.cancel()
            try:
                await self.process_task
            except asyncio.CancelledError:
                self.logger.info("Message processing task successfully cancelled.")

        # Clear the message queue
        while not self.message_queue.empty():
            try:
                msg = self.message_queue.get_nowait()
                # self.logger.debug(f"Cleared message from queue during disconnect: {msg}")
            except Exception as e:
                self.logger.warning(f"Failed to clear message queue: {e}")

        # Unsubscribe from Meshtastic events
        try:
            pub.unsubscribe(self._handle_message, "meshtastic.receive.text")
            # self.logger.info("Unsubscribed from Meshtastic receive events.")
        except Exception as e:
            self.logger.warning(f"Failed to unsubscribe from Meshtastic events: {e}")

        # Close the Meshtastic Serial connection
        try:
            if self.interface:
                self.interface.close()
                self.interface = None  # Remove reference
                # self.logger.info("Meshtastic serial connection closed.")
            else:
                self.logger.warning("No valid Meshtastic serial interface found during disconnect.")
        except Exception as e:
            self.logger.warning(f"Error closing Meshtastic serial interface: {e}")

        # Cleanup message ID cache
        self.recent_message_ids.clear()
        self.logger.info(f"Meshtastic node [{self.name}] disconnected and cleaned up.")


    async def get_gps_position(self, timeout: int = 10) -> Optional[Dict[str, float]]:
        try:
            start_time = asyncio.get_running_loop().time()
            while asyncio.get_running_loop().time() - start_time < timeout:
                node_info = self.interface.getMyNodeInfo()
                if node_info and "position" in node_info:
                    position = node_info["position"]
                    if "latitudeI" in position and "longitudeI" in position:
                        latitude = round(position["latitudeI"] / 1e7, 6)
                        longitude = round(position["longitudeI"] / 1e7, 6)
                        altitude = position.get("altitude", 0.0)
                        return {"latitude": latitude, "longitude": longitude, "altitude": altitude}
                await asyncio.sleep(1)
            print("GPS data not available within timeout.")
            return None
        except Exception as e:
            print(f"Error accessing Meshtastic GPS: {e}")
            return None
