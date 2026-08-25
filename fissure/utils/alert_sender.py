# #!/usr/bin/env python3
# """Send alertReturn to HIPRFISR/Dashboard
# """
# from multiprocessing import Pipe
# from multiprocessing.connection import Connection
# import asyncio
# import subprocess
# import fissure.comms
# import json
# import logging
# import os
# import signal
# import threading


# def _alert_sender(
#     self,
#     cmd: str,
#     c2: Connection,
#     identifier: str,
#     node_uid: any,
#     hiprfisr_socket: fissure.comms.Server,
#     gps_position: dict,
#     logger: logging.Logger,
#     network_type: str,
# ):
#     """Run command and monitor stdout for alerts.

#     This function runs in a thread. It reads line-based JSON from the stdout
#     of a launched process and sends messages back to HIPRFISR.

#     Parameters
#     ----------
#     cmd : str
#         Command to execute.
#     c2 : Connection
#         Pipe for shutdown signaling.
#     identifier : str
#         Node identifier.
#     node_uid : any
#         Unique node ID.
#     hiprfisr_socket : fissure.comms.Server
#         Socket to HIPRFISR.
#     gps_position : dict
#         Dict with GPS keys.
#     logger : logging.Logger
#         Logger for debug/info/error messages.
#     network_type : str
#         "IP" or "Meshtastic"
#     """
#     try:
#         # Start the Command
#         self.proc = subprocess.Popen(
#             cmd,
#             stdout=subprocess.PIPE,
#             stderr=subprocess.PIPE,
#             stdin=subprocess.DEVNULL,  # stdin not needed
#             bufsize=1,
#             universal_newlines=True,
#             shell=True,
#             preexec_fn=os.setsid,
#         )

#         # Print the Errors While Running
#         def _read_stderr(pipe):
#             for line in iter(pipe.readline, ''):
#                 logger.error(f"[STDERR] {line.strip()}")
#             pipe.close()

#         threading.Thread(target=_read_stderr, args=(self.proc.stderr,), daemon=True).start()

#     except Exception as e:
#         logger.error(f"Failed to start alertSender command: {e}")
#         self.proc = None
#         return

#     stop = False

#     try:
#         # Read stdout line-by-line until signaled to stop or process ends
#         while not stop:
#             # Ensure the subprocess and stdout are still available
#             if not self.proc or not self.proc.stdout or self.proc.stdout.closed:
#                 break

#             try:
#                 line = self.proc.stdout.readline()
#             except ValueError:
#                 # This happens if stdout was closed while reading
#                 break

#             if not line:
#                 break  # EOF or closed

#             # Try to substitute GPS fields into the line
#             try:
#                 line = line % gps_position
#             except (TypeError, ValueError):
#                 pass  # Not a formatting string or placeholder missing

#             # Try to parse JSON and handle message types
#             try:
#                 data = json.loads(line)
#             except json.JSONDecodeError:
#                 logger.info(line.strip())
#                 continue

#             # Make sure it's a dict and has a message type
#             if not isinstance(data, dict) or 'msg' not in data:
#                 logger.info(str(data))
#                 continue

#             msg_type = data['msg']

#             if msg_type == 'alert':
#                 PARAMETERS = {
#                     "node_uid": node_uid,
#                     "alert_text": data.get('text')
#                 }
#                 msg = {
#                     fissure.comms.MessageFields.IDENTIFIER if network_type == "IP" else fissure.comms.MessageFields.SOURCE: identifier,
#                     fissure.comms.MessageFields.MESSAGE_NAME: "alertReturn" if network_type == "IP" else "alertReturnLT",
#                     fissure.comms.MessageFields.PARAMETERS: PARAMETERS if network_type == "IP" else { "node_uid": node_uid, "alert_text": PARAMETERS["alert_text"][:100] },
#                 }
#                 asyncio.run(hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg))

#             elif msg_type == 'tak':
#                 if 'type' not in data:
#                     data['type'] = "a-f-G-U-H" # default to assumed friendly ground unit headquarters

#                 PARAMETERS = {
#                     "uid": data.get('uid'),
#                     "lat": data.get('lat'),
#                     "lon": data.get('lon'),
#                     "alt": data.get('alt'),
#                     "time": data.get('time'),
#                     "type": data.get('type'),
#                     "remarks": data.get('remarks'),
#                 }
#                 is_gps_update = PARAMETERS["remarks"] == "GPS UPDATE"
#                 name = "takPlotGpsUpdate" if is_gps_update else "takPlot"
#                 if network_type == "Meshtastic":
#                     name += "LT"
#                     PARAMETERS = {
#                         "msg": [
#                             PARAMETERS["uid"][:17],
#                             PARAMETERS["lat"],
#                             PARAMETERS["lon"],
#                             PARAMETERS["alt"],
#                             PARAMETERS["time"],
#                             PARAMETERS["remarks"][:10] if PARAMETERS["remarks"] else None,
#                             PARAMETERS["type"]
#                         ]
#                     }
#                     # print(str(len(PARAMETERS.get("msg"))) + ":" + str(PARAMETERS.get("msg")))
#                 # print(PARAMETERS)
#                 msg = {
#                     fissure.comms.MessageFields.IDENTIFIER if network_type == "IP" else fissure.comms.MessageFields.SOURCE: identifier,
#                     fissure.comms.MessageFields.MESSAGE_NAME: name,
#                     fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
#                 }
#                 msg[fissure.comms.MessageFields.DESTINATION] = fissure.comms.Identifiers.HIPRFISR_LT if network_type == "Meshtastic" else None
#                 asyncio.run(hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg))

#             elif msg_type == 'exploit':
#                 PARAMETERS = {
#                     "node_uid": node_uid,
#                     "protocol": data.get('protocol'),
#                     "modulation": data.get('modulation'),
#                     "hardware": data.get('hardware'),
#                     "type": data.get('type'),
#                     "attack": data.get('attack'),
#                     "variables": data.get('variables'),
#                 }

#                 if network_type == "Meshtastic":
#                     PARAMETERS = {
#                         "msg": list(PARAMETERS.values())
#                     }

#                 msg = {
#                     fissure.comms.MessageFields.IDENTIFIER if network_type == "IP" else fissure.comms.MessageFields.SOURCE: identifier,
#                     fissure.comms.MessageFields.MESSAGE_NAME: "exploit" if network_type == "IP" else "exploitLT",
#                     fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
#                 }
#                 if network_type == "Meshtastic":
#                     msg[fissure.comms.MessageFields.DESTINATION] = fissure.comms.Identifiers.HIPRFISR_LT
#                 asyncio.run(hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg))

#             elif msg_type == 'snreport':
#                 PARAMETERS = {
#                     "node_uid": node_uid,
#                     "text": data.get('text')
#                 }
#                 msg = {
#                     fissure.comms.MessageFields.IDENTIFIER: identifier,
#                     fissure.comms.MessageFields.MESSAGE_NAME: "snreport",
#                     fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
#                 }
#                 asyncio.run(hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg))

#             # Check for quit signal from control pipe
#             if c2.poll():
#                 msg = c2.recv()
#                 if msg == 'QUIT':
#                     stop = True
#                     break

#     finally:
#         # Cleanup process
#         if self.proc:
#             try:
#                 if self.proc.poll() is None:
#                     os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
#                     self.proc.wait(timeout=3)
#             except Exception:
#                 pass

#             try:
#                 if self.proc.stdout:
#                     self.proc.stdout.close()
#                 if self.proc.stderr:
#                     self.proc.stderr.close()
#             except Exception:
#                 pass


# class alertSender(object):
#     def __init__(self, cmd: str, identifier: str, node_uid: any, hiprfisr_socket: fissure.comms.Server, gps_position: dict, logger: logging.Logger, network_type: str):
#         """Run Command and Capture stdout for Alerts

#         Run command, capture stdout and send by to HIPRFISR as alertReturn command

#         Parameters
#         ----------
#         cmd : str
#             System command to run
#         identifier : str
#             Sensor node identifier
#         node_uid : any
#             Sensor node ID
#         hiprfisr_socket : fissure.comms.Server
#             HIPRFISR socker
#         gps_position : dict
#             Dictionary with gps position
#         logger : logging.Logger
#             Sensor node logger
#         """
#         self.proc = None
#         self.logger = logger
#         self.cmd = cmd
#         self.identifier = identifier
#         self.node_uid = node_uid
#         self.hiprfisr_socket = hiprfisr_socket
#         self.gps_position = gps_position
#         self.network_type = network_type

#         (self.conn1, conn2) = Pipe()

#         # Launch _alert_sender in its own thread
#         self.thread = threading.Thread(
#             target=_alert_sender,
#             args=(self, cmd, conn2, identifier, node_uid, hiprfisr_socket, gps_position, logger, network_type),
#             daemon=True
#         )
#         self.thread.start()


#     def stop(self):
#         """
#         Gracefully stop the alert sender thread and its subprocess.
#         """
#         # Notify the alert sender thread to stop
#         try:
#             self.conn1.send('QUIT')
#         except Exception:
#             pass  # Pipe already closed or broken

#         # Terminate the subprocess if it is running
#         if self.proc:
#             if self.proc.poll() is None:
#                 try:
#                     os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
#                     self.proc.wait(timeout=3)
#                 except subprocess.TimeoutExpired:
#                     try:
#                         os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
#                         self.proc.wait(timeout=3)
#                     except Exception:
#                         pass
#                 except Exception:
#                     pass

#         # Wait for thread to finish before touching self.proc.* streams
#         thread_ref = getattr(self, "thread", None)
#         if thread_ref:
#             try:
#                 thread_ref.join(timeout=3)
#             except Exception:
#                 pass

#         # Now safe to close any remaining process pipes
#         if self.proc:
#             try:
#                 if self.proc.stdout and not self.proc.stdout.closed:
#                     self.proc.stdout.close()
#                 if self.proc.stderr and not self.proc.stderr.closed:
#                     self.proc.stderr.close()
#                 if self.proc.stdin and not self.proc.stdin.closed:
#                     self.proc.stdin.close()
#             except Exception:
#                 pass
#             self.proc = None

#         # Final cleanup of thread reference
#         self.thread = None
