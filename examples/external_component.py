"""Optional HIPRFISR client showing an external program's minimal wire protocol.

This example is NOT started by FISSURE. Run from the repository root:
    python3 examples/external_component.py

By default it uses hiprfisr.backend in YAML/fissure_config.yaml (local IPC).
To use TCP, configure the HIPRFISR backend ROUTER for TCP and supply its
address/ports with --host, --heartbeat-port, and --message-port.
"""

import argparse
import asyncio
import time
import uuid

import zmq

import fissure.comms
import fissure.utils

IDENTIFIER = "ExternalExample"


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", help="HIPRFISR backend host; omit for config-based IPC")
    parser.add_argument("--heartbeat-port", type=int, default=5061)
    parser.add_argument("--message-port", type=int, default=5062)
    return parser.parse_args()


async def main():
    args = parse_args()
    fissure.utils.init_logging()
    settings = fissure.utils.get_fissure_config()
    backend_cfg = settings["hiprfisr"]["backend"]

    if args.host:
        address = fissure.comms.Address(
            protocol="tcp",
            address=args.host,
            hb_channel=args.heartbeat_port,
            msg_channel=args.message_port,
        )
    else:
        address = fissure.comms.Address(address_config=backend_cfg)

    client = fissure.comms.Listener(
        sock_type=zmq.DEALER, name=f"{IDENTIFIER}::backend"
    )
    client.set_identity(f"{IDENTIFIER}-{uuid.uuid4()}")

    await client.connect(address)
    heartbeat_interval = float(settings.get("heartbeat_interval", 5))
    failure_multiple = float(settings.get("failure_multiple", 5))
    last_sent = 0.0
    last_hiprfisr = None
    last_connected_notice = 0.0
    ready = False
    try:
        print(f"{IDENTIFIER}: connected to {address}; Ctrl+C to quit")
        while True:
            now = time.time()
            if now - last_sent >= heartbeat_interval:
                await client.send_heartbeat({
                    fissure.comms.MessageFields.IDENTIFIER: IDENTIFIER,
                    fissure.comms.MessageFields.MESSAGE_NAME: fissure.comms.MessageFields.HEARTBEAT,
                    fissure.comms.MessageFields.TIME: now,
                })
                last_sent = now

            # STATUS Connected/OK is already supported by HIPRFISR's ROUTER.
            if not ready and now - last_connected_notice >= heartbeat_interval:
                await client.send_msg(fissure.comms.MessageTypes.STATUS, {
                    fissure.comms.MessageFields.IDENTIFIER: IDENTIFIER,
                    fissure.comms.MessageFields.MESSAGE_NAME: "Connected",
                })
                last_connected_notice = now

            hb = await client.recv_heartbeat()
            if hb is not None:
                last_hiprfisr = time.time()  # Use receipt time for remote clock skew
                if not ready:
                    print("HIPRFISR heartbeat received")

            response = await client.recv_msg()
            if response is not None:
                msg_name = response.get(fissure.comms.MessageFields.MESSAGE_NAME)
                if response.get(fissure.comms.MessageFields.TYPE) == fissure.comms.MessageTypes.STATUS and msg_name == "OK":
                    if not ready:
                        print("HIPRFISR acknowledged connection")
                    ready = True
                else:
                    print("HIPRFISR message:", response)

            if last_hiprfisr is not None and now - last_hiprfisr > heartbeat_interval * failure_multiple:
                if ready:
                    print("HIPRFISR heartbeat timed out; awaiting reconnection")
                ready = False
                last_hiprfisr = None

            await asyncio.sleep(0.1)
    finally:
        client.close_sockets()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
