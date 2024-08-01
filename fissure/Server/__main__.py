from fissure.Server import Parser

import asyncio
import fissure.comms
import fissure.Server.HiprFisr
import fissure.Server.ProtocolDiscovery
import fissure.Server.TargetSignalIdentification
import fissure.utils


def run():
    asyncio.run(main())


async def main():
    fissure.utils.init_logging()

    args = Parser.parse_args()

    print("[FISSURE][Server] start")

    if args.remote:
        server_address = fissure.comms.Address(
            protocol="tcp", address="0.0.0.0", hb_channel=args.heartbeat_port, msg_channel=args.message_port
        )
    else:
        server_address = fissure.comms.Address(protocol="ipc", address="fissure")

    # Create components
    hiprfisr = fissure.Server.HiprFisr.HiprFisr(server_address)
    pd = fissure.Server.ProtocolDiscovery.ProtocolDiscovery()
    tsi = fissure.Server.TargetSignalIdentification.TargetSignalIdentification()

    # Run Asynchronously
    server_tasks = asyncio.gather(
        hiprfisr.begin(),
        pd.begin(),
        tsi.begin(),
    )
    await server_tasks

    print("[FISSURE][Server] end")
    fissure.utils.zmq_cleanup()


if __name__ == "__main__":
    import sys

    rc = 0
    try:
        run()
    except Exception:
        rc = 1

    sys.exit(rc)
