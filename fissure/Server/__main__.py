from fissure.Server import Parser

import asyncio
import fissure.comms
import fissure.Server.HiprFisr
import fissure.utils


async def main():
    args = Parser.parse_args()
    print("[FISSURE][Server] start")

    fissure.utils.init_logging()

    if args.remote:
        server_address = fissure.comms.Address(
            protocol="tcp",
            address="0.0.0.0",
            hb_channel=args.heartbeat_port,
            msg_channel=args.message_port
        )
    else:
        server_address = fissure.comms.Address(protocol="ipc", address="fissure")

    hiprfisr = fissure.Server.HiprFisr.HiprFisr(
        server_address,
        dashboard_expected=not args.remote,
    )
    tasks = [asyncio.create_task(hiprfisr.begin())]

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        # Normal shutdown
        pass


def run():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        print("\n[FISSURE] Ctrl+C → FORCING SHUTDOWN")

        # Cancel EVERYTHING immediately
        for task in asyncio.all_tasks(loop):
            task.cancel()

        # Don't wait for tasks to finish properly—just stop the loop
        loop.stop()

    finally:
        loop.close()
        print("[FISSURE] exited.")


if __name__ == "__main__":
    import sys

    rc = 0
    try:
        run()
    except Exception:
        rc = 1

    sys.exit(rc)
