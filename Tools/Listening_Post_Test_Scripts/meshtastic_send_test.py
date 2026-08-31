#!/usr/bin/env python3
import argparse
import json
import time

from meshtastic.serial_interface import SerialInterface


def main():
    parser = argparse.ArgumentParser(
        description="Send one Meshtastic text payload to a FISSURE Meshtastic Listening Post."
    )
    parser.add_argument(
        "--port",
        required=True,
        help="Serial port for the transmitting Meshtastic radio.",
    )
    parser.add_argument(
        "--message",
        default="Meshtastic Listening Post test",
    )
    parser.add_argument(
        "--target-id",
        default="",
    )
    args = parser.parse_args()

    payload = {
        "alert_text": args.message,
    }
    if args.target_id:
        payload["target_id"] = args.target_id

    text = json.dumps(
        payload,
        separators=(",", ":"),
    )

    interface = SerialInterface(
        args.port
    )

    try:
        interface.sendText(text)
        print(text)

        # Give the serial interface time to hand the packet to the radio.
        time.sleep(1.0)
    finally:
        interface.close()


if __name__ == "__main__":
    main()
