#!/usr/bin/env python3
import argparse
import json

import serial


def main():
    parser = argparse.ArgumentParser(
        description="Send one line to a FISSURE Serial Port Listening Post."
    )
    parser.add_argument(
        "--port",
        required=True,
        help="Paired/transmitting serial port, not the port opened by the Listening Post.",
    )
    parser.add_argument(
        "--baud",
        type=int,
        default=9600,
    )
    parser.add_argument(
        "--message",
        default="Serial Listening Post test",
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

    wire = (
        json.dumps(payload) + "\n"
    ).encode("utf-8")

    with serial.Serial(
        args.port,
        args.baud,
        timeout=1,
    ) as connection:
        connection.write(wire)
        connection.flush()

    print(
        wire.decode("utf-8").strip()
    )


if __name__ == "__main__":
    main()
