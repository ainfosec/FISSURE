#!/usr/bin/env python3
import argparse
import json
import socket


def build_payload(message, target_id):
    payload = {
        "alert_text": message,
    }
    if target_id:
        payload["target_id"] = target_id
    return json.dumps(payload)


def main():
    parser = argparse.ArgumentParser(
        description="Send one test message to a FISSURE TCP/UDP Listening Post."
    )
    parser.add_argument(
        "--protocol",
        choices=("tcp", "udp"),
        default="tcp",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=55555,
    )
    parser.add_argument(
        "--message",
        default="TCP/UDP Listening Post test",
    )
    parser.add_argument(
        "--target-id",
        default="",
    )
    args = parser.parse_args()

    payload = build_payload(
        args.message,
        args.target_id,
    ).encode("utf-8") + b"\n"

    if args.protocol == "tcp":
        with socket.create_connection(
            (args.host, args.port),
            timeout=5,
        ) as sock:
            sock.sendall(payload)
    else:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        ) as sock:
            sock.sendto(
                payload,
                (args.host, args.port),
            )

    print(payload.decode("utf-8").strip())


if __name__ == "__main__":
    main()
