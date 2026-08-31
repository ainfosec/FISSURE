#!/usr/bin/env python3
import argparse
import json
import time

import zmq


def main():
    parser = argparse.ArgumentParser(
        description="Publish one test message for a FISSURE ZMQ SUB Listening Post."
    )
    parser.add_argument(
        "--bind",
        default="tcp://*:55555",
    )
    parser.add_argument(
        "--topic",
        default="alerts",
    )
    parser.add_argument(
        "--message",
        default="ZMQ Listening Post test",
    )
    parser.add_argument(
        "--target-id",
        default="",
    )
    parser.add_argument(
        "--wait",
        type=float,
        default=1.0,
        help="Seconds to wait for SUB connection before publishing.",
    )
    args = parser.parse_args()

    payload = {
        "alert_text": args.message,
    }
    if args.target_id:
        payload["target_id"] = args.target_id

    context = zmq.Context()
    socket = context.socket(zmq.PUB)
    socket.bind(args.bind)

    try:
        print(f"Publishing from {args.bind}")
        print(f"Waiting {args.wait:.1f}s for subscriber connection...")
        time.sleep(args.wait)

        wire_message = (
            f"{args.topic} {json.dumps(payload)}"
            if args.topic
            else json.dumps(payload)
        )
        socket.send_string(wire_message)
        print(wire_message)

        # Give ZeroMQ a moment to flush before closing this one-shot publisher.
        time.sleep(0.25)
    finally:
        socket.close(linger=1000)
        context.term()


if __name__ == "__main__":
    main()
