#!/usr/bin/env python3
import argparse
import json

import paho.mqtt.publish as publish


def main():
    parser = argparse.ArgumentParser(
        description="Publish one test message to a FISSURE MQTT Listening Post."
    )
    parser.add_argument(
        "--host",
        default="localhost",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=1883,
    )
    parser.add_argument(
        "--topic",
        default="fissure/alerts",
    )
    parser.add_argument(
        "--username",
        default="",
    )
    parser.add_argument(
        "--password",
        default="",
    )
    parser.add_argument(
        "--message",
        default="MQTT Listening Post test",
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

    auth = None
    if args.username:
        auth = {
            "username": args.username,
            "password": args.password or None,
        }

    message = json.dumps(payload)
    publish.single(
        args.topic,
        payload=message,
        hostname=args.host,
        port=args.port,
        auth=auth,
    )

    print(
        f"{args.host}:{args.port} {args.topic} {message}"
    )


if __name__ == "__main__":
    main()
