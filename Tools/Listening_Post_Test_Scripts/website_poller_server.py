#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import json
import threading


class MessageStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.messages = []

    def add(self, payload):
        with self.lock:
            self.messages.append(
                json.dumps(
                    payload,
                    separators=(",", ":"),
                )
            )

    def snapshot(self):
        with self.lock:
            return list(self.messages)


STORE = MessageStore()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/", "/messages"):
            self.send_error(404)
            return

        body = "\n".join(
            STORE.snapshot()
        )
        if body:
            body += "\n"

        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/plain; charset=utf-8",
        )
        self.send_header(
            "Content-Length",
            str(len(encoded)),
        )
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self):
        if self.path not in ("/", "/messages"):
            self.send_error(404)
            return

        length = int(
            self.headers.get(
                "Content-Length",
                "0",
            )
        )
        raw = self.rfile.read(length)

        try:
            payload = json.loads(
                raw.decode("utf-8")
            )
        except Exception:
            self.send_error(
                400,
                "POST body must be valid JSON.",
            )
            return

        if not isinstance(payload, dict):
            self.send_error(
                400,
                "POST body must be a JSON object.",
            )
            return

        STORE.add(payload)
        self.send_response(204)
        self.end_headers()
        print(
            "Added:",
            json.dumps(payload),
        )

    def log_message(self, format, *args):
        print(
            "%s - %s"
            % (
                self.address_string(),
                format % args,
            )
        )


def main():
    parser = argparse.ArgumentParser(
        description="Local line-oriented HTTP source for FISSURE Website Poller tests."
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
    )
    args = parser.parse_args()

    server = ThreadingHTTPServer(
        (args.host, args.port),
        Handler,
    )

    print(
        f"Serving Listening Post test messages at "
        f"http://{args.host}:{args.port}"
    )
    print(
        "POST JSON to / or /messages; GET returns "
        "one JSON object per line."
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
