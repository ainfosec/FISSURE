#!/usr/bin/env python3
"""Privileged Scapy packet sender used by the Base scapy_transmit operation."""

import argparse
import os
import sys
import time


PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

import importlib.util

SCAPY_COMPAT_PATH = os.path.join(
    FISSURE_REPO_ROOT,
    "fissure",
    "utils",
    "scapy_compat.py",
)

spec = importlib.util.spec_from_file_location(
    "fissure_scapy_compat",
    SCAPY_COMPAT_PATH,
)

if spec is None or spec.loader is None:
    raise ImportError(f"Could not load Scapy compatibility module: {SCAPY_COMPAT_PATH}")

scapy_compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scapy_compat)

try:
    from scapy.all import send, sendp
    SCAPY_SEND_IMPORT_ERROR = ""
except Exception as exc:
    send = None
    sendp = None
    SCAPY_SEND_IMPORT_ERROR = str(exc)


SCAPY_METHOD_SENDP = "sendp (Layer 2)"
SCAPY_METHOD_SEND = "send (Layer 3)"


def _emit(kind: str, value="") -> None:
    print(f"{kind}\t{value}", flush=True)


def _stop_requested(stop_file: str) -> bool:
    return bool(stop_file and os.path.exists(stop_file))


def _sleep_interval(interval: float, stop_file: str) -> bool:
    if interval <= 0:
        return _stop_requested(stop_file)

    end_time = time.monotonic() + interval

    while time.monotonic() < end_time:
        if _stop_requested(stop_file):
            return True

        time.sleep(min(0.05, max(0.0, end_time - time.monotonic())))

    return _stop_requested(stop_file)


def _build_packet(packet_hex: str, root_layer: str):
    if not scapy_compat.is_available():
        detail = str(scapy_compat.import_error() or SCAPY_SEND_IMPORT_ERROR or "").strip()
        raise RuntimeError("Scapy is unavailable" + (f": {detail}" if detail else "."))

    if send is None or sendp is None:
        raise RuntimeError(
            "Scapy send/sendp could not be imported"
            + (f": {SCAPY_SEND_IMPORT_ERROR}" if SCAPY_SEND_IMPORT_ERROR else ".")
        )

    layer_class = scapy_compat.get_layer_class(root_layer)
    if layer_class is None:
        raise ValueError(f"Scapy layer '{root_layer}' is unavailable.")

    packet_hex = str(packet_hex or "").strip()
    if packet_hex.lower().startswith("0x"):
        packet_hex = packet_hex[2:]

    try:
        packet_bytes = bytes.fromhex(packet_hex)
    except ValueError as exc:
        raise ValueError("Packet Hex is not valid hexadecimal.") from exc

    if not packet_bytes:
        raise ValueError("Packet is empty.")

    try:
        return layer_class(packet_bytes)
    except Exception as exc:
        raise ValueError(f"Could not rebuild packet as {root_layer}: {exc}") from exc


def _send_once(packet, interface: str, method: str) -> None:
    if method == SCAPY_METHOD_SENDP:
        sendp(packet, iface=interface, count=1, verbose=False)
        return

    if method != SCAPY_METHOD_SEND:
        raise ValueError(f"Unsupported Scapy method: {method}")

    try:
        send(packet, iface=interface, count=1, verbose=False)
    except TypeError:
        # Older Scapy releases may not accept iface on send().
        send(packet, count=1, verbose=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet-hex", required=True)
    parser.add_argument("--root-layer", required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--method", required=True)
    parser.add_argument("--interval", type=float, default=0.1)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--stop-file", default="")
    args = parser.parse_args()

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        _emit("ERROR", "Scapy sender must be run with elevated privileges.")
        return 1

    if not args.interface:
        _emit("ERROR", "No interface selected.")
        return 1

    if args.interval < 0:
        _emit("ERROR", "Interval cannot be negative.")
        return 1

    if not args.loop and args.count < 1:
        _emit("ERROR", "Packet count must be at least 1.")
        return 1

    try:
        packet = _build_packet(args.packet_hex, args.root_layer)
        packets_sent = 0
        _emit("READY", args.method)

        while args.loop or packets_sent < args.count:
            if _stop_requested(args.stop_file):
                _emit("STOPPED", packets_sent)
                return 0

            _send_once(packet, args.interface, args.method)
            packets_sent += 1
            _emit("SENT", packets_sent)

            if not args.loop and packets_sent >= args.count:
                break

            if _sleep_interval(args.interval, args.stop_file):
                _emit("STOPPED", packets_sent)
                return 0

        _emit("DONE", packets_sent)
        return 0

    except Exception as exc:
        _emit("ERROR", str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())