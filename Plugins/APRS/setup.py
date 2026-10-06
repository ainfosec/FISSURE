#!/usr/bin/env python3
"""Safe, no-op FISSURE plugin lifecycle hook (dependencies are manual)."""

import sys


PLUGIN_NAME = "APRS"


def check() -> int:
    print("APRS: no automated external setup; see README.md for RTL/audio prerequisites")
    return 0


def install() -> int:
    print("APRS: install rtl-sdr and multimon-ng manually for live mode")
    return 0


def cleanup() -> int:
    print("APRS: no plugin-owned external resources to remove")
    return 0


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("check", "install", "cleanup"):
        print("Usage: setup.py {check|install|cleanup}")
        return 2
    return globals()[sys.argv[1]]()


if __name__ == "__main__":
    raise SystemExit(main())
