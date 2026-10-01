#!/usr/bin/env python3
"""No-op FISSURE setup hook for the ADS-B plugin.

The plugin reuses dump1090 and RTL-SDR support already installed by FISSURE.
It owns no external packages or system resources.
"""

import sys


PLUGIN_NAME = "ADS-B"


def check():
    print(f"{PLUGIN_NAME} requires no plugin-owned external setup.")
    return 0


def install():
    print(f"{PLUGIN_NAME} has no plugin-owned setup to install.")
    return 0


def cleanup():
    print(f"{PLUGIN_NAME} has no plugin-owned setup resources to clean up.")
    return 0


def main():
    if len(sys.argv) != 2:
        print("Usage: setup.py {check|install|cleanup}")
        return 2

    action = sys.argv[1].strip().lower()
    if action == "check":
        return check()
    if action == "install":
        return install()
    if action == "cleanup":
        return cleanup()

    print(f"Unknown action: {action}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
