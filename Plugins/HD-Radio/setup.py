#!/usr/bin/env python3
"""Inert FISSURE plugin setup hook. Never change host SDR/decoder installs."""
import shutil
import sys


PLUGIN_NAME = "HD-Radio"


def check():
    full = shutil.which("nrsc5")
    quick = shutil.which("rtl_power")
    print("%s: nrsc5: %s" % (PLUGIN_NAME, full or "MISSING (Full and Quick unavailable)"))
    print("%s: rtl_power: %s" % (PLUGIN_NAME, quick or "MISSING (Quick unavailable; Full still works)"))
    return 0 if full else 1


def install():
    print("No automatic packages installed. See README.md for nrsc5 and rtl_power prerequisites.")
    return 0


def cleanup():
    print("No plugin-owned external resources to remove. SDR drivers and tools are shared.")
    return 0


def main():
    if len(sys.argv) != 2:
        print("Usage: setup.py {check|install|cleanup}")
        return 2
    action = sys.argv[1].strip().lower()
    commands = {"check": check, "install": install, "cleanup": cleanup}
    if action not in commands:
        print("Unknown setup action: %s" % action)
        return 2
    return commands[action]()


if __name__ == "__main__":
    raise SystemExit(main())
