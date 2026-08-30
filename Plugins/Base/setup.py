#!/usr/bin/env python3
"""FISSURE plugin setup hook template.

FISSURE may call this file with one of three actions:

    python3 setup.py check
    python3 setup.py install
    python3 setup.py cleanup

Exit-code contract:
    check:   0 = Ready, 1 = Setup Required, 2+ = Setup Failed
    install: 0 = Success, non-zero = Failure
    cleanup: 0 = Success, non-zero = Failure

This plugin currently requires no external setup. The functions below are
intentional no-ops so the file can serve as a starting point when the plugin
later needs packages, OOT modules, helper binaries, udev rules, configuration,
or other node-side resources.

Keep setup plugin-owned and idempotent. Do not remove shared dependencies from
cleanup. If cleanup becomes necessary, also opt in with ``cleanup: true`` in
plugin.yaml.
"""

import sys


PLUGIN_NAME = 'Base'


def check():
    """Return whether this plugin's external node-side setup is ready."""
    # Add dependency/configuration checks here when this plugin needs them.
    print(f"{PLUGIN_NAME} requires no external setup.")
    return 0


def install():
    """Install or repair plugin-owned external requirements."""
    # Add idempotent setup steps here when this plugin needs them.
    print(f"{PLUGIN_NAME} has no external setup to install.")
    return 0


def cleanup():
    """Remove only resources owned exclusively by this plugin."""
    # This is not called during removal unless plugin.yaml opts in with:
    #
    #     cleanup: true
    #
    # Never remove shared dependencies such as GNU Radio, Python packages, or
    # system tools merely because this plugin uses them.
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
