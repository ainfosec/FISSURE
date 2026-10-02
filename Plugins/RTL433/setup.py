#!/usr/bin/env python3
"""Safe, non-mutating FISSURE setup hook (check/install/cleanup)."""
import sys
import shutil


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("check", "install", "cleanup"):
        print("Usage: setup.py {check|install|cleanup}")
        return 2
    if sys.argv[1] == "check":
        executable = shutil.which("rtl_433")
        if executable:
            print("rtl_433 available: %s" % executable)
            return 0
        print("rtl_433 is not installed or is not in the Sensor Node PATH.")
        return 1
    print("RTL433 does not install or remove shared dependencies. "
          "Install rtl_433 on the executing Sensor Node before running the Action.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
