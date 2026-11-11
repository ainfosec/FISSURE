#!/usr/bin/env python3
"""AIS plugin setup hook: deliberately does not alter host packages or hardware."""
import sys


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"check", "install", "cleanup"}:
        print("Usage: setup.py {check|install|cleanup}")
        return 2
    if sys.argv[1] == "check":
        try:
            import pyais
            print("AIS: pyais available:", getattr(pyais, "__version__", "version unknown"))
        except ImportError:
            print("AIS: pyais missing on this Sensor Node. Enable the FISSURE pyais installer item.")
            return 1
    else:
        print("AIS: no automatic installation or cleanup. Configure pyais using the FISSURE installer.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
