#!/usr/bin/env python3
import sys


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "check"

    if action not in {"check", "install", "cleanup"}:
        print(
            f"Unsupported setup action: {action}",
            file=sys.stderr,
        )
        return 2

    print(
        "RadarAnalysis requires no external host setup; it uses FISSURE's "
        "Python environment."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
