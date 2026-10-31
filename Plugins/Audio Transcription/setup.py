#!/usr/bin/env python3
"""Inert FISSURE plugin lifecycle hooks: never install or remove host tools."""
import sys


PLUGIN_NAME = "Audio Transcription"


def check():
    print("Audio Transcription installs nothing. Check local whisper.cpp and FFmpeg per README.md.")
    return 0


def install():
    print("No automatic installation. See README.md for manual prerequisites.")
    return 0


def cleanup():
    print("No cleanup: external FFmpeg, whisper.cpp and models are user-managed.")
    return 0


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("check", "install", "cleanup"):
        print("Usage: setup.py {check|install|cleanup}")
        return 2
    return globals()[sys.argv[1]]()


if __name__ == "__main__":
    raise SystemExit(main())
