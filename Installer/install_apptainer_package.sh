#!/bin/bash
set -euo pipefail

if command -v apptainer >/dev/null 2>&1; then
    echo "[*] Apptainer is already installed."
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Run the Apptainer package installer as root." >&2
    exit 1
fi

. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
    *" ubuntu "*) ;;
    *)
        echo "Automatic Apptainer installation supports Ubuntu-derived systems only." >&2
        exit 1
        ;;
esac

architecture=$(dpkg --print-architecture)
case "$architecture" in
    amd64|arm64) ;;
    *)
        echo "Automatic Apptainer installation does not support $architecture." >&2
        exit 1
        ;;
esac

echo "[*] Installing Apptainer from the official Ubuntu PPA..."
# GitHub's Debian package is AMD64-only; the PPA also supports ARM64 nodes.
apt-get update
env DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common
add-apt-repository -y ppa:apptainer/ppa
apt-get update
env DEBIAN_FRONTEND=noninteractive apt-get install -y apptainer
apptainer version >/dev/null
echo "[✓] Apptainer installed."
