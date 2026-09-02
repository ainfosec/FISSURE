#!/bin/bash
set -euo pipefail

has_setuid_support() {
    command -v apptainer >/dev/null 2>&1 &&
        apptainer buildcfg 2>/dev/null |
        grep -q '^APPTAINER_SUID_INSTALL=1$'
}

if has_setuid_support; then
    echo "[✓] Existing Apptainer installation has setuid support."
    exit 0
fi

if command -v apptainer >/dev/null 2>&1; then
    echo "[!] Existing Apptainer installation does not have setuid support."
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
if ! grep -Rqs "ppa.launchpadcontent.net/apptainer/ppa" \
    /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
    add-apt-repository -y ppa:apptainer/ppa
fi
apt-get update
env DEBIAN_FRONTEND=noninteractive apt-get install -y apptainer-suid

if ! has_setuid_support; then
    echo "Apptainer installation did not provide setuid support." >&2
    exit 1
fi

echo "[✓] $(apptainer version)"
