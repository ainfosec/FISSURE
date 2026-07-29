#!/usr/bin/env python3
"""Validate a FISSURE remote sensor-node image and its runtime inputs."""

import argparse
import importlib
import os
from pathlib import Path
import shutil
import sys

import yaml
import zmq.auth


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = PROJECT_ROOT / "YAML" / "Sensor_Node_Config" / "default.yaml"
DEFAULT_CERTIFICATES = PROJECT_ROOT / "certificates"
XVFB_ACTIVE_ENV = "FISSURE_XVFB_ACTIVE"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--certificates", type=Path, default=DEFAULT_CERTIFICATES)
    parser.add_argument("--skip-certificates", action="store_true")
    parser.add_argument("--skip-runtime-import", action="store_true")
    parser.add_argument("--allow-placeholder-config", action="store_true")
    return parser.parse_args()


def ensure_apptainer_display():
    in_apptainer = os.getenv("APPTAINER_CONTAINER") or os.getenv("APPTAINER_NAME")
    if not in_apptainer or os.getenv(XVFB_ACTIVE_ENV) == "1":
        return

    xvfb_run = shutil.which("xvfb-run")
    if not xvfb_run:
        raise RuntimeError("xvfb-run is required for headless Apptainer validation")

    # Apptainer can inherit an unusable host DISPLAY. Always create an isolated
    # virtual display so Dashboard imports cannot depend on host X credentials.
    environment = os.environ.copy()
    environment[XVFB_ACTIVE_ENV] = "1"
    os.execve(
        xvfb_run,
        [xvfb_run, "-a", sys.executable, *sys.argv],
        environment,
    )


def validate_config(config_path, allow_placeholder_config=False):
    with config_path.open(encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file)

    if not isinstance(config, dict) or not isinstance(config.get("Sensor Node"), dict):
        raise ValueError("config must contain a 'Sensor Node' mapping")

    node = config["Sensor Node"]
    network_type = str(node.get("network_type", "")).strip()
    if network_type not in {"IP", "Meshtastic"}:
        raise ValueError("Sensor Node.network_type must be IP or Meshtastic")

    nickname = str(node.get("nickname", "")).strip()
    if not nickname or nickname == "Local Sensor Node":
        raise ValueError("remote sensor-node nickname must be non-empty and not 'Local Sensor Node'")

    if network_type == "IP":
        hiprfisr_address = str(node.get("hiprfisr_ip_address", "")).strip()
        if not hiprfisr_address:
            raise ValueError("Sensor Node.hiprfisr_ip_address must not be empty")
        if (
            not allow_placeholder_config
            and hiprfisr_address in {"ipc", "127.0.0.1", "localhost"}
        ):
            raise ValueError(
                "an IP remote node needs a non-loopback Sensor Node.hiprfisr_ip_address"
            )

        for field in ("hb_port", "msg_port"):
            port = int(node.get(field, 0))
            if not 1 <= port <= 65535:
                raise ValueError(f"Sensor Node.{field} must be a valid TCP port")
    else:
        serial_port = str(node.get("meshtastic_serial_port", "")).strip()
        if not serial_port.startswith("/dev/"):
            raise ValueError("Meshtastic nodes need an absolute /dev serial port")

    return network_type


def validate_certificates(certificates_path):
    required = (
        certificates_path / "clients" / "client_0.key_secret",
        certificates_path / "server" / "server.key",
    )
    for certificate in required:
        if not certificate.is_file():
            raise FileNotFoundError(f"missing required certificate: {certificate}")
        zmq.auth.load_certificate(str(certificate))

    private_mode = required[0].stat().st_mode & 0o777
    if private_mode & 0o077:
        raise PermissionError(
            f"{required[0]} must not be accessible by group or other users "
            f"(current mode: {private_mode:o})"
        )


def main():
    args = parse_args()
    network_type = validate_config(args.config, args.allow_placeholder_config)

    if network_type == "IP" and not args.skip_certificates:
        validate_certificates(args.certificates)

    if not args.skip_runtime_import:
        sys.path.insert(0, str(PROJECT_ROOT))
        importlib.import_module("fissure.Sensor_Node.SensorNode")

    certificate_result = (
        "skipped"
        if args.skip_certificates or network_type != "IP"
        else "valid"
    )
    print(
        "FISSURE remote sensor-node image check passed "
        f"(network={network_type}, certificates={certificate_result})"
    )


if __name__ == "__main__":
    try:
        ensure_apptainer_display()
        main()
    except Exception as exc:
        print(f"FISSURE remote sensor-node image check failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
