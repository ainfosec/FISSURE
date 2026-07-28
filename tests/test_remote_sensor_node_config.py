"""Tests for staging the installed Sensor Node configuration."""

from pathlib import Path
import sys
import tempfile
import unittest

import yaml


INSTALLER_DIR = Path(__file__).resolve().parents[1] / "Installer"
sys.path.insert(0, str(INSTALLER_DIR))

from remote_sensor_node_config import (  # noqa: E402
    ConfigPreparationError,
    prepare_remote_config,
)


class FakeConnection:
    def __init__(self, local_address):
        self.local_address = local_address

    def get_extra_info(self, name):
        return (self.local_address, 54321) if name == "sockname" else None


class RemoteSensorNodeConfigTests(unittest.TestCase):
    def test_replaces_loopback_in_staged_copy(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            source, staged = root / "source.yaml", root / "staged.yaml"
            source.write_text(
                yaml.safe_dump(
                    {
                        "Sensor Node": {
                            "network_type": "IP",
                            "hiprfisr_ip_address": "127.0.0.1",
                        }
                    }
                )
            )

            result = prepare_remote_config(
                source,
                staged,
                FakeConnection("192.168.187.10"),
            )

            config = yaml.safe_load(result.read_text())
            self.assertEqual(
                config["Sensor Node"]["hiprfisr_ip_address"],
                "192.168.187.10",
            )
            self.assertIn("127.0.0.1", source.read_text())

    def test_preserves_explicit_remote_address(self):
        with tempfile.TemporaryDirectory() as temp_name:
            source = Path(temp_name) / "source.yaml"
            source.write_text(
                yaml.safe_dump(
                    {
                        "Sensor Node": {
                            "network_type": "IP",
                            "hiprfisr_ip_address": "10.20.30.40",
                        }
                    }
                )
            )

            result = prepare_remote_config(
                source,
                Path(temp_name) / "staged.yaml",
                FakeConnection("192.168.187.10"),
            )

            self.assertEqual(result, source)

    def test_rejects_unusable_connection_address(self):
        with tempfile.TemporaryDirectory() as temp_name:
            source = Path(temp_name) / "source.yaml"
            source.write_text(
                yaml.safe_dump(
                    {
                        "Sensor Node": {
                            "network_type": "IP",
                            "hiprfisr_ip_address": "localhost",
                        }
                    }
                )
            )

            with self.assertRaisesRegex(ConfigPreparationError, "reachable IPv4"):
                prepare_remote_config(
                    source,
                    Path(temp_name) / "staged.yaml",
                    FakeConnection("127.0.0.1"),
                )


if __name__ == "__main__":
    unittest.main()
