"""Uninstall invariants for remote Sensor Node deployments."""

from pathlib import Path
import sys
import unittest


INSTALLER_DIR = Path(__file__).resolve().parents[1] / "Installer"
sys.path.insert(0, str(INSTALLER_DIR))

from remote_sensor_node_uninstall import uninstall_remote  # noqa: E402


class FakeResult:
    def __init__(self, stdout="", stderr="", exit_status=0):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_status = exit_status


class FakeConnection:
    def __init__(self):
        self.results = [FakeResult("passwordless\n"), FakeResult()]
        self.calls = []

    async def run(self, command, input=None, check=False):
        self.calls.append(
            {"command": command, "input": input, "check": check}
        )
        return self.results.pop(0)


class RemoteUninstallTests(unittest.IsolatedAsyncioTestCase):
    async def test_removes_only_service_and_deployment_root(self):
        connection = FakeConnection()

        await uninstall_remote(
            connection,
            "fissure@sensor.example",
            "/opt/fissure-sensor-node",
            "fissure-sensor-node",
        )

        self.assertEqual(len(connection.calls), 2)
        preflight, uninstall = connection.calls
        self.assertNotIn("apptainer", preflight["command"])
        self.assertIn("sudo -n --", uninstall["command"])
        self.assertIn(
            'rm -rf --one-file-system -- "$root"',
            uninstall["command"],
        )
        self.assertIn("/opt/fissure-sensor-node", uninstall["command"])
        self.assertIn("fissure-sensor-node", uninstall["command"])
        self.assertNotIn("apt-get", uninstall["command"])
        self.assertIsNone(uninstall["input"])


if __name__ == "__main__":
    unittest.main()
