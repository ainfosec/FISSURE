"""Privilege and prerequisite invariants for remote sensor-node deployment."""

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


INSTALLER_DIR = Path(__file__).resolve().parents[1] / "Installer"
sys.path.insert(0, str(INSTALLER_DIR))

from remote_sensor_node_privilege import (  # noqa: E402
    PrivilegeContext,
    PrivilegeError,
    prepare_remote_environment,
    run_root_command,
    run_root_script,
)


class FakeRemoteResult:
    def __init__(self, stdout="", stderr="", exit_status=0):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_status = exit_status


class FakeRemoteConnection:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    async def run(self, command, input=None, check=False):
        self.calls.append(
            {"command": command, "input": input, "check": check}
        )
        return self.results.pop(0)


class RemoteBootstrapTests(unittest.IsolatedAsyncioTestCase):
    async def test_uses_existing_apptainer_without_package_changes(self):
        connection = FakeRemoteConnection(
            [
                FakeRemoteResult(
                    "fissure|fissure|/usr/bin/apptainer|passwordless\n"
                )
            ]
        )

        environment = await prepare_remote_environment(
            connection, "fissure@sensor", install_apptainer=True
        )

        self.assertEqual(environment.apptainer, "/usr/bin/apptainer")
        self.assertEqual(environment.privilege.mode, "passwordless")
        self.assertEqual(len(connection.calls), 1)

    async def test_installs_missing_apptainer_as_root(self):
        connection = FakeRemoteConnection(
            [
                FakeRemoteResult("fissure|fissure||passwordless\n"),
                FakeRemoteResult(),
                FakeRemoteResult("/usr/bin/apptainer\n"),
            ]
        )

        environment = await prepare_remote_environment(
            connection, "fissure@sensor", install_apptainer=True
        )

        self.assertEqual(environment.apptainer, "/usr/bin/apptainer")
        install_call = connection.calls[1]
        self.assertIn("sudo -n --", install_call["command"])
        self.assertIn("ppa:apptainer/ppa", install_call["command"])
        self.assertIn("amd64|arm64", install_call["command"])
        self.assertIsNone(install_call["input"])

    async def test_missing_apptainer_can_fail_without_installing(self):
        connection = FakeRemoteConnection(
            [FakeRemoteResult("fissure|fissure||passwordless\n")]
        )

        with self.assertRaisesRegex(PrivilegeError, "not installed"):
            await prepare_remote_environment(
                connection, "fissure@sensor", install_apptainer=False
            )
        self.assertEqual(len(connection.calls), 1)

    async def test_install_failure_reports_remote_error(self):
        connection = FakeRemoteConnection(
            [
                FakeRemoteResult("fissure|fissure||passwordless\n"),
                FakeRemoteResult(
                    stderr="Automatic installation is unsupported",
                    exit_status=20,
                ),
            ]
        )

        with self.assertRaisesRegex(PrivilegeError, "unsupported"):
            await prepare_remote_environment(
                connection, "fissure@sensor", install_apptainer=True
            )
        self.assertEqual(len(connection.calls), 2)


class SudoPasswordTests(unittest.IsolatedAsyncioTestCase):
    @patch(
        "remote_sensor_node_privilege.getpass.getpass",
        return_value="sudo-secret",
    )
    async def test_prompts_and_validates_sudo_password(self, get_password):
        connection = FakeRemoteConnection(
            [
                FakeRemoteResult(
                    "fissure|fissure|/usr/bin/apptainer|password\n"
                ),
                FakeRemoteResult(),
            ]
        )

        environment = await prepare_remote_environment(
            connection, "fissure@sensor", install_apptainer=True
        )

        get_password.assert_called_once_with(
            "Sudo password for fissure@sensor: "
        )
        validation = connection.calls[1]
        self.assertIn("sudo -k -S -p ''", validation["command"])
        self.assertNotIn("sudo-secret", validation["command"])
        self.assertEqual(validation["input"], "sudo-secret\n")
        self.assertNotIn("sudo-secret", repr(environment.privilege))

    @patch(
        "remote_sensor_node_privilege.getpass.getpass",
        return_value="wrong-password",
    )
    async def test_rejects_invalid_sudo_password(self, _get_password):
        connection = FakeRemoteConnection(
            [
                FakeRemoteResult(
                    "fissure|fissure|/usr/bin/apptainer|password\n"
                ),
                FakeRemoteResult(stderr="Sorry, try again.", exit_status=1),
            ]
        )

        with self.assertRaisesRegex(PrivilegeError, "authentication failed"):
            await prepare_remote_environment(
                connection, "fissure@sensor", install_apptainer=True
            )

    @patch("remote_sensor_node_privilege.getpass.getpass", return_value="")
    async def test_rejects_empty_sudo_password(self, _get_password):
        connection = FakeRemoteConnection(
            [
                FakeRemoteResult(
                    "fissure|fissure|/usr/bin/apptainer|password\n"
                )
            ]
        )

        with self.assertRaisesRegex(PrivilegeError, "cannot be empty"):
            await prepare_remote_environment(
                connection, "fissure@sensor", install_apptainer=True
            )

    async def test_password_is_stdin_only_for_privileged_scripts(self):
        connection = FakeRemoteConnection([FakeRemoteResult()])
        privilege = PrivilegeContext("password", "sudo-secret")

        await run_root_script(
            connection,
            "echo installed",
            ["/opt/fissure"],
            privilege,
        )

        call = connection.calls[0]
        self.assertNotIn("sudo-secret", call["command"])
        self.assertIn("exec </dev/null", call["command"])
        self.assertEqual(call["input"], "sudo-secret\n")


class RootPrivilegeTests(unittest.IsolatedAsyncioTestCase):
    async def test_root_connection_does_not_invoke_sudo(self):
        connection = FakeRemoteConnection([FakeRemoteResult()])

        await run_root_command(
            connection,
            ["systemctl", "is-active", "fissure.service"],
            PrivilegeContext("root"),
        )

        call = connection.calls[0]
        self.assertIn("systemctl is-active fissure.service", call["command"])
        self.assertIn("exec </dev/null", call["command"])
        self.assertNotIn("sudo", call["command"])
        self.assertIsNone(call["input"])


if __name__ == "__main__":
    unittest.main()
