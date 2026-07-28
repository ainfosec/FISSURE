"""Invariant tests for the AsyncSSH sensor-node deployment workflow."""

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


INSTALLER_DIR = Path(__file__).resolve().parents[1] / "Installer"
sys.path.insert(0, str(INSTALLER_DIR))

from deploy_remote_sensor_node import (  # noqa: E402
    DeployOptions,
    DeploymentError,
    HostSpec,
    build_service_unit,
    connect,
    copy_build_context,
    heartbeat_is_ready,
    parse_options,
    prompt_for_ssh_password,
    upload_payload,
    validate_options,
)


def make_options(**overrides) -> DeployOptions:
    values = {
        "target": HostSpec("sensor.example", "fissure"),
        "identity_file": None,
        "config_file": Path("/missing/config.yaml"),
        "certificates_dir": Path("/missing/certificates"),
        "image_file": None,
        "output_image": Path("/tmp/fissure-test.sif"),
        "source_dir": Path("/missing/source"),
        "remote_dir": "/opt/fissure-sensor-node",
        "service_name": "fissure-sensor-node",
        "health_timeout": 75,
        "overlay_size_mb": 4096,
        "startup_only": False,
        "health_only": True,
        "build_with_sudo": False,
        "install_apptainer": True,
        "uninstall": False,
    }
    values.update(overrides)
    return DeployOptions(**values)


class FakeAsyncSSH:
    Error = RuntimeError

    def __init__(self):
        self.calls = []

    async def connect(self, hostname, **kwargs):
        self.calls.append((hostname, kwargs))
        return object()


class HostSpecTests(unittest.TestCase):
    def test_parses_user_and_host(self):
        self.assertEqual(
            HostSpec.parse("fissure@sensor.example"),
            HostSpec("sensor.example", "fissure"),
        )
        self.assertEqual(HostSpec.parse("[::1]"), HostSpec("::1", "root"))

    def test_rejects_empty_or_option_like_host(self):
        for target in ("", "user@", "--proxy"):
            with self.subTest(target=target), self.assertRaises(DeploymentError):
                HostSpec.parse(target)
class DocoptCliTests(unittest.TestCase):
    def test_defaults_are_mapped_to_deployment_options(self):
        options = parse_options(["--target=fissure@sensor.example", "--health-only"])
        self.assertEqual(options.target, HostSpec("sensor.example", "fissure"))
        self.assertEqual(options.remote_dir, "/opt/fissure-sensor-node")
        self.assertEqual(options.overlay_size_mb, 4096)
        self.assertEqual(options.health_timeout, 75)
        self.assertTrue(options.install_apptainer)
        self.assertTrue(options.health_only)

    def test_typed_values_and_service_suffix_are_normalized(self):
        options = parse_options(
            [
                "--target=node.example",
                "--overlay-size=1024",
                "--service-name=fissure-node.service",
                "--startup-only",
                "--health-only",
            ]
        )
        self.assertEqual(options.overlay_size_mb, 1024)
        self.assertEqual(options.service_name, "fissure-node")
        self.assertTrue(options.startup_only)

    def test_short_identity_option_expands_the_key_path(self):
        options = parse_options(
            ["--target=root@sensor.example", "-i", "~/.ssh/fissure_node"]
        )
        self.assertEqual(
            options.identity_file,
            Path("~/.ssh/fissure_node").expanduser(),
        )

    def test_ip_only_defaults_to_root_and_installed_inputs(self):
        options = parse_options(
            [
                "192.0.2.20",
                "--source=/opt/FISSURE",
                "--health-only",
            ]
        )

        self.assertEqual(options.target, HostSpec("192.0.2.20", "root"))
        self.assertEqual(
            options.config_file,
            Path("/opt/FISSURE/YAML/Sensor_Node_Config/default.yaml"),
        )
        self.assertEqual(
            options.certificates_dir,
            Path("/opt/FISSURE/certificates"),
        )

    def test_legacy_target_option_and_explicit_config_remain_supported(self):
        options = parse_options(
            [
                "--target=192.0.2.20",
                "--config=/tmp/sensor-node.yaml",
                "--health-only",
            ]
        )

        self.assertEqual(options.target, HostSpec("192.0.2.20", "root"))
        self.assertEqual(options.config_file, Path("/tmp/sensor-node.yaml"))

    def test_apptainer_auto_install_can_be_disabled(self):
        options = parse_options(
            [
                "192.0.2.20",
                "--no-install-apptainer",
                "--health-only",
            ]
        )
        self.assertFalse(options.install_apptainer)

    def test_uninstall_is_parsed_without_local_inputs(self):
        options = parse_options(
            ["192.0.2.20", "--source=/missing/FISSURE", "--uninstall"]
        )

        self.assertTrue(options.uninstall)
        validate_options(options)


class ValidationTests(unittest.TestCase):
    def test_rejects_broad_remote_roots(self):
        for options in (
            make_options(remote_dir="/"),
            make_options(remote_dir="/opt"),
            make_options(remote_dir="/opt/../etc"),
        ):
            with self.subTest(options=options), self.assertRaises(DeploymentError):
                validate_options(options)

    def test_existing_image_does_not_require_source_tree(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            config = root / "node.yaml"
            image = root / "node.sif"
            certificates = root / "certificates"
            (certificates / "clients").mkdir(parents=True)
            (certificates / "server").mkdir()
            for path in (
                config,
                image,
                certificates / "clients/client_0.key_secret",
                certificates / "server/server.key",
            ):
                path.touch()
            options = make_options(
                config_file=config,
                certificates_dir=certificates,
                image_file=image,
                health_only=False,
            )
            validate_options(options)

    def test_certificate_inputs_are_mandatory(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            config, image = root / "node.yaml", root / "node.sif"
            config.touch()
            image.touch()
            options = make_options(
                config_file=config,
                certificates_dir=root / "certificates",
                image_file=image,
                health_only=False,
            )
            with self.assertRaisesRegex(DeploymentError, "client_0.key_secret"):
                validate_options(options)

    def test_identity_must_be_a_file(self):
        options = make_options(identity_file=Path("/missing/ssh-key"))
        with self.assertRaisesRegex(DeploymentError, "SSH identity"):
            validate_options(options)

    def test_uninstall_and_health_only_are_mutually_exclusive(self):
        options = make_options(uninstall=True, health_only=True)
        with self.assertRaisesRegex(DeploymentError, "cannot be combined"):
            validate_options(options)


class ConnectionOptionTests(unittest.IsolatedAsyncioTestCase):
    async def test_identity_is_passed_to_asyncssh(self):
        asyncssh = FakeAsyncSSH()
        identity = Path("/keys/fissure-node")
        await connect(
            asyncssh,
            make_options(
                target=HostSpec("sensor.example", "root"),
                identity_file=identity,
            ),
            password=None,
        )

        self.assertEqual(
            asyncssh.calls,
            [
                (
                    "sensor.example",
                    {
                        "keepalive_interval": 30,
                        "username": "root",
                        "client_keys": [str(identity)],
                    },
                )
            ],
        )

    async def test_password_disables_implicit_key_authentication(self):
        asyncssh = FakeAsyncSSH()
        await connect(asyncssh, make_options(), password="test-password")

        _, kwargs = asyncssh.calls[0]
        self.assertIsNone(kwargs["client_keys"])
        self.assertEqual(kwargs["password"], "test-password")

    async def test_missing_authentication_is_rejected_before_connecting(self):
        asyncssh = FakeAsyncSSH()
        with self.assertRaisesRegex(DeploymentError, "password is required"):
            await connect(asyncssh, make_options(), password=None)
        self.assertEqual(asyncssh.calls, [])


class PasswordPromptTests(unittest.TestCase):
    @patch("deploy_remote_sensor_node.getpass.getpass")
    def test_prompts_for_root_password_without_identity(self, get_password):
        get_password.return_value = "test-password"

        password = prompt_for_ssh_password(
            make_options(target=HostSpec("sensor.example", "root"))
        )

        self.assertEqual(password, "test-password")
        get_password.assert_called_once_with(
            "SSH password for root@sensor.example: "
        )

    @patch("deploy_remote_sensor_node.getpass.getpass")
    def test_identity_skips_password_prompt(self, get_password):
        password = prompt_for_ssh_password(
            make_options(identity_file=Path("/keys/fissure-node"))
        )

        self.assertIsNone(password)
        get_password.assert_not_called()

    @patch("deploy_remote_sensor_node.getpass.getpass", return_value="")
    def test_empty_password_is_rejected(self, _get_password):
        with self.assertRaisesRegex(DeploymentError, "cannot be empty"):
            prompt_for_ssh_password(make_options())

    @patch("deploy_remote_sensor_node.getpass.getpass", side_effect=EOFError)
    def test_missing_secure_terminal_is_rejected(self, _get_password):
        with self.assertRaisesRegex(DeploymentError, "securely"):
            prompt_for_ssh_password(make_options())


class DeploymentInvariantTests(unittest.TestCase):
    def test_service_tracks_current_release_and_external_state(self):
        options = make_options()
        unit = build_service_unit(
            options, "fissure", "fissure", "/usr/bin/apptainer"
        )
        self.assertIn("/opt/fissure-sensor-node/current/", unit)
        self.assertIn("/opt/fissure-sensor-node/state/home", unit)
        self.assertIn("/opt/fissure-sensor-node/state/runtime-overlay.img", unit)
        self.assertIn("/certificates:/opt/FISSURE/certificates:ro", unit)

    def test_ip_health_requires_a_current_hub_heartbeat(self):
        options = make_options()
        snapshot = {
            "network_type": "IP",
            "hiprfisr_connected": True,
            "updated_at_epoch": 1_000,
        }
        self.assertTrue(heartbeat_is_ready(snapshot, 1_050, options))
        self.assertFalse(heartbeat_is_ready(snapshot, 1_100, options))
        self.assertFalse(
            heartbeat_is_ready({**snapshot, "hiprfisr_connected": False}, 1_050, options)
        )
        self.assertTrue(
            heartbeat_is_ready(snapshot, 2_000, make_options(startup_only=True))
        )

    def test_build_context_excludes_private_material(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            source, destination = root / "source", root / "copy"
            (source / ".git").mkdir(parents=True)
            (source / "certificates").mkdir()
            (source / "nested").mkdir()
            (source / "keep.txt").write_text("keep")
            (source / ".git/config").write_text("secret")
            (source / "certificates/private.key").write_text("secret")
            (source / "nested/client.key_secret").write_text("secret")

            copy_build_context(source, destination)

            self.assertTrue((destination / "keep.txt").is_file())
            self.assertFalse((destination / ".git").exists())
            self.assertFalse((destination / "certificates").exists())
            self.assertFalse((destination / "nested/client.key_secret").exists())


class ScpTransferTests(unittest.IsolatedAsyncioTestCase):
    async def test_payload_uses_scp_with_normalized_remote_names(self):
        class FakeAsyncSSH:
            def __init__(self):
                self.calls = []

            async def scp(self, source, destination):
                self.calls.append((source, destination))

        asyncssh = FakeAsyncSSH()
        connection = object()
        await upload_payload(
            asyncssh,
            connection,
            "/tmp/fissure-node-deploy.test",
            make_options(),
            Path("/local/custom-name.sif"),
            Path("/local/fissure-sensor-node.service"),
        )

        remote_names = [destination[1].rsplit("/", 1)[-1] for _, destination in asyncssh.calls]
        self.assertEqual(
            remote_names,
            [
                "fissure-sensor-node.sif",
                "default.yaml",
                "client_0.key_secret",
                "server.key",
                "fissure-sensor-node.service",
            ],
        )
        self.assertTrue(all(destination[0] is connection for _, destination in asyncssh.calls))


if __name__ == "__main__":
    unittest.main()
