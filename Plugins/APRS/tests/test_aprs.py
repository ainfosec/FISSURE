"""No-device contract tests. Run: python3 -m unittest discover -s Plugins/APRS/tests -v"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import uuid


ROOT = Path(__file__).resolve().parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# The real Operation class is provided by FISSURE in production. A small stub
# reproduces the contracts touched by the tests, without any SDR/Qt/ZMQ deps.
class FakeOperation:
    def __init__(self, node_uid="", logger=None, detection_callback=None,
                 target_callback=None, status_callback=None, artifact_manager=None):
        self.node_uid = node_uid
        self.opid = str(uuid.uuid4())
        self.logger = logger or logging.getLogger(__name__)
        self.detection_callback = detection_callback or (lambda x: None)
        self.target_callback = target_callback or (lambda **x: None)
        self.status_callback = status_callback or (lambda x: None)
        self.artifact_manager = artifact_manager
        self._stop = False
        # Emulate upstream's decorated base __init__: prepare_resources() is
        # invoked before the subclass constructor regains control.
        self.prepared_resources = self.get_resources(**getattr(self, "resource_args", {}))

    def get_subprocess_environment(self):
        return os.environ.copy()

    async def _sleep_stop_aware(self, seconds):
        loop = asyncio.get_running_loop()
        end = loop.time() + seconds
        while loop.time() < end and not self._stop:
            await asyncio.sleep(min(0.01, max(0, end - loop.time())))
        return not self._stop

    def create_artifact(self, files, name, artifact_type, metadata, file_metadata=None):
        return self.artifact_manager.create_artifact(
            source_id=self.node_uid, operation_id=self.opid, files=files,
            name=name, artifact_type=artifact_type, metadata=metadata,
            file_metadata=file_metadata,
        )

    def update_artifact(self, artifact_id, files, metadata):
        return self.artifact_manager.update_artifact(
            artifact_id=artifact_id, files=files, metadata=metadata,
        )


fake_module = types.ModuleType("fissure.utils.plugins.operations")
fake_module.Operation = FakeOperation
with patch.dict(sys.modules, {"fissure.utils.plugins.operations": fake_module}):
    OP = _load("aprs_plugin_operation_test", ROOT / "operations/aprs_monitor.py")
CODEC = _load("aprs_codec_test", ROOT / "scripts/aprs_codec.py")


class FakeArtifactManager:
    def __init__(self, base):
        self.base = Path(base)
        self.create_calls = []
        self.update_calls = []

    def create_operation_dir(self, opid):
        directory = self.base / opid
        directory.mkdir(exist_ok=True)
        return str(directory.parent), str(directory)

    def create_artifact(self, **kwargs):
        self.create_calls.append(kwargs)
        return "artifact-aprs-test"

    def update_artifact(self, **kwargs):
        self.update_calls.append(kwargs)
        return True


class CodecTests(unittest.TestCase):
    def test_tnc2_uncompressed_position_and_altitude(self):
        packet = CODEC.parse_line(
            "APRS: N0CALL-9>APRS,WIDE1-1*,WIDE2-1:!4903.50N/07201.75W>Demo /A=001234"
        )
        self.assertEqual(packet["source"], "N0CALL-9")
        self.assertEqual(packet["path"], ["WIDE1-1*", "WIDE2-1"])
        self.assertEqual(packet["packet_type"], "position")
        self.assertAlmostEqual(packet["position"]["latitude"], 49.058333, places=5)
        self.assertAlmostEqual(packet["position"]["longitude"], -72.029167, places=5)
        self.assertAlmostEqual(packet["position"]["altitude_m"], 376.1232, places=2)

    def test_timestamped_south_east_position(self):
        packet = CODEC.parse_line(
            "AFSK1200: VK2ABC>APRS:/012345z3256.46S\\15130.90E#Test"
        )
        self.assertAlmostEqual(packet["position"]["latitude"], -32.941, places=3)
        self.assertAlmostEqual(packet["position"]["longitude"], 151.515, places=3)

    def test_compressed_position(self):
        def b91(n):
            out = ""
            for div in (91 ** 3, 91 ** 2, 91, 1):
                out += chr(33 + n // div % 91)
            return out

        lat, lon = 40.714, -74.006
        body = "/" + b91(round((90 - lat) * 380926)) + b91(round((180 + lon) * 190463)) + ">"
        packet = CODEC.parse_line("N2XYZ>APRS:!" + body + "Compressed")
        self.assertEqual(packet["position"]["position_format"], "compressed")
        self.assertAlmostEqual(packet["position"]["latitude"], lat, delta=0.001)
        self.assertAlmostEqual(packet["position"]["longitude"], lon, delta=0.001)

    def test_malformed_and_third_party_not_mapped(self):
        self.assertIsNone(CODEC.parse_line("rtl_fm: buffer underrun"))
        self.assertIsNone(CODEC.parse_line("APRS: NOT A CALL>APRS:!4903.50N/07201.75W>"))
        invalid = CODEC.parse_line("N0CALL>APRS:!9001.00N/18101.00W>bad")
        self.assertIsNone(invalid["position"])
        third_party = CODEC.parse_line(
            "IGATE>APRS:}N0CALL>APRS:!4903.50N/07201.75W>Outer gateway"
        )
        self.assertEqual(third_party["packet_type"], "third_party")
        self.assertIsNone(third_party["position"])

    def test_object_is_not_station_location(self):
        packet = CODEC.parse_line(
            "N0CALL>APRS:;BALLOON  *111111z4903.50N/07201.75WOObject"
        )
        self.assertEqual(packet["packet_type"], "object")
        self.assertEqual(packet["position_entity"], "BALLOON")
        self.assertIsNotNone(packet["position"])
        self.assertIsNone(CODEC.parse_line("N0CALL>APRS:;GARBAGE" )["position"])


class RunTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addAsyncCleanup(self._clean)
        self.events = []
        self.targets = []
        self.statuses = []
        self.artifacts = FakeArtifactManager(self.temp.name)

    async def _clean(self):
        self.temp.cleanup()

    async def detection(self, event):
        self.events.append(event)

    async def target(self, **kwargs):
        self.targets.append(kwargs)

    async def status(self, message):
        self.statuses.append(message)

    def operation(self, **kwargs):
        return OP.OperationMain(
            node_uid="node-test", detection_callback=self.detection,
            target_callback=self.target, status_callback=self.status,
            artifact_manager=self.artifacts, **kwargs,
        )

    async def test_full_replay_targets_detections_artifact(self):
        op = self.operation(
            input_mode="tnc2_file",
            source_file=str(ROOT / "resources/example_aprs.tnc2"),
            log_artifact="true", artifact_update_packets=2,
        )
        await op.run()
        self.assertEqual(op.packets, 5)
        self.assertEqual(set(op.stations), {"N0CALL-9", "K1ABC"})
        self.assertEqual(len(self.events), 5)
        self.assertEqual(op.prepared_resources, {})  # No RTL lock during replay.
        self.assertEqual([x["first_seen"] for x in self.events],
                         [True, True, False, False, False])
        self.assertEqual(len(self.targets), 4)
        self.assertEqual(len(self.artifacts.create_calls), 1)
        self.assertEqual(len(self.artifacts.update_calls), 2)
        self.assertEqual(self.artifacts.update_calls[-1]["metadata"]["packet_count"], 5)
        raw_path = Path(self.artifacts.create_calls[0]["files"][0])
        lines = [json.loads(s) for s in raw_path.read_text().splitlines()]
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[0]["callsign"], "N0CALL-9")
        self.assertAlmostEqual(lines[0]["latitude"], 49.058333, places=5)
        self.assertTrue(self.statuses[-1].startswith("Finished"))
        first_id = self.targets[0]["target_id"]
        self.assertEqual(first_id, self.targets[2]["target_id"])
        self.assertEqual(self.targets[0]["patch"]["location"]["source"], "aprs_reported")
        self.assertNotIn("ce_m", self.targets[0]["patch"]["location"])
        self.assertNotIn("location", self.targets[1]["patch"])

    async def test_unrecognized_text_replay_reports_why_no_events(self):
        bad = Path(self.temp.name) / "unsupported.txt"
        bad.write_text("2026-01-01 APRS TEST1>APRS:!4903.50N/07201.75W>prefixed\n"
                       "AFSK1200: fm TEST1 to APRS via WIDE1-1 UI\n")
        op = self.operation(input_mode="tnc2_file", source_file=str(bad))
        await op.run()
        self.assertEqual(op.packets, 0)
        self.assertEqual(op.replay_lines_checked, 2)
        self.assertEqual(op.replay_lines_skipped, 2)
        self.assertTrue(any("0 valid packets" in msg for msg in self.statuses))

    async def test_object_position_maps_object_not_sender(self):
        data = Path(self.temp.name) / "objects.txt"
        data.write_text("N0CALL>APRS:;BALLOON  *111111z4903.50N/07201.75WOObject\n")
        op = self.operation(input_mode="tnc2_file", source_file=str(data))
        await op.run()
        self.assertEqual(len(self.targets), 2)
        self.assertNotIn("location", self.targets[0]["patch"])
        self.assertIn("location", self.targets[1]["patch"])
        self.assertEqual(self.events[0]["position_entity"], "BALLOON")

    async def test_stop_during_slow_replay(self):
        op = self.operation(input_mode="tnc2_file", replay_delay_s=0.4,
                            source_file=str(ROOT / "resources/example_aprs.tnc2"))
        task = asyncio.create_task(op.run())
        while not self.events:
            await asyncio.sleep(0.01)
        op._stop = True
        await asyncio.wait_for(task, timeout=2)
        self.assertTrue(1 <= op.packets < 5)
        self.assertTrue(self.statuses[-1].startswith("Stopped"))

    async def test_missing_replay_file_errors_cleanly(self):
        op = self.operation(input_mode="tnc2_file", source_file="/not/real/aprs.tnc2")
        with self.assertRaises(FileNotFoundError):
            await op.run()
        self.assertTrue(any("Error:" in message for message in self.statuses))
        self.assertTrue(self.statuses[-1].startswith("Error:"))
        self.assertFalse(any(message.startswith("Finished") for message in self.statuses))

    async def test_target_identity_is_independent_of_sensor_node(self):
        line = "APRS: N0CALL-9>APRS:!4903.50N/07201.75W>Same station"
        first_targets = []
        second_targets = []

        async def first_target(**kwargs):
            first_targets.append(kwargs)

        async def second_target(**kwargs):
            second_targets.append(kwargs)

        first = OP.OperationMain(
            input_mode="tnc2_file", source_file="unused", node_uid="node-a",
            detection_callback=self.detection, target_callback=first_target,
            status_callback=self.status, artifact_manager=self.artifacts,
        )
        second = OP.OperationMain(
            input_mode="tnc2_file", source_file="unused", node_uid="node-b",
            detection_callback=self.detection, target_callback=second_target,
            status_callback=self.status, artifact_manager=self.artifacts,
        )
        await first._receive_line(line)
        await second._receive_line(line)
        self.assertEqual(first_targets[0]["target_id"], second_targets[0]["target_id"])
        self.assertEqual(first_targets[0]["patch"]["node_uid"], "node-a")
        self.assertEqual(second_targets[0]["patch"]["node_uid"], "node-b")

    async def test_synthetic_rtl_pipeline(self):
        """Fake executables exercise the *real* asyncio subprocess plumbing."""
        rtl = Path(self.temp.name) / "fake_rtl_fm"
        rtl.write_text("#!/usr/bin/env python3\nimport sys, time\n"
                       "sys.stdout.buffer.write(b'\\x00' * 32768)\n"
                       "sys.stdout.buffer.flush()\ntime.sleep(0.5)\n")
        multimon = Path(self.temp.name) / "fake_multimon_ng"
        multimon.write_text(
            "#!/usr/bin/env python3\nimport sys\n"
            "expected = ['-q', '-A', '-a', 'AFSK1200', '-t', 'raw', '-']\n"
            "assert sys.argv[1:] == expected, sys.argv[1:]\n"
            "sys.stdin.buffer.read(4096)\n"
            "print('APRS: TEST1>APRS:!4903.50N/07201.75W>Fake RF', flush=True)\n"
        )
        rtl.chmod(0o755)
        multimon.chmod(0o755)
        orig_which = OP.shutil.which

        def which(name):
            return {"rtl_fm": str(rtl), "multimon-ng": str(multimon)}.get(name, orig_which(name))

        op = self.operation(input_mode="rtl", max_packets=1)
        self.assertEqual(op.prepared_resources["rtl_receiver"]["serial"], "0")
        with patch.object(OP.shutil, "which", side_effect=which):
            await asyncio.wait_for(op.run(), timeout=5)
        self.assertEqual(op.packets, 1)
        self.assertEqual(self.events[0]["callsign"], "TEST1")
        self.assertFalse(op._procs)
        self.assertFalse(op._tasks)
        self.assertEqual(op.get_resources("tnc2_file"), {})
        self.assertEqual(op.get_resources("rtl", "1")["rtl_receiver"]["serial"], "1")

    async def test_simulated_audio_file_decoder(self):
        """Verify WAV audio replay launches multimon-ng, parses, and exits."""
        audio = Path(self.temp.name) / "simulated_aprs.wav"
        audio.write_bytes(b"RIFF" + b"\0" * 64)
        decoder = Path(self.temp.name) / "fake_audio_multimon_ng"
        decoder.write_text(
            "#!/usr/bin/env python3\nimport sys\n"
            "assert sys.argv[1:] == ['-q', '-A', '-a', 'AFSK1200', '-t', 'wav', sys.argv[-1]]\n"
            "print('AFSK1200: K1ABC>APRS:!4000.00N/07400.00W>Fake WAV', flush=True)\n"
        )
        decoder.chmod(0o755)
        op = self.operation(input_mode="audio_file", source_file=str(audio))
        self.assertEqual(op.prepared_resources, {})
        original = OP.shutil.which
        with patch.object(OP.shutil, "which", side_effect=lambda name: str(decoder) if name == "multimon-ng" else original(name)):
            await asyncio.wait_for(op.run(), timeout=3)
        self.assertEqual(op.packets, 1)
        self.assertEqual(self.events[0]["callsign"], "K1ABC")
        self.assertEqual(len(self.targets), 1)
        self.assertFalse(op._procs)


class ActionTests(unittest.IsolatedAsyncioTestCase):
    async def test_exposes_only_live_monitor_action(self):
        sensor_mod = types.ModuleType("fissure.Sensor_Node.SensorNode")
        sensor_mod.SensorNode = type("SensorNode", (), {})
        with patch.dict(sys.modules, {"fissure.Sensor_Node.SensorNode": sensor_mod}):
            action = _load("aprs_plugin_actions_test", ROOT / "actions.py")
        import inspect
        exported = {n for n, v in vars(action).items()
                    if inspect.iscoroutinefunction(v) and getattr(v, "__module__", "") == action.__name__}
        self.assertEqual(exported, {"aprs_monitor"})
        self.assertEqual(action.ACTION_HARDWARE, {"aprs_monitor": ["RTL2832U"]})
        self.assertEqual(set(action.ACTION_TAGS), {"aprs_monitor"})

        class Component:
            def __init__(self):
                self.calls = []

            async def run_plugin_operation(self, *args):
                self.calls.append(args)

        component = Component()
        await action.aprs_monitor(component, {"rtl_device": "1"}, "node-a")
        self.assertEqual(len(component.calls), 1)
        args = component.calls[0]
        self.assertIs(args[0], component)
        self.assertEqual(args[1:3], ("APRS", "aprs_monitor.py"))
        self.assertEqual(args[4], "node-a")
        self.assertEqual(args[3]["input_mode"], "rtl")
        self.assertEqual(
            {p["name"] for p in action.aprs_monitor_schema["params"]},
            {"rtl_device", "rtl_gain_db", "log_artifact", "emit_targets"},
        )
        self.assertNotIn("rtl_ppm", {p["name"] for p in action.aprs_monitor_schema["params"]})


if __name__ == "__main__":
    unittest.main()
