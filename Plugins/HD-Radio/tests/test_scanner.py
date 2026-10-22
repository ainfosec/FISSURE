"""Hardware-free tests for FISSURE Action/Operation architecture and survey logic.

Run: python3 -m unittest discover -s tests -v
No fake fixture constitutes an over-the-air HD Radio acquisition.
"""
import asyncio
import importlib.util
import json
import logging
from pathlib import Path
import os
import sys
import tempfile
import textwrap
import types
import unittest
import uuid
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, str(filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class FakeOperation:
    def __init__(self, node_uid="", logger=None, status_callback=None, artifact_manager=None):
        self.node_uid = node_uid
        self.logger = logger or logging.getLogger("test_scan")
        self.status_callback = status_callback or (lambda message: asyncio.sleep(0))
        self.artifact_manager = artifact_manager
        self.opid = str(uuid.uuid4())
        self._stop = False
        self.resources_on_init = self.get_resources(**getattr(self, "resource_args", {}))

    def create_artifact(self, **kwargs):
        return self.artifact_manager.create_artifact(operation_id=self.opid, **kwargs)


for name in ["fissure", "fissure.utils", "fissure.utils.plugins"]:
    sys.modules.setdefault(name, types.ModuleType(name))
sys.modules["fissure.utils.plugins.operations"] = types.ModuleType("fissure.utils.plugins.operations")
sys.modules["fissure.utils.plugins.operations"].Operation = FakeOperation
sys.modules["fissure.Sensor_Node"] = types.ModuleType("fissure.Sensor_Node")
sys.modules["fissure.Sensor_Node.SensorNode"] = types.ModuleType("fissure.Sensor_Node.SensorNode")
sys.modules["fissure.Sensor_Node.SensorNode"].SensorNode = type("SensorNode", (), {})

parser = load_module("nrsc5_parser", ROOT / "scripts/nrsc5_parser.py")
survey = load_module("hd_radio_survey", ROOT / "scripts/hd_radio_survey.py")
report = load_module("hd_radio_report", ROOT / "scripts/hd_radio_report.py")
core = load_module("hd_radio_scan_core", ROOT / "scripts/hd_radio_scan_core.py")
full = load_module("hd_scan_full_test", ROOT / "operations/scan_hd_radio.py")
quick = load_module("hd_scan_quick_test", ROOT / "operations/scan_hd_radio_quick.py")
actions = load_module("hd_scan_actions_test", ROOT / "actions.py")


class FakeArtifactManager:
    def __init__(self, parent):
        self.parent = Path(parent)
        self.records = []

    def create_operation_dir(self, opid):
        path = self.parent / opid / "files"
        path.mkdir(parents=True, exist_ok=True)
        return str(path.parent), str(path)

    def create_artifact(self, *, operation_id, files, name, artifact_type, metadata, file_metadata):
        _, directory = self.create_operation_dir(operation_id)
        for filename in files:
            if not Path(filename).is_file() or Path(filename).parent != Path(directory):
                raise AssertionError("unmanaged FISSURE Artifact file")
        self.records.append({"files": files, "name": name, "artifact_type": artifact_type,
                             "metadata": metadata, "file_metadata": file_metadata})
        return "artifact-test-id"

    def json_results(self):
        return json.loads(Path(self.records[-1]["files"][-1]).read_text())

    def text_results(self):
        return Path(self.records[-1]["files"][0]).read_text()


class ParserTests(unittest.TestCase):
    def test_confirmed_sis_and_sig(self):
        lines = ["11:22:33 Synchronized", "11:22:34 Country: US, FCC facility ID: 12345",
                 "11:22:34 Station name: WTEST", "11:22:34 Slogan: The Station",
                 "11:22:34 SIG Service: type=audio number=0 name=Main",
                 "11:22:35 SIG Service: type=audio number=1 name=Jazz",
                 "11:22:35 Audio program 1: public, type: Jazz, sound experience 0"]
        record = parser.parse_nrsc5_output(lines, 88.1)
        self.assertEqual(record["classification"], "confirmed_hd_radio")
        self.assertEqual(record["station_identifiers"]["fcc_facility_id"], 12345)
        self.assertEqual([p["hd_channel"] for p in record["programs"]], ["HD1", "HD2"])
        self.assertEqual(record["station_identifiers"]["slogan"], "The Station")

    def test_sync_not_confirmed(self):
        self.assertEqual(parser.parse_nrsc5_output(["Synchronized"], 88.3)["classification"],
                         "sync_only_unconfirmed")

    def test_metadata_without_sync_not_confirmed(self):
        self.assertEqual(parser.parse_nrsc5_output(["Station name: WTEST"], 88.1)["classification"],
                         "no_hd_confirmed")

    def test_analog_noise_not_hd(self):
        self.assertEqual(parser.parse_nrsc5_output(["Signal detected", "RDS PS: TEST"], 88.5)["classification"],
                         "no_hd_confirmed")

    def test_frequency_validation(self):
        for bad in [88, 108, 88.2, 87.9, float("nan"), float("inf")]:
            with self.assertRaises(ValueError):
                core.channel_tenths(bad, "frequency")
        self.assertEqual(core.channel_tenths("88.1", "frequency"), 881)

    def test_rtl_power_bins_selection_and_cap(self):
        data = "2026-01-01, 10:00:00, 88000000, 89000000, 100000, 10, " + ", ".join(
            str(x) for x in [-65, -42, -65, -49, -65, -80, -65, -36, -65, -80]) + "\n"
        bins = survey.parse_rtl_power_csv(data)
        self.assertEqual(len(bins), 10)
        result = survey.select_candidates(bins, [881, 883, 885, 887], 6, 2, 1)
        self.assertEqual(result["candidate_frequencies_mhz"], [88.7, 88.1])
        self.assertEqual(result["excluded_frequencies_mhz"], [88.3, 88.5])

    def test_fallback_minimum_candidates(self):
        bins = [{"frequency_hz": 88100000, "power_db": -80},
                {"frequency_hz": 88300000, "power_db": -80}]
        result = survey.select_candidates(bins, [881, 883], threshold_db=20,
                                          max_candidates=10, min_candidates=1)
        self.assertEqual(result["selected_count"], 1)

    def test_survey_missing_bin_rejected(self):
        with self.assertRaises(ValueError):
            survey.select_candidates([{"frequency_hz": 88100000, "power_db": -65}], [881, 883])
        self.assertEqual(survey.parse_rtl_power_csv("not,csv\n"), [])

    def test_nonfinite_parameters(self):
        for bad in [float("inf"), float("nan"), -2]:
            with self.assertRaises(ValueError):
                quick.OperationMain(acquisition_time_s=bad)
        with self.assertRaises(ValueError):
            quick.OperationMain(min_candidates=50, max_candidates=20)


class ActionTests(unittest.IsolatedAsyncioTestCase):
    async def test_both_actions_delegated(self):
        class FakeNode:
            def __init__(self):
                self.invocations = []

            async def run_plugin_operation(self, *args):
                self.invocations.append(args)

        node = FakeNode()
        params = {"start_frequency_mhz": 88.1, "stop_frequency_mhz": 88.5}
        await actions.scan_hd_radio(node, params, "node")
        await actions.hd_radio_quick_scan(node, params, "node")
        self.assertEqual([args[2] for args in node.invocations],
                         ["scan_hd_radio.py", "scan_hd_radio_quick.py"])
        self.assertEqual(set(actions.ACTION_HARDWARE), {"scan_hd_radio", "hd_radio_quick_scan"})
        self.assertEqual(set(actions.ACTION_TAGS), set(actions.ACTION_HARDWARE))
        self.assertEqual({p["name"] for p in actions.scan_hd_radio_schema["params"]},
                         {"start_frequency_mhz", "stop_frequency_mhz", "sdr_index", "gain_db",
                          "acquisition_time_s"})
        self.assertEqual({p["name"] for p in actions.hd_radio_quick_scan_schema["params"]},
                         {"start_frequency_mhz", "stop_frequency_mhz", "sdr_index", "gain_db",
                          "acquisition_time_s", "max_candidates"})
        self.assertEqual(actions.PLUGIN_NAME, "HD-Radio")


class OperationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.manager = FakeArtifactManager(self.tmp.name)
        self.nrsc5_bin = Path(self.tmp.name) / "nrsc5"
        self.nrsc5_bin.write_text(textwrap.dedent('''\
            #!/bin/sh
            for argument in "$@"; do
                if [ "$argument" = "-t" ]; then
                    echo "nrsc5: invalid option -- 't'" >&2
                    exit 2
                fi
            done
            while [ "$#" -gt 2 ]; do shift; done
            if [ "$1" = "88.5" ]; then
                echo 'Open device failed.'
                exit 1
            fi
            echo '12:13:14 Synchronized'
            if [ "$1" = "88.1" ]; then
                echo '12:13:15 Country: US, FCC facility ID: 23456'
                echo '12:13:15 Station name: WTEST'
                echo '12:13:16 SIG Service: type=audio number=0 name=Main'
                echo '12:13:16 SIG Service: type=audio number=1 name=Jazz'
            fi
            exec sleep 10
        '''))
        self.nrsc5_bin.chmod(0o755)
        self.rtl_bin = Path(self.tmp.name) / "rtl_power"
        # 88.1 and 88.7 top channels; 88.3 weaker; 88.5 no signal.
        self.rtl_bin.write_text(textwrap.dedent('''\
            #!/bin/sh
            printf '2026-01-01, 10:00:00, 88000000, 89000000, 100000, 10, -65, -42, -65, -49, -65, -80, -65, -36, -65, -80\\n'
        '''))
        self.rtl_bin.chmod(0o755)
        self.statuses = []

    async def asyncTearDown(self):
        self.tmp.cleanup()

    async def status(self, message):
        self.statuses.append(message)

    def make_full(self, stop=88.3, index=3):
        op = full.OperationMain(start_frequency_mhz=88.1, stop_frequency_mhz=stop,
                                sdr_index=index, acquisition_time_s=3,
                                artifact_manager=self.manager, node_uid="test-node",
                                status_callback=self.status)
        op.acquisition_time_s = 0.2
        return op

    def make_quick(self, stop=88.7, max_candidates=2, min_candidates=1):
        op = quick.OperationMain(start_frequency_mhz=88.1, stop_frequency_mhz=stop,
                                 acquisition_time_s=3, max_candidates=max_candidates,
                                 min_candidates=min_candidates,
                                 artifact_manager=self.manager, node_uid="test-node",
                                 status_callback=self.status)
        op.acquisition_time_s = 0.2
        op.retry_sync_seconds = 0.2
        return op

    def patch_tools(self, nrsc5=True, rtl=True):
        def which(exe):
            if exe == "nrsc5" and nrsc5:
                return str(self.nrsc5_bin)
            if exe == "rtl_power" and rtl:
                return str(self.rtl_bin)
            return None
        return mock.patch.object(core.shutil, "which", side_effect=which)

    async def test_full_scan_preserved_three_files(self):
        op = self.make_full()
        self.assertEqual(op.resources_on_init["rtl_sdr"]["serial"], "3")
        with self.patch_tools():
            await op.run()
        result = self.manager.json_results()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["mode"], "full")
        self.assertEqual(result["statistics"]["channels_acquired"], 2)
        self.assertEqual(len(result["confirmed_stations"]), 1)
        self.assertEqual(len(result["synchronization_candidates"]), 1)
        self.assertEqual(len(self.manager.records[0]["files"]), 3)
        self.assertIn("CONFIRMED HD RADIO STATIONS", self.manager.text_results())
        self.assertIn("HD2 Jazz", self.manager.text_results())
        self.assertIn("SYNC-ONLY / UNCONFIRMED", self.manager.text_results())
        self.assertTrue(any("confirmed" in s.lower() for s in self.statuses))
        self.assertIsNone(op._process)
        self.assertIsNone(op._reader_task)

    async def test_quick_scan_shortlists(self):
        op = self.make_quick()
        with self.patch_tools():
            await op.run()
        payload = self.manager.json_results()
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(payload["mode"], "quick")
        self.assertEqual(payload["survey"]["selected_count"], 2)
        self.assertEqual(payload["statistics"]["channels_acquired"], 2)
        self.assertEqual(payload["channels_not_checked"], [88.3, 88.5])
        self.assertEqual([r["frequency_mhz"] for r in payload["confirmed_stations"]], [88.1])
        self.assertIn("QUICK SCAN SPECTRUM SURVEY", self.manager.text_results())
        self.assertIn("88.3", self.manager.text_results())
        self.assertIsNone(op._process)

    async def test_quick_sync_only_retry_and_candidate(self):
        op = self.make_quick(stop=88.3, max_candidates=2, min_candidates=2)
        with self.patch_tools():
            await op.run()
        payload = self.manager.json_results()
        self.assertEqual(payload["statistics"]["sync_only"], 1)
        record = payload["synchronization_candidates"][0]
        self.assertTrue(record["extended_after_sync"])
        self.assertTrue(any("extended" in note for note in record["notes"]))
        self.assertGreater(record["acquisition_seconds"], 0.2)

    async def test_quick_extends_existing_nrsc5_session_for_late_metadata(self):
        # Synchronization appears first; station metadata arrives only during
        # the extension. Starting a new process would lose decoder state.
        starts = Path(self.tmp.name) / "decoder_starts.txt"
        self.nrsc5_bin.write_text("#!/bin/sh\n"
                                  + "echo start >> '" + str(starts) + "'\n"
                                  + "echo '12:13:14 Synchronized'\n"
                                  + "sleep 0.30\n"
                                  + "echo '12:13:15 Station name: WLATE'\n"
                                  + "echo '12:13:15 SIG Service: type=audio number=0 name=Main'\n"
                                  + "exec sleep 10\n")
        self.nrsc5_bin.chmod(0o755)
        op = self.make_quick(stop=88.1, max_candidates=1, min_candidates=1)
        op.retry_sync_seconds = 0.45
        with self.patch_tools():
            await op.run()
        result = self.manager.json_results()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["confirmed_stations"][0]["station_identifiers"]["station_name"], "WLATE")
        self.assertTrue(result["observations"][0]["extended_after_sync"])
        self.assertEqual(starts.read_text().splitlines(), ["start"])

    async def test_artifact_registration_failure_is_reported(self):
        op = self.make_full(stop=88.1)
        with self.patch_tools(), mock.patch.object(self.manager, "create_artifact", side_effect=OSError("disk error")):
            with self.assertRaisesRegex(RuntimeError, "disk error"):
                await op.run()
        self.assertTrue(any("ARTIFACT ERROR" in message for message in self.statuses))

    async def test_missing_nrsc5_creates_failure_artifact(self):
        with self.patch_tools(nrsc5=False):
            with self.assertRaisesRegex(RuntimeError, "nrsc5 executable missing"):
                await self.make_full().run()
        self.assertEqual(self.manager.json_results()["status"], "failed")
        self.assertIn("nrsc5", self.manager.json_results()["errors"][0]["error"])

    async def test_missing_rtl_power_creates_failure_artifact(self):
        with self.patch_tools(rtl=False):
            with self.assertRaisesRegex(RuntimeError, "rtl_power executable missing"):
                await self.make_quick().run()
        self.assertEqual(self.manager.json_results()["status"], "failed")
        self.assertIn("rtl_power", self.manager.json_results()["errors"][0]["error"])

    async def test_acquisition_failed_and_partial_results(self):
        with self.patch_tools():
            with self.assertRaisesRegex(RuntimeError, "Open device failed"):
                await self.make_full(stop=88.5).run()
        data = self.manager.json_results()
        self.assertEqual(data["status"], "failed")
        self.assertEqual(len(data["confirmed_stations"]), 1)
        self.assertEqual(data["observations"][-1]["acquisition_status"], "failed")

    async def test_stop_during_full_scan(self):
        op = self.make_full(stop=88.7)
        op.acquisition_time_s = 10
        with self.patch_tools():
            task = asyncio.create_task(op.run())
            await asyncio.sleep(0.2)
            op._stop = True
            await asyncio.wait_for(task, timeout=4)
        self.assertEqual(self.manager.json_results()["status"], "interrupted")
        self.assertIsNone(op._process)

    async def test_stop_during_quick_scan_survey(self):
        self.rtl_bin.write_text("#!/bin/sh\nexec sleep 10\n")
        op = self.make_quick()
        with self.patch_tools():
            task = asyncio.create_task(op.run())
            await asyncio.sleep(0.2)
            op._stop = True
            await asyncio.wait_for(task, timeout=4)
        self.assertEqual(self.manager.json_results()["status"], "interrupted")
        self.assertIsNone(op._process)

    async def test_task_cancellation_preserves_partial_artifact(self):
        op = self.make_full(stop=88.7)
        op.acquisition_time_s = 10
        with self.patch_tools():
            task = asyncio.create_task(op.run())
            await asyncio.sleep(0.2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=4)
        self.assertEqual(self.manager.json_results()["status"], "interrupted")
        self.assertIsNone(op._process)

    async def test_cancel_during_survey_creates_interrupted_artifact(self):
        self.rtl_bin.write_text("#!/bin/sh\nexec sleep 10\n")
        op = self.make_quick()
        with self.patch_tools():
            task = asyncio.create_task(op.run())
            await asyncio.sleep(0.2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=4)
        self.assertEqual(self.manager.json_results()["status"], "interrupted")
        self.assertIsNone(op._process)

    async def test_rtl_power_nonzero_reports_failure(self):
        self.rtl_bin.write_text("#!/bin/sh\necho 'No supported devices found.' >&2\nexit 1\n")
        with self.patch_tools():
            with self.assertRaises(RuntimeError):
                await self.make_quick().run()
        data = self.manager.json_results()
        self.assertEqual(data["status"], "failed")
        self.assertIn("No supported devices", data["errors"][0]["error"])

    async def test_quick_bad_survey_errors_not_false_zero_stations(self):
        self.rtl_bin.write_text("#!/bin/sh\necho 'broken csv'\n")
        with self.patch_tools():
            with self.assertRaises(RuntimeError):
                await self.make_quick().run()
        result = self.manager.json_results()
        self.assertEqual(result["status"], "failed")
        self.assertIn("no valid FFT", result["errors"][0]["error"])

    async def test_historical_nrsc5_cli_compatibility(self):
        cmd = self.make_full()._command("nrsc5", 99.1)
        self.assertNotIn("-t", cmd)
        self.assertIn("-o", cmd)
        self.assertEqual(cmd[-2:], ["99.1", "0"])


if __name__ == "__main__":
    unittest.main()
