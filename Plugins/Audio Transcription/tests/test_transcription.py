"""Local isolated tests. Requires ffmpeg but not FISSURE or whisper.cpp.

Runs only temporary test fixtures and fake whisper-cli; proves no actual ASR.
"""
import asyncio
import importlib.util
import inspect
import json
import logging
import math
import os
import random
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
import wave


# Mimic only the Operation base interface used by the plugin.
class StubOperation:
    def __init__(self, node_uid="", logger=None, status_callback=None, artifact_manager=None):
        self.node_uid = node_uid
        self.logger = logger or logging.getLogger(__name__)
        self.status_callback = status_callback
        self.artifact_manager = artifact_manager
        self.opid = "test-operation-id"
        self._stop = False

    def create_artifact(self, files, name, artifact_type, metadata=None, file_metadata=None):
        return self.artifact_manager.create_artifact(
            self.opid, files, name, artifact_type, metadata, file_metadata
        )


for module_name in (
    "fissure", "fissure.utils", "fissure.utils.plugins", "fissure.utils.plugins.operations",
):
    sys.modules.setdefault(module_name, types.ModuleType(module_name))
sys.modules["fissure.utils.plugins.operations"].Operation = StubOperation

spec = importlib.util.spec_from_file_location(
    "audio_transcription_operation", Path(__file__).resolve().parents[1] /
    "operations" / "transcribe_audio_file.py"
)
op_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op_module)


class FakeArtifacts:
    def __init__(self, root):
        self.root = Path(root)
        self.created = []

    def create_operation_dir(self, opid):
        files = self.root / opid / "files"
        files.mkdir(parents=True, exist_ok=True)
        return str(files.parent), str(files)

    def create_artifact(self, opid, files, name, artifact_type, metadata, file_metadata):
        for item in files:
            # Mimic FISSURE's managed-path check.
            assert Path(item).resolve().parent == (self.root / opid / "files").resolve()
        self.created.append((files, metadata, file_metadata))
        return "artifact-test-123"


def create_wav(path, rate, channels, silence=False):
    with wave.open(str(path), "wb") as wav:
        wav.setnchannels(channels)
        wav.setsampwidth(2)
        wav.setframerate(rate)
        frames = []
        for n in range(int(rate * 0.5)):
            sample = 0 if silence else int(2000 * math.sin(2 * math.pi * 440 * n / rate))
            for _ in range(channels):
                frames.append(sample)
        wav.writeframes(struct.pack("<{}h".format(len(frames)), *frames))


class TranscriptionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.root = self.folder / "whisper.cpp"
        cli = self.root / "build" / "bin" / "whisper-cli"
        cli.parent.mkdir(parents=True)
        cli.write_text(
            "#!/usr/bin/env python3\n"
            "import json,sys\n"
            "a=sys.argv\n"
            "prefix=a[a.index('-of')+1]\n"
            "data={'result':{'language':'en'},'transcription':["
            "{'timestamps':{'from':'00:00:00,000','to':'00:00:00,500'},"
            "'text':' This is Station Alpha.'}]}\n"
            "open(prefix+'.json','w').write(json.dumps(data))\n",
            encoding="utf-8",
        )
        cli.chmod(0o755)
        model = self.root / "models" / "ggml-small.bin"
        model.parent.mkdir(parents=True)
        model.write_bytes(b"fixture")
        original = os.environ.get(op_module.WHISPER_ROOT_ENV)
        os.environ[op_module.WHISPER_ROOT_ENV] = str(self.root)
        self.addCleanup(
            lambda: os.environ.pop(op_module.WHISPER_ROOT_ENV, None) if original is None
            else os.environ.__setitem__(op_module.WHISPER_ROOT_ENV, original)
        )
        self.statuses = []
        self.artifacts = FakeArtifacts(self.folder / "artifacts_node")

    def run_op(self, path):
        async def status_cb(text):
            self.statuses.append(text)
        op = op_module.OperationMain(
            audio_file_path=str(path), node_uid="testnode", status_callback=status_cb,
            artifact_manager=self.artifacts,
        )
        asyncio.run(op.run())
        return op

    def test_one_action_exposed_and_delegates_to_operation(self):
        node_package = types.ModuleType("fissure.Sensor_Node")
        node_module = types.ModuleType("fissure.Sensor_Node.SensorNode")
        node_module.SensorNode = type("SensorNode", (), {})
        sys.modules["fissure.Sensor_Node"] = node_package
        sys.modules["fissure.Sensor_Node.SensorNode"] = node_module
        actions_path = Path(__file__).resolve().parents[1] / "actions.py"
        spec = importlib.util.spec_from_file_location("audio_actions_test", actions_path)
        actions = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(actions)
        exposed = [name for name, obj in inspect.getmembers(actions, inspect.iscoroutinefunction)
                   if obj.__module__ == actions.__name__ and not name.startswith("_")]
        self.assertEqual(exposed, ["transcribe_audio_file"])
        self.assertEqual(actions.transcribe_audio_file_schema["params"][0]["name"], "audio_file_path")

        class FakeNode:
            def __init__(self):
                self.arguments = None

            async def run_plugin_operation(self, *args):
                self.arguments = args

        node = FakeNode()
        asyncio.run(actions.transcribe_audio_file(node, {"audio_file_path": "/tmp/a.wav"}, "node1"))
        self.assertEqual(node.arguments[1:3], ("Audio Transcription", "transcribe_audio_file.py"))
        self.assertEqual(node.arguments[3]["audio_file_path"], "/tmp/a.wav")

    def test_stereo_8k_converts_and_transcribes(self):
        source = self.folder / "stereo_8k.wav"
        create_wav(source, 8000, 2)
        op = self.run_op(source)
        self.assertEqual(op.result["transcription_status"], "completed")
        self.assertEqual(op.result["detected_language"], "en")
        self.assertEqual(op.result["artifact_id"], "artifact-test-123")
        transcript = Path(self.artifacts.created[0][0][0]).read_text()
        self.assertIn("[00:00:00,000 --> 00:00:00,500] This is Station Alpha.", transcript)
        self.assertEqual(self.artifacts.created[0][2][str(Path(self.artifacts.created[0][0][0]))]["role"], "transcript")

    def test_mono_44100_converts_and_transcribes(self):
        source = self.folder / "mono_44k.wav"
        create_wav(source, 44100, 1)
        op = self.run_op(source)
        self.assertEqual(op.result["transcription_status"], "completed")

    def test_silence_registers_empty_transcript(self):
        source = self.folder / "silent.wav"
        create_wav(source, 16000, 1, silence=True)
        op = self.run_op(source)
        self.assertEqual(op.result["transcription_status"], "no_speech")
        self.assertEqual(op.result["detected_language"], "und")
        self.assertIn("No speech detected", Path(self.artifacts.created[0][0][0]).read_text())

    def test_artifact_contains_readable_transcript_and_preview(self):
        source = self.folder / "speech.wav"
        create_wav(source, 16000, 1)
        op = self.run_op(source)
        self.assertEqual(op.result["segment_count"], 1)
        self.assertAlmostEqual(op.result["duration_seconds"], .5)
        transcript = Path(self.artifacts.created[0][0][0]).read_text()
        self.assertIn("TRANSCRIPT\n", transcript)
        self.assertIn("This is Station Alpha.\n", transcript)
        self.assertIn("TIMESTAMPED SEGMENTS", transcript)
        metadata = self.artifacts.created[0][1]
        self.assertEqual(metadata["transcript_preview"], "This is Station Alpha.")
        self.assertEqual(metadata["duration_seconds"], 0.5)

    def test_quiet_broadband_noise_does_not_hallucinate(self):
        source = self.folder / "low_noise.wav"
        rng = random.Random(42)
        with wave.open(str(source), "wb") as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(16000)
            # Short quiet baseline, broadband noise, quiet baseline.
            vals = [0] * 16000
            vals += [rng.randint(-700, 700) for _ in range(16000 * 3)]
            vals += [0] * 16000
            wav.writeframes(struct.pack("<{}h".format(len(vals)), *vals))
        op = self.run_op(source)
        self.assertEqual(op.result["transcription_status"], "no_speech")
        self.assertEqual(op.result["detected_language"], "und")
        self.assertIn("Low-level broadband", self.artifacts.created[0][1]["audio_check"])
        transcript = Path(self.artifacts.created[0][0][0]).read_text()
        self.assertIn("not definitive", transcript)
        self.assertNotIn("This is Station Alpha", transcript)

    def test_quiet_tonal_audio_is_not_rejected_as_noise(self):
        source = self.folder / "quiet_tone.wav"
        with wave.open(str(source), "wb") as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(16000)
            vals = [int(300 * math.sin(2 * math.pi * 440 * n / 16000))
                    for n in range(16000)]
            wav.writeframes(struct.pack("<{}h".format(len(vals)), *vals))
        op = self.run_op(source)
        self.assertEqual(op.result["transcription_status"], "completed")

    def test_invalid_file_fails_cleanly(self):
        source = self.folder / "not-a-wav.wav"
        source.write_text("garbage")
        op = self.run_op(source)
        self.assertEqual(op.result["transcription_status"], "failed")
        self.assertFalse(self.artifacts.created)
        self.assertTrue(any("failed" in item for item in self.statuses))

    def test_missing_source_fails_cleanly(self):
        op = self.run_op(self.folder / "missing.wav")
        self.assertEqual(op.result["transcription_status"], "failed")
        self.assertFalse(self.artifacts.created)

    def test_missing_model_fails_cleanly(self):
        (self.root / "models" / "ggml-small.bin").unlink()
        source = self.folder / "recording.wav"
        create_wav(source, 16000, 1)
        op = self.run_op(source)
        self.assertEqual(op.result["transcription_status"], "failed")
        self.assertIn("model missing", op.result["error"])

    def test_bad_json_fails_cleanly(self):
        cli = self.root / "build" / "bin" / "whisper-cli"
        cli.write_text("#!/usr/bin/env python3\nimport sys\n", encoding="utf-8")
        cli.chmod(0o755)
        source = self.folder / "voice.wav"
        create_wav(source, 16000, 1)
        op = self.run_op(source)
        self.assertEqual(op.result["transcription_status"], "failed")
        self.assertFalse(self.artifacts.created)

    def test_stop_during_whisper_cleans_subprocess(self):
        cli = self.root / "build" / "bin" / "whisper-cli"
        cli.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n", encoding="utf-8")
        cli.chmod(0o755)
        source = self.folder / "voice.wav"
        create_wav(source, 16000, 1)
        async def scenario():
            async def status(text):
                self.statuses.append(text)
            op = op_module.OperationMain(audio_file_path=str(source),
                status_callback=status, artifact_manager=self.artifacts)
            task = asyncio.create_task(op.run())
            for _ in range(200):
                if op._process and any("Recognizing speech" in x for x in self.statuses):
                    break
                await asyncio.sleep(0.025)
            op._stop = True
            await asyncio.wait_for(task, timeout=8)
            return op
        op = asyncio.run(scenario())
        self.assertEqual(op.result["transcription_status"], "stopped")
        self.assertFalse(self.artifacts.created)
        self.assertIsNone(op._process)


if __name__ == "__main__":
    unittest.main()
