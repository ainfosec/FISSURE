"""No-hardware tests for B210 cabled RF Action safety and UHD topology."""
from pathlib import Path
import json
import struct
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ais_b210_loopback as b210


def test_b210_gain_values_and_frequency_bounds():
    assert b210.validate_settings(240000, 915e6, 0, 20) == 240000
    assert b210.validate_settings(240000, 915e6, 85, 60) == 240000
    for frequency in [161975000, 162025000, 433920000, float("nan")]:
        with pytest.raises(b210.LoopbackConfigError, match="lab RF center"):
            b210.validate_settings(240000, frequency, 0, 20)
    for bad_gain in (-1, float("nan"), float("inf")):
        with pytest.raises(b210.LoopbackConfigError, match="TX gain"):
            b210.validate_settings(240000, 915e6, bad_gain, 20)
    with pytest.raises(b210.LoopbackConfigError, match="RX gain"):
        b210.validate_settings(240000, 915e6, 0, 65)
    with pytest.raises(b210.LoopbackConfigError, match="sample rate"):
        b210.validate_settings(200000, 915e6, 0, 20)


def test_b210_flowgraph_has_both_channels_one_top_block(tmp_path):
    calls = {"tx": [], "rx": [], "edges": [], "streams": [], "blocks": []}

    class FakeUSRPRadio:
        def __init__(self, role):
            self.role = role
        def set_samp_rate(self, rate):
            self.rate = rate
        def get_samp_rate(self):
            return self.rate
        def set_center_freq(self, freq, ch):
            calls[self.role].append(("freq", freq, ch))
        def set_gain(self, gain, ch):
            calls[self.role].append(("gain", gain, ch))
        def set_antenna(self, name, ch):
            calls[self.role].append(("antenna", name, ch))

    class FakeUHD:
        @staticmethod
        def stream_args(**kwargs):
            calls["streams"].append(kwargs)
            return kwargs
        @staticmethod
        def usrp_sink(args, stream):
            assert args == "type=b200"
            return FakeUSRPRadio("tx")
        @staticmethod
        def usrp_source(args, stream):
            assert args == "type=b200"
            return FakeUSRPRadio("rx")

    class FakeGR:
        sizeof_gr_complex = 8
        @staticmethod
        def top_block(name):
            class Graph:
                def connect(self, *nodes):
                    for a, b in zip(nodes, nodes[1:]):
                        calls["edges"].append((a, b))
            calls["blocks"].append(name)
            return Graph()

    class FakeBlocks:
        @staticmethod
        def file_source(size, path, repeat):
            assert repeat is False
            return ("input", path)
        @staticmethod
        def multiply_const_cc(scale):
            return ("scale", scale)
        @staticmethod
        def head(size, samples):
            return ("head", samples)
        @staticmethod
        def file_sink(size, path, flag):
            return ("output", path)

    graph, sink = b210.make_top_block(
        tmp_path / "tx.cf32", tmp_path / "rx.cf32", 2500000,
        240000, 915000000, "type=b200", 0, 20, .15,
        (FakeGR, FakeBlocks, FakeUHD, "3.8.mock"))
    assert len(calls["blocks"]) == 1
    assert len(calls["edges"]) == 4
    assert ("antenna", "TX/RX", 0) in calls["tx"]
    assert ("antenna", "RX2", 0) in calls["rx"]
    assert calls["streams"] == [dict(cpu_format="fc32", channels=[0])]
    assert calls["edges"][0][1][0][0] == "scale"
    assert calls["edges"][1][1][0].role == "tx"
    assert calls["edges"][2][1][0][0] == "head"
    assert calls["edges"][3][1][0][0] == "output"


def test_tx_iq_padding_and_capture_duration(tmp_path):
    stimulus = tmp_path / "source.cf32"
    stimulus.write_bytes(struct.pack("<ff", 0.4, 0.3) * 1024)
    padded = tmp_path / "padded.cf32"
    lead, tail, total = b210.prepare_tx_file(stimulus, padded, 240000, lead_s=1, tail_s=0.5)
    assert (lead, tail, total) == (240000, 120000, 240000 + 1024 + 120000)
    with padded.open("rb") as file:
        assert file.read(16) == b"\0" * 16
        file.seek(lead * 8)
        assert file.read(8) == struct.pack("<ff", 0.4, 0.3)
        file.seek(-8, 2)
        assert file.read(8) == b"\0" * 8
    assert b210.verify_iq_file(stimulus)[1] == 1024
    zero = tmp_path / "zero.cf32"
    zero.write_bytes(b"\0" * 8192)
    with pytest.raises(b210.LoopbackConfigError, match="zeros"):
        b210.verify_iq_file(zero)


def test_b210_action_exposes_only_two_gain_settings():
    import ast
    content = (ROOT / "actions.py").read_text(encoding="utf-8")
    parsed = ast.parse(content)
    schema_assignments = [node for node in parsed.body if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == "ais_b210_loopback_schema"
                                  for target in node.targets)]
    assert len(schema_assignments) == 1
    schema = ast.literal_eval(schema_assignments[0].value)
    gains = [param["name"] for param in schema["params"] if "gain" in param["name"]]
    assert gains == ["tx_gain", "rx_gain"]
    tx_field = next(p for p in schema["params"] if p["name"] == "tx_gain")
    assert tx_field["max"] >= 89 and tx_field["step"] <= 0.5
    names = [param["name"] for param in schema["params"]]
    for removed in ("external_attenuation_db", "isolated_coax_confirmed", "tx_amplitude"):
        assert removed not in names
    assert "rf_frequency" in names


def test_b210_operation_registers_rx_tx_validation_artifacts_without_real_hardware(monkeypatch, tmp_path):
    import asyncio
    import importlib.util
    from test_ais_plugin import import_operations, FakeArtifactManager
    import_operations(monkeypatch)

    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        monkeypatch.setitem(sys.modules, name, module)
        return module

    receiver = load("ais_iq_receive", ROOT / "operations" / "ais_iq_receive.py")
    load("ais_iq_loopback", ROOT / "operations" / "ais_iq_loopback.py")
    hardware = load("test_ais_b210_operation", ROOT / "operations" / "ais_b210_loopback.py")
    manager = FakeArtifactManager(tmp_path)
    callbacks = []

    async def status(msg):
        callbacks.append(msg)

    def create_single_sample(self, path):
        path.write_text("!AIVDM,test-sentence\n", encoding="ascii")
        self._expected_mmsis.add("200000001")
        return 1

    async def mock_call(self, command, timeout, phase):
        args = list(command)
        destination = Path(args[args.index("--output") + 1])
        manifest = Path(args[args.index("--manifest") + 1])
        destination.write_bytes(struct.pack("<ff", 0.5, 0.2) * 1024)
        if "offline" in phase:
            manifest.write_text(json.dumps({"frame_count": 1, "skipped_nmea_sentences": 0,
                                            "rf_transmitted": False}))
        else:
            manifest.write_text(json.dumps({"rf_transmitted": True}))

    async def mock_decode(self):
        assert self._simulated is True and self._simulated_source == "isolated_b210_rf_loopback"
        self._message_count = 1
        self._vessels = {"200000001": {"count": 1}}
        raw = Path(self.iq_file).parent / "receiver.nmea"
        raw.write_text("!AIVDM,test-sentence\n", encoding="ascii")
        self._files["raw"] = raw
        self._received_artifact_id = self.create_artifact(
            files=[str(raw)], name="AIS decoded", artifact_type="ais_nmea_observations",
            metadata=dict(self._input_metadata))

    monkeypatch.setattr(hardware, "require_pyais", lambda: object())
    monkeypatch.setattr(hardware.OperationMain, "_create_nmea", create_single_sample)
    monkeypatch.setattr(hardware.OperationMain, "_call", mock_call)
    monkeypatch.setattr(receiver.OperationMain, "run", mock_decode)
    op = hardware.OperationMain(vessel_count=1, position_updates=1, include_static_data=False,
                                artifact_manager=manager, status_callback=status)
    asyncio.run(op.run())
    assert len(manager.artifacts) == 4
    assert [a[2] for a in manager.artifacts] == [
        "ais_b210_tx_stimulus", "ais_b210_rx_iq", "ais_nmea_observations", "ais_b210_validation"]
    report = manager.artifacts[-1][-1]
    assert report["state"] == "passed" and report["decoded_messages"] == 1
    assert report["rf_lab_transmitted"] is True
    assert manager.artifacts[1][-1]["rf_roundtrip_validation"] == "passed"
    assert manager.relations["artifact-test-2"]
    assert any("verified" in msg for msg in callbacks)


def test_b210_invalid_gain_is_rejected_before_artifacts(monkeypatch, tmp_path):
    import importlib.util
    from test_ais_plugin import import_operations, FakeArtifactManager
    import_operations(monkeypatch)
    def load(name, file):
        spec = importlib.util.spec_from_file_location(name, ROOT / "operations" / (file + ".py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        monkeypatch.setitem(sys.modules, name, module)
        return module
    load("ais_iq_receive", "ais_iq_receive")
    load("ais_iq_loopback", "ais_iq_loopback")
    action = load("ais_b210_loopback_action_test", "ais_b210_loopback")
    manager = FakeArtifactManager(tmp_path)
    op = action.OperationMain(artifact_manager=manager, tx_gain=-1)
    with pytest.raises(ValueError, match="TX gain"):
        import asyncio
        asyncio.run(op.run())
    assert manager.artifacts == []


def test_fissure_dynamic_operation_name_does_not_shadow_rf_helper(monkeypatch):
    """Reproduce SensorNode loading operations/ais_b210_loopback by its filename.

    In v0.6.0 `from ais_b210_loopback import validate_settings` imported the
    Action itself rather than scripts/ais_b210_loopback, failing before UHD.
    """
    import importlib.util
    from test_ais_plugin import import_operations
    import_operations(monkeypatch)
    operation_path = ROOT / "operations" / "ais_b210_loopback.py"
    spec = importlib.util.spec_from_file_location("ais_b210_loopback", operation_path)
    operation = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "ais_b210_loopback", operation)
    spec.loader.exec_module(operation)
    instance = operation.OperationMain()
    assert instance._validate_rf_settings() == 240000
    from ais_b210_rf_hardware import validate_settings
    assert validate_settings(240000, 915e6, 0, 20) == 240000
    instance.rx_gain = 70
    with pytest.raises(ValueError, match="RX gain"):
        instance._validate_rf_settings()


def test_operation_subprocess_uses_distinct_hardware_module():
    action = (ROOT / "operations" / "ais_b210_loopback.py").read_text()
    assert 'spec_from_file_location' in action
    assert '"ais_b210_rf_hardware.py"' in action
    assert '"ais_b210_rf_hardware.py"' in action
    assert (ROOT / "scripts" / "ais_b210_loopback.py").is_file()
    assert (ROOT / "scripts" / "ais_b210_rf_hardware.py").is_file()


def test_dynamic_action_ignores_cached_old_rf_validation(monkeypatch):
    """Regression: an already-running Sensor Node can cache v0.6.1 helper."""
    import importlib.util
    import types
    from test_ais_plugin import import_operations
    import_operations(monkeypatch)
    stale = types.ModuleType("ais_b210_rf_hardware")
    def validate_settings(sample_rate, rf_frequency, tx_gain, rx_gain,
                          attenuation_db, confirmed, device_args=""):
        raise AssertionError("Stale validator must not be used")
    stale.validate_settings = validate_settings
    monkeypatch.setitem(sys.modules, "ais_b210_rf_hardware", stale)
    path = ROOT / "operations" / "ais_b210_loopback.py"
    spec = importlib.util.spec_from_file_location("ais_b210_loopback", path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "ais_b210_loopback", module)
    spec.loader.exec_module(module)
    op = module.OperationMain()
    assert op._validate_rf_settings() == 240000
    assert sys.modules["ais_b210_rf_hardware"] is stale
    op.tx_gain = -1
    with pytest.raises(ValueError, match="TX gain"):
        op._validate_rf_settings()


def test_outdated_rf_helper_on_disk_gets_clear_error(monkeypatch, tmp_path):
    import importlib.util
    from test_ais_plugin import import_operations
    import_operations(monkeypatch)
    path = ROOT / "operations" / "ais_b210_loopback.py"
    spec = importlib.util.spec_from_file_location("ais_b210_loopback_fresh_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    obsolete_dir = tmp_path / "Plugins" / "AIS" / "scripts"
    obsolete_dir.mkdir(parents=True)
    (obsolete_dir / "ais_b210_rf_hardware.py").write_text(
        "def validate_settings(sample_rate, rf_frequency, tx_gain, rx_gain, attenuation_db, confirmed):\n"
        "    return sample_rate\n", encoding="utf-8")
    monkeypatch.setattr(module, "PLUGIN_ROOT", obsolete_dir.parent)
    with pytest.raises(RuntimeError, match="Outdated AIS B210 hardware helper"):
        module.OperationMain()._validate_rf_settings()
