"""No-RF regression tests for standalone AIS B210 TX and RX Actions."""
import ast
import asyncio
import importlib.util
import json
import types
from pathlib import Path
import struct
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ais_sdr_hardware as hardware


def test_standalone_hardware_import_ignores_stale_b210_module(monkeypatch):
    """Reproduce the user's long-running Sensor Node module-cache failure.

    The previous B210 helper is kept in sys.modules, while the installed v0.7
    file on disk provides the current TX_DIGITAL_SCALE helper interface.
    """
    stale = types.ModuleType("ais_b210_rf_hardware")
    stale.validate_settings = lambda *args: None
    monkeypatch.setitem(sys.modules, "ais_b210_rf_hardware", stale)
    spec = importlib.util.spec_from_file_location(
        "_fissure_sdr_fresh_import_test", ROOT / "scripts" / "ais_sdr_hardware.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.TX_DIGITAL_SCALE == 0.15
    assert module._b210_helper is not stale
    assert callable(module.probe)
    assert module.validate_rx(240000, 162e6, 70, "type=b200", 20) == 240000
    assert sys.modules["ais_b210_rf_hardware"] is stale


def test_sensor_node_rx_and_tx_action_import_with_stale_b210(monkeypatch):
    """Both standalone FISSURE operation modules must import without UHD access."""
    from test_ais_plugin import import_operations
    import_operations(monkeypatch)
    _load(monkeypatch, "ais_iq_receive")
    _load(monkeypatch, "ais_iq_loopback")
    stale = types.ModuleType("ais_b210_rf_hardware")
    stale.validate_settings = lambda *args, **kwargs: None
    monkeypatch.setitem(sys.modules, "ais_b210_rf_hardware", stale)
    # Simulate an import under the already running Sensor Node, not an
    # isolated Python interpreter after a full FISSURE restart.
    monkeypatch.delitem(sys.modules, "ais_sdr_hardware", raising=False)
    rx = _load(monkeypatch, "ais_sdr_receive")
    tx = _load(monkeypatch, "ais_sdr_transmit")
    assert rx.OperationMain().rx_gain == 70
    assert tx.OperationMain().tx_gain == 60
    assert sys.modules["ais_b210_rf_hardware"] is stale


def test_action_defaults_and_standalone_routes():
    tree = ast.parse((ROOT / "actions.py").read_text())
    def schema(name):
        node = next(n for n in tree.body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
        return {row["name"]: row for row in ast.literal_eval(node.value)["params"]}
    loop = schema("ais_b210_loopback_schema")
    tx = schema("ais_usrp_b210_transmit_schema")
    rx = schema("ais_usrp_b210_receive_schema")
    assert loop["tx_gain"]["default"] == 40
    assert loop["rx_gain"]["default"] == 40
    assert tx["tx_gain"]["default"] == 60
    assert rx["rx_gain"]["default"] == 70
    assert tx["rf_frequency"]["default"] == 915000000
    assert rx["rf_frequency"]["default"] == 162000000
    assert "rx_gain" not in tx and "tx_gain" not in rx
    assert "external_attenuation_db" not in loop
    assert "isolated_coax_confirmed" not in loop
    for op in ("ais_usrp_b210_transmit", "ais_usrp_b210_receive"):
        assert (ROOT / "operations" / (op + ".py")).exists()


def test_separate_hardware_validators():
    assert hardware.validate_tx(240000, 915e6, 60, "type=b200") == 240000
    assert hardware.validate_rx(240000, 162e6, 70, "type=b200", 20) == 240000
    with pytest.raises(ValueError, match="non-maritime"):
        hardware.validate_tx(240000, 162e6, 60, "type=b200")
    with pytest.raises(ValueError, match="duration"):
        hardware.validate_rx(240000, 162e6, 70, "type=b200", 300)
    with pytest.raises(ValueError, match="TX gain"):
        hardware.validate_tx(240000, 915e6, -1, "type=b200")


def test_distinct_uhd_tx_and_rx_graphs(tmp_path):
    calls = {"edges": [], "tx": [], "rx": [], "sources": 0, "sinks": 0}

    class Radio:
        def __init__(self, role): self.role = role
        def set_samp_rate(self, rate): self.rate = rate
        def get_samp_rate(self): return self.rate
        def set_center_freq(self, freq, chan): calls[self.role].append(("freq", freq, chan))
        def set_gain(self, gain, chan): calls[self.role].append(("gain", gain, chan))
        def set_antenna(self, antenna, chan): calls[self.role].append(("port", antenna, chan))

    class UHD:
        @staticmethod
        def stream_args(**kwargs): return kwargs
        @staticmethod
        def usrp_sink(dev, stream): calls["sinks"] += 1; return Radio("tx")
        @staticmethod
        def usrp_source(dev, stream): calls["sources"] += 1; return Radio("rx")

    class GR:
        sizeof_gr_complex = 8
        @staticmethod
        def top_block(name):
            class TB:
                def connect(self, *args): calls["edges"].append(args)
            return TB()

    class Blocks:
        @staticmethod
        def file_source(*args): return "file_source"
        @staticmethod
        def multiply_const_cc(*args): return "scale"
        @staticmethod
        def head(*args): return "head"
        @staticmethod
        def file_sink(*args): return "file_sink"

    fake = (GR, Blocks, UHD, "3.8.fake")
    hardware.make_tx_graph(tmp_path / "tx.cf32", 240000, 915e6, "type=b200", 60, fake)
    assert calls["sinks"] == 1 and calls["sources"] == 0
    assert len(calls["edges"]) == 1
    assert len(calls["edges"][0]) == 3
    assert ("port", "TX/RX", 0) in calls["tx"]
    hardware.make_rx_graph(tmp_path / "rx.cf32", 240000, 240000, 162e6, "type=b200", 70, fake)
    assert calls["sinks"] == 1 and calls["sources"] == 1
    assert ("port", "TX/RX", 0) in calls["rx"]
    assert len(calls["edges"]) == 2  # Two single-direction graphs, not a combined TX/RX graph


def _load(monkeypatch, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "operations" / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, mod)
    spec.loader.exec_module(mod)
    return mod


def _imports(monkeypatch):
    from test_ais_plugin import import_operations
    import_operations(monkeypatch)
    _load(monkeypatch, "ais_iq_receive")
    _load(monkeypatch, "ais_iq_loopback")
    return _load(monkeypatch, "ais_sdr_transmit"), _load(monkeypatch, "ais_sdr_receive")


def test_standalone_transmitter_registers_artifacts_no_receiver(monkeypatch, tmp_path):
    from test_ais_plugin import FakeArtifactManager
    tx_mod, _ = _imports(monkeypatch)
    monkeypatch.setattr(tx_mod, "require_pyais", lambda: object())
    manager = FakeArtifactManager(tmp_path)

    def nmea(self, filename):
        filename.write_text("!AIVDM,1,1,,A,12vg20@P0tG?pF0EWrD1GQ600000,0*19\n")
        return 1

    async def proc(self, command, timeout, label, cwd):
        args = list(command)
        manifest = Path(args[args.index("--manifest") + 1])
        if "IQ generation" in label:
            Path(args[args.index("--output") + 1]).write_bytes(struct.pack("<ff", .4, .3) * 4000)
            manifest.write_text(json.dumps({"frame_count": 1, "skipped_nmea_sentences": 0}))
        else:
            assert "--mode" in args and args[args.index("--mode") + 1] == "tx"
            assert args[args.index("--tx-gain") + 1] == "60.0"
            manifest.write_text(json.dumps({"rf_transmitted": True, "transmitted_samples": 4000}))
        return "mock completed"

    monkeypatch.setattr(tx_mod.OperationMain, "_create_nmea", nmea)
    monkeypatch.setattr(tx_mod.OperationMain, "call_sdr_process", proc)
    op = tx_mod.OperationMain(artifact_manager=manager, repeat_count=1)
    asyncio.run(op.run())
    assert not manager.artifacts  # TX Artifacts default to off in v0.8.0


def test_standalone_receiver_uses_streaming_with_no_iq_artifact(monkeypatch, tmp_path):
    from test_ais_plugin import FakeArtifactManager
    _, rx_mod = _imports(monkeypatch)
    manager = FakeArtifactManager(tmp_path)
    called=[]
    async def stream(op, radio):
        called.append((op, radio, op.duration_s))
        assert op._simulated is True
        assert not hasattr(op, 'frequency_correction_hz')
    monkeypatch.setitem(rx_mod.OperationMain.run.__globals__, 'run_stream_monitor', stream)
    op = rx_mod.OperationMain(duration_s=20, artifact_manager=manager,
                              simulated_input='true')
    asyncio.run(op.run())
    assert called == [(op, 'b210', 20)]
    assert not hasattr(op, '_capture_and_decode')
    assert manager.artifacts == []
    assert not list(tmp_path.rglob('*.cf32'))
