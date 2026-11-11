"""Legacy gain presets and new automatic RX calibration defaults."""
import ast
from pathlib import Path
import importlib.util
import sys

ROOT = Path(__file__).resolve().parents[1]


def schema_params(name):
    tree = ast.parse((ROOT / 'actions.py').read_text())
    schema = next(ast.literal_eval(n.value) for n in tree.body
                  if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    return {p['name']: p for p in schema['params']}


def test_no_receiver_exposes_manual_frequency_correction():
    for action in ('ais_usrp_b210_receive_schema','ais_hackrf_receive_schema','ais_rtlsdr_receive_schema'):
        assert 'frequency_correction_hz' not in schema_params(action)


def test_hackrf_tx_schema_defaults_to_40_db():
    gain = schema_params('ais_hackrf_transmit_schema')['tx_gain']
    assert gain['default'] == 40
    assert gain['min'] <= 40 <= gain['max']


def test_b210_stream_command_uses_nominal_rf_center_without_manual_offset():
    from types import SimpleNamespace
    script_path = str(ROOT / 'scripts')
    if script_path not in sys.path:
        sys.path.insert(0, script_path)
    from ais_stream_runtime_v090 import build_stream_command
    op = SimpleNamespace(sample_rate=240000, rf_frequency=915000000,
                         device_args='type=b200', rx_gain=70,
                         rf_channel='0', rx_antenna='TX/RX')
    cmd = build_stream_command(op, 'b210')
    assert cmd[cmd.index('--rf-frequency') + 1] == '915000000'
    assert '--frequency-correction-hz' not in cmd


def test_b210_receive_constructor_has_no_manual_offset(monkeypatch):
    # FISSURE package imports are substituted by the established test helper.
    from test_ais_plugin import import_operations
    import_operations(monkeypatch)
    spec = importlib.util.spec_from_file_location('v012_b210', ROOT / 'operations' / 'ais_usrp_b210_receive.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Test with defaults; do not start SDR hardware.
    default = mod.OperationMain()
    assert not hasattr(default, 'frequency_correction_hz')


def test_hackrf_tx_constructor_default_and_manual_override(monkeypatch):
    from test_ais_plugin import import_operations
    import_operations(monkeypatch)
    spec = importlib.util.spec_from_file_location('v012_hackrf_tx', ROOT / 'operations' / 'ais_hackrf_transmit.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.OperationMain().tx_gain == 40
    assert mod.OperationMain(tx_gain=10).tx_gain == 10
