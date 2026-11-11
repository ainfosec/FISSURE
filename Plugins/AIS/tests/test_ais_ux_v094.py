"""AIS plugin UI parameter schema regressions (no hardware needed)."""
import ast
from pathlib import Path

AIS = Path(__file__).resolve().parents[1]


def schemas():
    tree = ast.parse((AIS / 'actions.py').read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(x, ast.Name) and x.id.endswith('_schema') for x in node.targets):
            data = ast.literal_eval(node.value)
            for row in data.get('params', []):
                yield row


def test_labels_fit_narrow_action_form():
    rows = list(schemas())
    assert len(rows) >= 60  # Simplified tactical forms; v0.9.5
    assert all(len(row.get('label', '')) <= 18 for row in rows)
    assert all(row.get('description') for row in rows)


def test_integer_parameters_use_integer_spinboxes_when_supported():
    byname = {}
    for row in schemas():
        byname.setdefault(row.get('name'), []).append(row)
    for name in ('vessel_count', 'position_updates', 'duration_s', 'repeat_count', 'listen_port'):
        assert all(row['type'] == 'integer' for row in byname[name]), name
    # USRP B210 TX gain is 0.5-dB stepping; do not cast away that precision.
    assert any(row['type'] == 'number' and row['step'] == 0.5 for row in byname['tx_gain'])
    # >2^31 RF frequency limits must stay QDoubleSpinBox, but present whole Hz.
    assert all(row.get('decimals') == 0 for row in byname['rf_frequency'])
