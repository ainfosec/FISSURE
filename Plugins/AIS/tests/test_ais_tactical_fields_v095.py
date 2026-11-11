"""Action schemas expose operational controls but retain engine default behavior."""
import ast
from pathlib import Path

AIS = Path(__file__).resolve().parents[1]

HIDDEN = {
    'ais_nmea_udp_simulate': {'send_udp': True},
    'ais_iq_file_decode': {'decoder_timeout_s': 300},
    'ais_iq_offline_loopback': {'include_static_data': True, 'sample_rate': 240000, 'gap_ms': 350, 'emit_targets': True},
    'ais_b210_loopback': {'include_static_data': True, 'sample_rate': 240000, 'gap_ms': 350, 'emit_targets': True},
    'ais_usrp_b210_transmit': {'include_static_data': True, 'sample_rate': 240000, 'gap_ms': 350, 'repeat_pause_s': 2.0, 'save_tx_artifact': False},
    'ais_usrp_b210_receive': {'sample_rate': 240000, 'simulated_input': False, 'detection_interval_s': 5},
    'ais_hackrf_transmit': {'include_static_data': True, 'gap_ms': 350, 'repeat_pause_s': 2.0, 'save_tx_artifact': False},
    'ais_hackrf_receive': {'simulated_input': False, 'detection_interval_s': 5},
    'ais_rtlsdr_receive': {'simulated_input': False, 'detection_interval_s': 5},
}

KEEP = {
    'ais_usrp_b210_transmit': {'rf_frequency', 'tx_gain', 'vessel_count', 'position_updates', 'repeat_count', 'base_latitude', 'base_longitude', 'serial_number', 'rf_channel'},
    'ais_hackrf_transmit': {'rf_frequency', 'tx_gain', 'repeat_count', 'vessel_count', 'position_updates', 'device_args'},
    'ais_usrp_b210_receive': {'duration_s','rf_frequency','rx_gain','emit_targets','serial_number','rf_channel','rx_antenna'},
    'ais_hackrf_receive': {'duration_s','rf_frequency','lna_gain','vga_gain','emit_targets','device_args'},
    'ais_rtlsdr_receive': {'duration_s','rf_frequency','rx_gain','emit_targets','device_args'},
    'ais_nmea_udp_file_receive': {'input_mode','source_file','listen_host','listen_port','duration_s'},
}

OPERATION_MODULE = {
 'ais_nmea_udp_simulate':'ais_simulate',
 'ais_iq_file_decode':'ais_iq_receive',
 'ais_iq_offline_loopback':'ais_iq_loopback',
 'ais_b210_loopback':'ais_b210_loopback',
 'ais_usrp_b210_transmit':'ais_sdr_transmit',
 'ais_usrp_b210_receive':'ais_sdr_receive',
 'ais_hackrf_transmit':'ais_hackrf_transmit',
 'ais_hackrf_receive':'ais_hackrf_receive',
 'ais_rtlsdr_receive':'ais_rtlsdr_receive',
}

def action_schemas():
    tree = ast.parse((AIS / 'actions.py').read_text())
    return {n.targets[0].id.removesuffix('_schema'): ast.literal_eval(n.value)['params']
            for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and
            isinstance(n.targets[0],ast.Name) and n.targets[0].id.endswith('_schema')}

def operation_defaults(action):
    tree=ast.parse((AIS/'operations'/ (OPERATION_MODULE[action]+'.py')).read_text())
    cls=next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'OperationMain')
    init=next(n for n in cls.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=='__init__')
    args=init.args.args
    return {arg.arg: ast.literal_eval(value) for arg,value in zip(args[-len(init.args.defaults):],init.args.defaults)
            if isinstance(value,(ast.Constant,ast.UnaryOp))}

def test_streamlined_fields_preserve_the_engine_defaults():
    actions=action_schemas()
    assert len(actions)==10
    for action, hidden in HIDDEN.items():
        names={p['name'] for p in actions[action]}
        defaults=operation_defaults(action)
        for name,expected in hidden.items():
            assert name not in names,(action,name)
            assert defaults[name] == expected,(action,name,defaults.get(name))


def test_important_operator_controls_still_available():
    actions=action_schemas()
    for action, important in KEEP.items():
        names={p['name'] for p in actions[action]}
        assert important <= names,(action,important-names)
    for action in ('ais_usrp_b210_transmit','ais_hackrf_transmit'):
        assert next(p for p in actions[action] if p['name']=='repeat_count')['default']==0
    for action in ('ais_usrp_b210_receive','ais_hackrf_receive','ais_rtlsdr_receive'):
        assert next(p for p in actions[action] if p['name']=='duration_s')['default']==0


def test_hidden_controls_can_still_be_passed_to_operation_constructors():
    for action,hidden in HIDDEN.items():
        defaults=operation_defaults(action)
        assert set(hidden) <= set(defaults)
