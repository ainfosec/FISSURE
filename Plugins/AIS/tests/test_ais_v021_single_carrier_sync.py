"""Live GNU Radio 3.10 retains a single carrier-corrected receiver.

Only static graph wiring and mocked blocks are tested here.  Successful
carrier acquisition still requires actual SDR/GNU Radio hardware testing.
"""
from pathlib import Path
import sys
import types
import ast
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def test_single_burst_aware_carrier_recovery_block_per_channel(monkeypatch):
    from test_ais_gr310_b210_v097 import install_fake_gr310
    recorded, ais = install_fake_gr310(monkeypatch)
    from gnuradio import blocks
    blocks.rotator_cc = lambda *args: 'rotator'
    import ais_burst_carrier_sync_v0922 as sync_module
    def sync(*args):
        recorded.append(('carrier_sync', args))
        return 'carrier_sync'
    monkeypatch.setattr(sync_module, 'make_sync', sync)
    from ais_gr310_receiver import make_receiver
    rx = make_receiver(-25000, 200000, 'A', ais, loop_bw=0.033,
                       channelizer='rotator', carrier_sync=True)
    assert ('carrier_sync', (sys.modules['gnuradio'].gr, 'A')) in recorded
    chain = rx.connections[0]
    assert chain[1] == 'rotator'
    assert chain[2] == 'resampler'
    assert chain[3] == 'carrier_sync'
    assert chain[4] == 'post_filter'
    assert chain[5] == 'agc'
    assert len(chain) == 14  # one decoder, plus post-CFO narrow filter


def test_burst_recovery_needs_no_native_square_fft_block(monkeypatch):
    from test_ais_gr310_b210_v097 import install_fake_gr310
    _, ais = install_fake_gr310(monkeypatch)
    from gnuradio import blocks
    blocks.rotator_cc = lambda *args: 'rotator'
    import ais_burst_carrier_sync_v0922 as sync_module
    monkeypatch.setattr(sync_module, 'make_sync', lambda *args: 'carrier_sync')
    assert not hasattr(ais, 'square_and_fft_sync_cc')
    from ais_gr310_receiver import make_receiver
    rx = make_receiver(-25000, 200000, 'A', ais, carrier_sync=True)
    assert rx.carrier_sync == 'carrier_sync'


def test_live_310_connects_only_two_receivers_without_afc(monkeypatch):
    import ais_iq_decoder as decoder
    import ais_gr310_receiver as core
    class FakeTB:
        def __init__(self, *args):
            self.connections = []
        def connect(self, *args):
            self.connections.append(args)
    gnuradio = types.ModuleType('gnuradio')
    gnuradio.gr = types.SimpleNamespace(top_block=FakeTB)
    gnuradio.blocks = types.SimpleNamespace()
    monkeypatch.setitem(sys.modules, 'gnuradio', gnuradio)
    seen = []
    def receiver(*args, **kwargs):
        seen.append((args, kwargs))
        return 'receiver_' + args[2]
    monkeypatch.setattr(core, 'make_receiver', receiver)
    graph = decoder.make_top_block(None, 200000, 162000000, 'both', 10,
                  types.SimpleNamespace(pdu_to_nmea=lambda *_:None),
                  source='iq_source', receiver_profile='grc_reference',
                  automatic_frequency_recovery=True)
    assert graph.connections == [(('iq_source',0),('receiver_A',0)),
                                 (('iq_source',0),('receiver_B',0))]
    assert len(graph._fissure_owned_blocks) == 3
    assert [options['carrier_sync'] for _, options in seen] == [True, True]
    assert all(options['channelizer'] == 'rotator' for _, options in seen)


def test_gr38_path_unchanged(monkeypatch):
    import ais_iq_decoder as decoder
    class FakeTB:
        def __init__(self,*args): self.connections=[]
        def connect(self,*args): self.connections.append(args)
    gnuradio=types.ModuleType('gnuradio')
    gnuradio.gr=types.SimpleNamespace(top_block=FakeTB)
    gnuradio.blocks=types.SimpleNamespace()
    monkeypatch.setitem(sys.modules,'gnuradio',gnuradio)
    called=[]
    def old_receiver(offset, rate, channel):
        called.append((offset,rate,channel))
        return channel
    graph=decoder.make_top_block(None,240000,162000000,'both',8,
                                  types.SimpleNamespace(ais_rx=old_receiver),
                                  source='iq_source',automatic_frequency_recovery=False)
    assert len(graph.connections) == 2
    assert called==[(-25000.0,240000,'A'),(25000.0,240000,'B')]


def test_ui_has_no_correction_setting_and_python_afc_unused():
    tree=ast.parse((ROOT/'actions.py').read_text())
    for name in ('ais_usrp_b210_receive_schema','ais_hackrf_receive_schema',
                 'ais_rtlsdr_receive_schema'):
        node=next(n for n in tree.body if isinstance(n,ast.Assign) and
                  any(isinstance(t,ast.Name) and t.id==name for t in n.targets))
        params=ast.literal_eval(node.value)['params']
        assert all('correction' not in item['name'] for item in params)
    assert not (ROOT/'scripts'/'ais_auto_frequency_v016.py').exists()
    assert 'make_afc_block' not in (ROOT/'scripts'/'ais_iq_decoder.py').read_text()
