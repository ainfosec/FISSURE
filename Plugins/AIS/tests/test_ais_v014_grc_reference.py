"""GNU Radio 3.10 B210 reference receiver regression tests."""
from pathlib import Path
from types import SimpleNamespace
import sys
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def test_receiver_rotator_matches_working_grc(monkeypatch):
    from test_ais_gr310_b210_v097 import install_fake_gr310
    record, ais = install_fake_gr310(monkeypatch)
    from gnuradio import blocks
    def rotator(*args):
        record.append(('rotator', args))
        return 'rotator'
    blocks.rotator_cc = rotator
    from ais_gr310_receiver import make_receiver
    a = make_receiver(-25000, 200000, 'A', ais, loop_bw=0.033, channelizer='rotator')
    b = make_receiver(25000, 200000, 'B', ais, loop_bw=0.033, channelizer='rotator')
    assert len(a.connections) == 1 and len(b.connections) == 1
    assert not any(kind == 'freq_filter' for kind, _ in record)
    rates = [v[0] for kind, v in record if kind == 'resampler']
    assert rates == pytest.approx([38400/200000]*2)
    rotations = [v[0] for kind, v in record if kind == 'rotator']
    import math
    assert rotations == pytest.approx([2*math.pi*25000/200000,
                                      -2*math.pi*25000/200000])
    timing = [v[2] for kind, v in record if kind == 'symbolsync']
    assert timing == pytest.approx([0.033, 0.033])


def test_grc_reference_invalid_profile(monkeypatch):
    from test_ais_gr310_b210_v097 import install_fake_gr310
    _,ais=install_fake_gr310(monkeypatch)
    from ais_gr310_receiver import make_receiver
    with pytest.raises(ValueError, match='channelizer'):
        make_receiver(-25000, 200000, 'A', ais, channelizer='what')


def test_b210_310_decoder_uses_standalone_grc_profile(monkeypatch):
    import ais_live_decoder as live
    from types import ModuleType
    import sys
    gnuradio=ModuleType('gnuradio')
    gnuradio.gr=object()
    gnuradio.uhd=object()
    monkeypatch.setitem(sys.modules,'gnuradio',gnuradio)
    monkeypatch.setattr(live, 'gr_minor_version', lambda gr:(10,'3.10.test'))
    monkeypatch.setattr(live, 'resolve_ais_module', lambda minor:'ais')
    seen={}
    def hardware(uhd, rate, center, gain, device_args, rf_channel, antenna, rf_tune_offset_hz):
        seen.update(rate=rate, center=center, offset=rf_tune_offset_hz)
        return 'source'
    monkeypatch.setattr(live, 'make_b210_source',hardware)
    class Graph:
        def start(self): pass
        def wait(self): pass
    def top(*args,**kwargs):
        seen.update(graph_rate=args[1], profile=kwargs.get('receiver_profile'),
                    bw=kwargs.get('loop_bandwidth'), correction=kwargs['frequency_correction_hz'],
                    auto=kwargs['automatic_frequency_recovery'])
        return Graph()
    monkeypatch.setattr(live,'make_top_block',top)
    assert live.main(['--source','b210','--rf-frequency','915000000'])==0
    assert seen == dict(rate=200000.0, center=915000000.0, offset=0.0,
                        graph_rate=200000.0, profile='grc_reference',
                        bw=0.033, correction=0, auto=True)


def test_38_b210_preserves_old_rate_chain(monkeypatch):
    import ais_live_decoder as live
    from types import ModuleType
    gnuradio=ModuleType('gnuradio')
    gnuradio.gr=object()
    gnuradio.uhd=object()
    monkeypatch.setitem(sys.modules,'gnuradio',gnuradio)
    monkeypatch.setattr(live,'gr_minor_version',lambda gr:(8,'3.8.test'))
    monkeypatch.setattr(live,'resolve_ais_module',lambda minor:'ais')
    seen={}
    def hardware(uhd, rate, center, gain, device_args, rf_channel, antenna, rf_tune_offset_hz):
        seen.update(rate=rate, offset=rf_tune_offset_hz)
        return 'source'
    monkeypatch.setattr(live,'make_b210_source',hardware)
    class Graph:
        def start(self):pass
        def wait(self):pass
    def top(*args,**kwargs):
        seen.update(graph_rate=args[1],profile=kwargs.get('receiver_profile'),
                    correction=kwargs['frequency_correction_hz'],
                    auto=kwargs['automatic_frequency_recovery'])
        return Graph()
    monkeypatch.setattr(live,'make_top_block',top)
    assert live.main(['--source','b210','--rf-frequency','915000000'])==0
    assert seen == dict(rate=240000.0,offset=0.0,
                        graph_rate=240000.0,profile=None,correction=0,auto=False)


def test_b210_summary_includes_decoder_and_uhd_tuner_metadata(tmp_path):
    from ais_monitor_summary_v084 import create_monitor_summary
    class Manager:
        def create_operation_dir(self,oid):
            return oid, str(tmp_path)
    class Op:
        opid='test';node_uid='node';artifact_manager=Manager()
        _vessels={}; _message_count=0; _simulated=True
        duration_s=20
        _b210_uhd_tune_text='AIS B210 RX UHD tune: actual=915000000 Hz'
        _decoder_start_text='AIS streaming decoder started: effective_sample_rate_hz=200000'
        def create_artifact(self,**kwargs):return 'artifact'
    assert create_monitor_summary(Op(),'b210',0,'finished',streaming=True)=='artifact'
    import json
    data=json.loads((tmp_path/'ais_b210_monitor_summary.json').read_text())
    assert '915000000' in data['metadata']['b210_uhd_tuning']
    assert '200000' in data['metadata']['decoder_configuration']
    assert data['metadata']['raw_iq_archived'] is False
