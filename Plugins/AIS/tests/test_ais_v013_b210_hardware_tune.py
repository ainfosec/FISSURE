"""B210 manual low-level UHD tune helper and automatic live receive regression."""
from pathlib import Path
import sys
import types

import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import ais_live_decoder as live


class Radio:
    def __init__(self):
        self.calls=[]
    def set_rx_subdev_spec(self,x): self.calls.append(('subdev',x))
    def set_samp_rate(self,x): self.calls.append(('rate',x)); self.rate=x
    def get_samp_rate(self): return self.rate
    def set_center_freq(self,x,ch): self.calls.append(('freq',x,ch)); self.freq=x
    def get_center_freq(self,ch): return self.freq
    def set_gain(self,x,ch): self.calls.append(('gain',x,ch))
    def set_antenna(self,x,ch): self.calls.append(('antenna',x,ch))


def test_uhd_b210_tuner_915m_minus3k(capsys):
    rx=Radio()
    uhd=types.SimpleNamespace(usrp_source=lambda *a: rx, stream_args=lambda **kw:'args')
    out=live.make_b210_source(uhd,240000,915000000,70,'type=b200',
                              rf_channel=0,rx_antenna='TX/RX',rf_tune_offset_hz=-3000)
    assert out is rx
    assert ('freq',914997000.0,0) in rx.calls
    assert 'actual=914997000 Hz' in capsys.readouterr().err


def test_uhd_b210_tuner_zero_offset():
    rx=Radio()
    uhd=types.SimpleNamespace(usrp_source=lambda *a: rx, stream_args=lambda **kw:'args')
    live.make_b210_source(uhd,240000,162000000,70,'type=b200')
    assert ('freq',162000000.0,0) in rx.calls


@pytest.mark.parametrize('minor', [10, 8])
def test_live_receiver_uses_nominal_hardware_tune_and_automatic_afc(monkeypatch, minor):
    observed={}
    gr=types.SimpleNamespace()
    uhd=types.SimpleNamespace()
    pkg=types.ModuleType('gnuradio')
    pkg.gr=gr; pkg.uhd=uhd
    monkeypatch.setitem(sys.modules,'gnuradio',pkg)
    monkeypatch.setattr(live,'gr_minor_version',lambda g:(minor,'3.%d.x'%minor))
    monkeypatch.setattr(live,'resolve_ais_module',lambda m:'ais')
    monkeypatch.setattr(live,'make_b210_source',lambda *args,**kw: observed.update(tuned=kw['rf_tune_offset_hz']) or 'source')
    class Graph:
        def start(self): pass
        def wait(self): pass
    def make_tb(*args,**kw):
        observed['dsp']=kw['frequency_correction_hz']
        observed['auto']=kw['automatic_frequency_recovery']
        return Graph()
    monkeypatch.setattr(live,'make_top_block',make_tb)
    assert live.main(['--source','b210','--rf-frequency','915000000'])==0
    assert observed['tuned']==0
    assert observed['dsp']==0
    assert observed['auto'] is (minor==10)
