"""Specific GNU Radio 3.10 bkerler block and B210 selectors regressions."""
from pathlib import Path
import sys
import types
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'operations'))

from ais_b210_frontend_v097 import make_device_args, channel_details, configure_subdevice, validate_antenna
from ais_gr310_receiver import make_receiver, validate_backend


def test_b210_serial_args():
    assert make_device_args() == 'type=b200'
    assert make_device_args('type=b200', '32AB01') == 'type=b200,serial=32AB01'
    assert make_device_args('type=b200,serial=old', 'NEW') == 'type=b200,serial=NEW'
    with pytest.raises(ValueError):
        make_device_args(serial_number='invalid,serial')


@pytest.mark.parametrize('choice, expected', [
    (0, (0,'A:A')),('0 (A:A)',(0,'A:A')),(1,(1,'A:B')),('1 (A:B)',(1,'A:B'))
])
def test_channels(choice, expected):
    assert channel_details(choice) == expected


def test_antenna_choices():
    assert validate_antenna() == 'TX/RX'
    assert validate_antenna('RX2') == 'RX2'
    with pytest.raises(ValueError):
        validate_antenna('UNKNOWN')


def test_rf_channel_configures_uhd_frontend():
    class Radio:
        def __init__(self): self.calls=[]
        def set_rx_subdev_spec(self, value): self.calls.append(('rx',value))
        def set_tx_subdev_spec(self, value): self.calls.append(('tx',value))
    radio=Radio()
    configure_subdevice(radio,'rx','1 (A:B)')
    configure_subdevice(radio,'tx','0 (A:A)')
    assert radio.calls == [('rx','A:B'),('tx','A:A')]


def install_fake_gr310(monkeypatch):
    """Model the real block APIs used by bkerler's apps/ais_demod.grc."""
    recorded=[]
    class GRBlock:
        def __init__(self, *args, **kwargs):
            self.connections=[]
            self.messages=[]
        def connect(self,*args): self.connections.append(args)
        def msg_connect(self,*args): self.messages.append(args)
    class GR:
        hier_block2=GRBlock
        sizeof_gr_complex=8
        io_signature=staticmethod(lambda *args: ('sig',args))
    class FakeModulator:
        def to_basic_block(self): return 'modulator-basic'
    class FakeConstellation:
        def base(self): return 'constellation-basic'
    def factory(name, result=None):
        def make(*args, **kwargs):
            recorded.append((name, args))
            return name if result is None else result
        return make
    firdes=types.SimpleNamespace(low_pass=factory('low_pass'))
    pfb=types.SimpleNamespace(arb_resampler_ccf=factory('resampler'))
    filt=types.SimpleNamespace(
        firdes=firdes,
        pfb=pfb,
        freq_xlating_fir_filter_ccf=factory('freq_filter'),
        fir_filter_ccf=factory('post_filter'))
    analog=types.SimpleNamespace(
        cpm=types.SimpleNamespace(GAUSSIAN='gaussian'),
        agc3_cc=factory('agc'), quadrature_demod_cf=factory('fm'))
    blocks=types.SimpleNamespace(not_bb=factory('invert'),
        add_const_bb=factory('fixbits'))
    digital=types.SimpleNamespace(
        cpmmod_bc=factory('cpmmod', FakeModulator()),
        modulate_vector_bc=factory('modulatedpreamble'),
        corr_est_cc=factory('correlator'),
        symbol_sync_cc=factory('symbolsync'),
        hdlc_deframer_bp=factory('deframer'),
        binary_slicer_fb=factory('slicer'),
        diff_decoder_bb=factory('diff'),
        constellation_bpsk=factory('constellation', FakeConstellation()),
        TED_DANDREA_AND_MENGALI_GEN_MSK='ted_msk',
        THRESHOLD_ABSOLUTE='absolute',
        IR_MMSE_8TAP='mmse8', DIFF_DIFFERENTIAL='differential')
    fft=types.SimpleNamespace(window=types.SimpleNamespace(WIN_HANN='hann'))
    gnuradio=types.ModuleType('gnuradio')
    gnuradio.gr, gnuradio.filter,gnuradio.digital=GR,filt,digital
    gnuradio.analog,gnuradio.blocks,gnuradio.fft=analog,blocks,fft
    monkeypatch.setitem(sys.modules,'gnuradio',gnuradio)
    monkeypatch.setitem(sys.modules,'gnuradio.filter',filt)
    monkeypatch.setitem(sys.modules,'gnuradio.fft',fft)
    ais=types.SimpleNamespace(
        pdu_to_nmea=factory('nmea'),
        __file__='/usr/local/lib/python3.12/dist-packages/gnuradio/ais/__init__.py')
    return recorded, ais


def test_gr310_bkerler_receiver_builds_actual_grc_chain(monkeypatch):
    recorded, ais = install_fake_gr310(monkeypatch)
    assert validate_backend(ais) == 'bkerler_core'
    rx=make_receiver(-25000,240000,'A',ais)
    assert len(rx.connections)==1
    assert len(rx.connections[0])==12  # input + 11 blocks
    assert len(rx.messages)==1
    assert rx.messages[0][1:] == ('out','nmea','print')
    fil=next(value for kind,value in recorded if kind=='freq_filter')
    assert fil[0] == 5
    assert fil[2] == -25000
    resample=next(value for kind,value in recorded if kind=='resampler')
    assert resample[0] == pytest.approx(0.8)
    assert resample[2] == 64
    mod=next(value for kind,value in recorded if kind=='cpmmod')
    assert mod == ('gaussian', 0.5, 4, 4, 0.4)
    preamble=next(value for kind,value in recorded if kind=='modulatedpreamble')
    assert preamble[0]=='modulator-basic'
    assert preamble[1]==[1,1,255,255]*7
    corr=next(value for kind,value in recorded if kind=='correlator')
    assert corr == ('modulatedpreamble', 4, 6, 0.83, 'absolute')
    timing=next(value for kind,value in recorded if kind=='symbolsync')
    assert timing[0]=='ted_msk' and timing[1]==4
    assert timing[2]==pytest.approx(0.05)
    assert next(value for kind,value in recorded if kind=='diff') == (2,'differential')
    assert next(value for kind,value in recorded if kind=='fixbits') == (2,)
    assert next(value for kind,value in recorded if kind=='nmea') == ('A',)


def test_gr310_bkerler_core_second_channel(monkeypatch):
    recorded, ais=install_fake_gr310(monkeypatch)
    make_receiver(25000,200000,'B',ais)
    assert next(value for kind,value in recorded if kind=='freq_filter')[2]==25000
    assert next(value for kind,value in recorded if kind=='nmea') == ('B',)


def test_gr310_bkerler_core_rejects_missing_blocks(monkeypatch):
    recorded, ais=install_fake_gr310(monkeypatch)
    from gnuradio import digital
    digital.symbol_sync_cc=None
    with pytest.raises(RuntimeError, match='missing AIS receive DSP blocks.*digital.symbol_sync_cc'):
        validate_backend(ais)



def test_schema_contains_frontend_params_not_raw_uhd_args():
    import ast
    t=ast.parse((ROOT/'actions.py').read_text())
    names={}
    for node in t.body:
        if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name):
            name=node.targets[0].id
            if name in ('ais_usrp_b210_receive_schema','ais_usrp_b210_transmit_schema'):
                names[name]={e['name']:e for e in ast.literal_eval(node.value)['params']}
    assert set(names)=={'ais_usrp_b210_receive_schema','ais_usrp_b210_transmit_schema'}
    for name in names:
        assert 'device_args' not in names[name]
        assert 'serial_number' in names[name]
        assert names[name]['rf_channel']['options'] == ['0 (A:A)','1 (A:B)']
    assert names['ais_usrp_b210_receive_schema']['rx_antenna']['default']=='TX/RX'
