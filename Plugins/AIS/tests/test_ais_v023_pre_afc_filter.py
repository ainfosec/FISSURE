"""v0.9.23: preserve signal bandwidth before correcting carrier offset.

The GNU Radio 3.10 capture used for development showed that the old
5.76-kHz PFB passband could bias the frequency estimate for a signal shifted
~2.7 kHz. Filtering away that energy before CFO recovery is irreversible.
"""
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def test_gr310_pre_cfo_bandwidth_and_post_cfo_filter(monkeypatch):
    from test_ais_gr310_b210_v097 import install_fake_gr310
    recorded, ais = install_fake_gr310(monkeypatch)
    from gnuradio import blocks
    blocks.rotator_cc = lambda *args: 'rotator'
    import ais_burst_carrier_sync_v0922 as sync_module
    monkeypatch.setattr(sync_module, 'make_sync', lambda *args: 'carrier_sync')
    from ais_gr310_receiver import make_receiver
    rx = make_receiver(-25000, 200000, 'A', ais, loop_bw=0.033,
                       channelizer='rotator', carrier_sync=True)
    chain = rx.connections[0]
    assert chain[1:6] == ('rotator', 'resampler', 'carrier_sync',
                          'post_filter', 'agc')
    assert [item for item in recorded if item[0] == 'post_filter'] == [
        ('post_filter', (1, 'low_pass'))]
    low_passes = [args for name, args in recorded if name == 'low_pass']
    # The first stage has a WIDE bandwidth; the second narrows the already
    # corrected waveform to the traditional AIS channel passband.
    assert low_passes[0][2] == 12000
    assert low_passes[0][3] == 2000
    assert low_passes[1][1] == 38400
    assert low_passes[1][2] == 5760
    assert low_passes[1][3] == 960


def test_legacy_narrow_receiver_unmodified(monkeypatch):
    from test_ais_gr310_b210_v097 import install_fake_gr310
    recorded, ais = install_fake_gr310(monkeypatch)
    from gnuradio import blocks
    blocks.rotator_cc = lambda *args: 'rotator'
    from ais_gr310_receiver import make_receiver
    rx = make_receiver(-25000, 200000, 'A', ais,
                       channelizer='rotator', carrier_sync=False)
    assert rx.post_sync_filter is None
    assert 'post_filter' not in rx.connections[0]
    low_passes = [args for name, args in recorded if name == 'low_pass']
    assert low_passes[0][2] == 5760
    assert low_passes[0][3] == 960


def test_cold_start_zero_noise_floor_recovers_for_multiple_bursts():
    from ais_burst_carrier_sync_v0922 import BurstCarrierCorrector
    sr = 38400
    rng = np.random.default_rng(20261109)
    n = sr * 2
    x = ((rng.normal(size=n) + 1j * rng.normal(size=n)) * 0.002).astype(np.complex64)
    # FIR resamplers may emit zeros while initializing. Without a moving
    # low-quantile noise reference, subsequent quiet samples appeared active
    # forever and stopped the receiver from acquiring each new burst.
    x[:384] = 0
    for start in (sr//2, sr + sr//2):
        nb = 1536
        bits = rng.choice([-1., 1.], size=nb//4)
        freq = np.repeat(bits, 4) * 2400 + 2700
        phase = np.cumsum(2 * np.pi * freq / sr)
        x[start:start+nb] += (0.3 * np.exp(1j*phase)).astype(np.complex64)
    sync = BurstCarrierCorrector()
    out = np.concatenate([sync.process(x[i:i+1237]) for i in range(0, n, 1237)])
    assert len(out) == n
    assert sync.bursts_acquired == 2
    assert abs(sync.frequency_hz - 2700) <= 150
    assert sync._noise_power > 0
