"""v0.9.11 HackRF-only diagnostic and upstream GNU Radio 3.10 tuning checks."""
from pathlib import Path
import sys
import numpy as np

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from ais_native_stream import hackrf_spectral_diagnostic


def test_hackrf_spectral_activity_reports_two_shifted_channels():
    rate=240000
    n=rate
    t=np.arange(n,dtype=np.float64)
    iq=(.2*np.exp(2j*np.pi*(-22300)*t/rate)+
        .2*np.exp(2j*np.pi*(27700)*t/rate)).astype('complex64')
    msg=hackrf_spectral_diagnostic(iq)
    assert 'A_peak_hz=' in msg and 'B_peak_hz=' in msg
    assert 'A_offset_hz=+2' in msg and 'B_offset_hz=+2' in msg


def test_hackrf_spectral_activity_in_memory_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert hackrf_spectral_diagnostic(np.zeros(100,dtype=np.complex64)) == 'insufficient_samples'
    assert not list(tmp_path.rglob('*'))


def test_gr310_loop_bandwidth_matches_top_level_application():
    src=(ROOT/'scripts'/'ais_gr310_receiver.py').read_text()
    assert 'loop_bw = float(loop_bw)' in src
    native=(ROOT/'scripts'/'ais_native_stream.py').read_text()
    assert "if kind == 'hackrf':\n            decoder_command += ['--loop-bandwidth', '0.033']" in native
    assert 'apps/ais_rx.grc' in src
