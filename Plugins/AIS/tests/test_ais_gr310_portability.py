"""Mocked GNU Radio 3.8 and 3.10 compatibility tests; no actual SDR required."""
import importlib
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from ais_gr_compat import gr_minor_version
from ais_iq_decoder import make_top_block


@pytest.mark.parametrize('version, minor', [('3.8.5.0', 8), ('3.10.9.2', 10), ('3.10.11.0', 10)])
def test_supported_minor_versions(version, minor):
    assert gr_minor_version(types.SimpleNamespace(version=lambda: version)) == (minor, version)


@pytest.mark.parametrize('version', ['3.7.9', '3.9.0', '3.11.0', '4.0.0', ''])
def test_unsupported_minor_versions_fail(version):
    with pytest.raises(RuntimeError, match='Unsupported GNU Radio version'):
        gr_minor_version(types.SimpleNamespace(version=lambda: version))


@pytest.mark.parametrize('minor', [8, 10])
def test_radio_flowgraph_uses_installed_gr_ais_not_old_core(monkeypatch, minor):
    constructed = []
    class TB:
        def __init__(self, title):
            self.title = title
            self.connections = []
        def connect(self, *edges):
            self.connections.append(edges)
    gr = types.ModuleType('gnuradio.gr')
    gr.sizeof_gr_complex = 8
    gr.top_block = TB
    blocks = types.ModuleType('gnuradio.blocks')
    blocks.file_source = lambda *args: ('file', args)
    package = types.ModuleType('gnuradio')
    package.gr, package.blocks = gr, blocks
    monkeypatch.setitem(sys.modules, 'gnuradio', package)
    monkeypatch.setitem(sys.modules, 'gnuradio.gr', gr)
    monkeypatch.setitem(sys.modules, 'gnuradio.blocks', blocks)
    ais = types.SimpleNamespace(ais_rx=lambda offset, rate, label:
                                constructed.append((offset, rate, label)) or ('ais', label))
    tb = make_top_block('/tmp/test.cf32', 240000, 162000000, 'both', minor, ais)
    assert constructed == [(-25000, 240000, 'A'), (25000, 240000, 'B')]
    assert len(tb.connections) == 2
    assert tb.title == 'FISSURE AIS IQ file receiver'


@pytest.mark.parametrize('minor', [8, 10])
def test_input_source_supports_persistent_rx_stream(monkeypatch, minor):
    gr = types.ModuleType('gnuradio.gr')
    class TB:
        def __init__(self, label):
            self.connections = []
        def connect(self, *args):
            self.connections.append(args)
    gr.top_block = TB
    package = types.ModuleType('gnuradio')
    package.gr = gr
    package.blocks = types.ModuleType('gnuradio.blocks')
    monkeypatch.setitem(sys.modules, 'gnuradio', package)
    monkeypatch.setitem(sys.modules, 'gnuradio.gr', gr)
    ais = types.SimpleNamespace(ais_rx=lambda *args: ('rx', args))
    source = ('stdin-live-iq', 0)
    tb = make_top_block(None, 240000, 162000000, 'both', minor, ais, source=source)
    assert len(tb.connections) == 2
    assert all(c[0] == (source, 0) for c in tb.connections)


@pytest.mark.parametrize('version', ['3.8.5.0', '3.10.9.2'])
def test_modulator_probe_accepts_both(monkeypatch, version):
    module = importlib.import_module('ais_iq_generator')
    package = types.ModuleType('gnuradio')
    package.gr = types.SimpleNamespace(version=lambda: version)
    package.blocks = object()
    package.digital = types.SimpleNamespace(gmsk_mod=lambda **kwargs: object())
    monkeypatch.setitem(sys.modules, 'gnuradio', package)
    assert module.probe()[-1] == version


@pytest.mark.parametrize('version', ['3.8.5.0', '3.10.9.2'])
def test_b210_probe_accepts_both(monkeypatch, version):
    module = importlib.import_module('ais_b210_rf_hardware')
    package = types.ModuleType('gnuradio')
    package.gr = types.SimpleNamespace(version=lambda: version)
    package.blocks = object()
    package.uhd = types.SimpleNamespace(usrp_source=lambda *args: object(),
                                        usrp_sink=lambda *args: object())
    monkeypatch.setitem(sys.modules, 'gnuradio', package)
    assert module.probe()[-1] == version


@pytest.mark.parametrize('version', ['3.8.5.0', '3.10.9.2'])
def test_hackrf_gr_osmosdr_probe_accepts_both(monkeypatch, version):
    module = importlib.import_module('ais_osmosdr_hardware')
    package = types.ModuleType('gnuradio')
    package.gr = types.SimpleNamespace(version=lambda: version)
    package.blocks = object()
    package.filter = types.SimpleNamespace(rational_resampler_ccc=lambda **kwargs: object())
    osmosdr = types.ModuleType('osmosdr')
    osmosdr.source = lambda **kwargs: object()
    osmosdr.sink = lambda **kwargs: object()
    monkeypatch.setitem(sys.modules, 'gnuradio', package)
    monkeypatch.setitem(sys.modules, 'osmosdr', osmosdr)
    assert module.probe()[-1] == version
