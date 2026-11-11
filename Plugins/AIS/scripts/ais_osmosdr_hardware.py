#!/usr/bin/env python3
"""Finite AIS capture/transmit via gr-osmosdr on GNU Radio 3.8/3.10.

HackRF operates at 2.4 MS/s. RTL-SDR capture also uses 2.4 MS/s.
The verified AIS IQ codec works at 240 kS/s; GNU Radio rational resamplers
bridge the rates, preserving both +/-25 kHz AIS channels.

Transmit only on an authorized, non-maritime, shielded/attenuated lab path.
Never directly connect a transmitter to an SDR receiver without confirming
receiver-safe input power. Neither gain settings nor IQ amplitude calibrate dBm.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
from pathlib import Path
import signal
import sys
import tempfile
import time

from ais_gr_compat import gr_minor_version
import shutil
import os
import subprocess

AIS_RATE = 240000
DEVICE_RATE = 2400000
TX_DIGITAL_SCALE = 0.15


def _load_b210_helper():
    path = Path(__file__).resolve().with_name('ais_b210_rf_hardware.py')
    spec = importlib.util.spec_from_file_location('_ais_osmosdr_b210_helpers_snapshot', str(path))
    if spec is None or spec.loader is None:
        raise ImportError('Missing AIS IQ file utilities: %s' % path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _validate_args(args, kind):
    args = str(args).strip()
    # Do not permit an arbitrary radio type through the HackRF/RTL-only helper.
    if not args.startswith(kind + '=') or any(c in args for c in '\n\r\x00'):
        raise ValueError('Expected gr-osmosdr device arguments beginning with %s=' % kind)
    return args


def validate_tx(rf_frequency=915000000, tx_vga_gain=10, device_args='hackrf=0'):
    freq, gain = float(rf_frequency), float(tx_vga_gain)
    if not math.isfinite(freq) or not 500e6 <= freq <= 3000e6:
        raise ValueError('HackRF TX requires a permitted isolated lab frequency, 500 MHz to 3 GHz; no maritime AIS frequencies')
    if not math.isfinite(gain) or not 0 <= gain <= 47:
        raise ValueError('HackRF TX IF gain must be in 0..47 dB')
    return _validate_args(device_args, 'hackrf')


def validate_rx(kind, rf_frequency, duration_s, device_args, gain=35, lna_gain=16, vga_gain=16):
    if kind not in ('hackrf', 'rtl'):
        raise ValueError('Only HackRF or RTL-SDR RX supported')
    freq, duration = float(rf_frequency), float(duration_s)
    if not math.isfinite(freq) or not 70e6 <= freq <= 1750e6:
        raise ValueError('RX center frequency must be 70 MHz–1.75 GHz for cross-device compatibility')
    if not math.isfinite(duration) or not 1 <= duration <= 120:
        raise ValueError('RX duration must be 1..120 seconds')
    if kind == 'rtl':
        if not math.isfinite(float(gain)) or not 0 <= float(gain) <= 50:
            raise ValueError('RTL-SDR tuner gain must be 0..50 dB (driver selects supported step)')
    else:
        if not math.isfinite(float(lna_gain)) or not 0 <= float(lna_gain) <= 40:
            raise ValueError('HackRF LNA gain must be 0..40 dB')
        if not math.isfinite(float(vga_gain)) or not 0 <= float(vga_gain) <= 62:
            raise ValueError('HackRF VGA gain must be 0..62 dB')
    return _validate_args(device_args, kind)


def probe():
    from gnuradio import gr, blocks, filter as grfilter
    import osmosdr
    _, version = gr_minor_version(gr)
    if not callable(getattr(osmosdr, 'source', None)) or not callable(getattr(osmosdr, 'sink', None)):
        raise RuntimeError('gr-osmosdr requires both source and sink Python blocks')
    if not callable(getattr(grfilter, 'rational_resampler_ccc', None)):
        raise RuntimeError('GNU Radio rational_resampler_ccc missing')
    return gr, blocks, grfilter, osmosdr, version


def make_tx_graph(input_file, rf_frequency, tx_vga_gain, device_args, runtime):
    gr, blocks, grfilter, osmosdr, _ = runtime
    tx = osmosdr.sink(args='numchan=1 ' + _validate_args(device_args, 'hackrf'))
    tx.set_sample_rate(DEVICE_RATE)
    tx.set_center_freq(float(rf_frequency), 0)
    tx.set_gain(0, 0)  # HackRF RF amplifier disabled
    tx.set_if_gain(float(tx_vga_gain), 0)
    src = blocks.file_source(gr.sizeof_gr_complex, str(input_file), False)
    interp = grfilter.rational_resampler_ccc(interpolation=10, decimation=1)
    scale = blocks.multiply_const_cc(TX_DIGITAL_SCALE)
    tb = gr.top_block('FISSURE AIS standalone HackRF TX')
    tb.connect((src, 0), (interp, 0), (scale, 0), (tx, 0))
    return tb


def make_rx_graph(output_file, duration_s, kind, rf_frequency, device_args,
                  gain, lna_gain, vga_gain, runtime):
    gr, blocks, grfilter, osmosdr, _ = runtime
    radio = osmosdr.source(args='numchan=1 ' + _validate_args(device_args, kind))
    radio.set_sample_rate(DEVICE_RATE)
    radio.set_center_freq(float(rf_frequency), 0)
    radio.set_gain_mode(False, 0)
    if kind == 'hackrf':
        radio.set_gain(0, 0)  # RF amplifier off
        radio.set_if_gain(float(lna_gain), 0)
        radio.set_bb_gain(float(vga_gain), 0)
    else:
        radio.set_gain(float(gain), 0)
    decimator = grfilter.rational_resampler_ccc(interpolation=1, decimation=10)
    limiter = blocks.head(gr.sizeof_gr_complex, int(AIS_RATE * float(duration_s)))
    out = blocks.file_sink(gr.sizeof_gr_complex, str(output_file), False)
    tb = gr.top_block('FISSURE AIS standalone %s RX' % kind)
    tb.connect((radio, 0), (decimator, 0), (limiter, 0), (out, 0))
    return tb, out


def _run_bounded(tb, seconds):
    started = False
    original = signal.getsignal(signal.SIGTERM)
    def stop_on_signal(signum, frame):
        if started:
            tb.stop()
        raise KeyboardInterrupt('AIS SDR stopped')
    signal.signal(signal.SIGTERM, stop_on_signal)
    try:
        tb.start()
        started = True
        time.sleep(float(seconds))
        tb.stop()
        tb.wait()
    finally:
        signal.signal(signal.SIGTERM, original)
        if started:
            tb.stop()
            tb.wait()


def select_tx_backend(tx_backend='auto'):
    """Use native HackRF CLI with GR 3.10 to isolate gr-osmosdr TX issues."""
    if tx_backend not in ('auto', 'native', 'osmosdr'):
        raise ValueError('TX backend must be auto, native or osmosdr')
    if tx_backend != 'auto':
        return tx_backend
    try:
        from gnuradio import gr
        minor, _ = gr_minor_version(gr)
    except (ImportError, RuntimeError):
        minor = 0
    if minor == 10 and shutil.which('hackrf_transfer'):
        return 'native'
    return 'osmosdr'


def run_tx(input_file, manifest_file, rf_frequency=915e6, tx_vga_gain=10,
           device_args='hackrf=0', tx_backend='auto'):
    validate_tx(rf_frequency, tx_vga_gain, device_args)
    helper = _load_b210_helper()
    iq_path, _ = helper.verify_iq_file(input_file)
    result_path = Path(manifest_file).expanduser().resolve()
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.unlink(missing_ok=True)
    backend = select_tx_backend(tx_backend)
    native_info = {}
    if backend == 'native':
        from ais_hackrf_native_tx_v099 import transmit_iq8
        native_info = transmit_iq8(iq_path, float(rf_frequency), float(tx_vga_gain), device_args)
        lead, tail, count = (native_info['lead_samples'], native_info['tail_samples'], native_info['tx_input_samples'])
    else:
        with tempfile.TemporaryDirectory(prefix='fissure_ais_hackrf_tx_') as scratch:
            padded = Path(scratch) / 'finite_tx.cf32'
            lead, tail, count = helper.prepare_tx_file(iq_path, padded, AIS_RATE, lead_s=1.0, tail_s=0.5)
            tb = make_tx_graph(padded, float(rf_frequency), float(tx_vga_gain), device_args, probe())
            _run_bounded(tb, count / AIS_RATE + 1.0)
    result = {'schema': 'fissure.ais.hackrf_tx.v1', 'device': 'HackRF',
              'rf_transmitted': True, 'rf_center_frequency_hz': float(rf_frequency),
              'ais_iq_sample_rate_hz': AIS_RATE, 'radio_sample_rate_hz': DEVICE_RATE,
              'tx_vga_gain_db': float(tx_vga_gain), 'tx_rf_amp_enabled': False,
              'tx_backend': backend, 'native_iq8_stats': native_info,
              'tx_digital_scale': TX_DIGITAL_SCALE, 'tx_input_samples': count,
              'lead_samples': lead, 'tail_samples': tail,
              'rx_input_power_measured': False, 'verified_safe_rf_path': False}
    result_path.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result


def native_rx_executable(kind):
    """Prefer the vendor CLI when gr-osmosdr and GNU Radio have mismatched ABIs."""
    return shutil.which('rtl_sdr' if kind == 'rtl' else 'hackrf_transfer')


def native_rx_command(kind, raw_path, rf_frequency, duration_s, device_args,
                      gain=35, lna_gain=16, vga_gain=16):
    """Return a finite device-native IQ8 capture command (no RF transmission)."""
    binary = native_rx_executable(kind)
    if binary is None:
        raise RuntimeError('Native %s receive requires %s in PATH' %
                           (kind, 'rtl_sdr' if kind == 'rtl' else 'hackrf_transfer'))
    index = _validate_args(device_args, kind).split('=', 1)[1]
    if ',' in index or ' ' in index:
        raise ValueError('Native receive requires a single %s device selector' % kind)
    count = int(round(DEVICE_RATE * float(duration_s)))
    if kind == 'rtl':
        cmd = [binary, '-d', index, '-f', str(int(rf_frequency)),
               '-s', str(DEVICE_RATE), '-g', str(float(gain)),
               '-n', str(count), str(raw_path)]
    else:
        cmd = [binary, '-r', str(raw_path), '-f', str(int(rf_frequency)),
               '-s', str(DEVICE_RATE), '-l', str(int(lna_gain)),
               '-g', str(int(vga_gain)), '-a', '0', '-n', str(count)]
        if index != '0':
            cmd.extend(['-d', index])
    return cmd


def _run_native_capture(command, timeout_s):
    """Manage child lifetime on cancellation, including Sensor Node SIGTERM."""
    proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True)
    previous = signal.getsignal(signal.SIGTERM)
    def cancel(signum, frame):
        raise KeyboardInterrupt('AIS native capture stopped')
    signal.signal(signal.SIGTERM, cancel)
    try:
        out, err = proc.communicate(timeout=max(20.0, float(timeout_s)))
        if proc.returncode != 0:
            raise RuntimeError('%s exited %d: %s' % (Path(command[0]).name,
                proc.returncode, err.decode('utf-8', 'replace')[-1500:]))
        return err.decode('utf-8', 'replace')[-1000:]
    except subprocess.TimeoutExpired:
        raise RuntimeError('%s timed out recording samples' % Path(command[0]).name)
    finally:
        signal.signal(signal.SIGTERM, previous)
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.communicate()


def convert_native_iq8(raw_file, out_file, kind, chunk_samples=1200000):
    """Convert unsigned RTL / signed HackRF interleaved IQ8 to decimated cf32.

    Uses a polyphase anti-alias filter. A 1000-sample overlap on either
    side of each chunk avoids filter discontinuities at block boundaries.
    Peak memory stays small for long recordings. Returned count is at
    AIS_RATE (240 kS/s), suitable for the existing gr-ais IQ decoder.
    """
    import numpy as np
    from scipy.signal import resample_poly
    if kind not in ('rtl', 'hackrf'):
        raise ValueError('Invalid IQ8 format %r' % kind)
    chunk_samples = max(10000, int(chunk_samples) // 10 * 10)
    overlap = 1000  # input samples; divisible by decimation 10
    kind_dtype = np.uint8 if kind == 'rtl' else np.int8
    size = Path(raw_file).stat().st_size
    if size < 2 * 10000 or size % 2:
        raise RuntimeError('Native %s RX produced no valid IQ8 data' % kind)
    def decode(data):
        values = np.frombuffer(data, dtype=kind_dtype).astype(np.float32).reshape(-1, 2)
        if kind == 'rtl':
            values = (values - 127.5) * (1 / 128.0)
        else:
            values *= (1 / 128.0)
        return np.asarray(values[:, 0] + 1j * values[:, 1], dtype=np.complex64)
    previous = np.empty(0, dtype=np.complex64)
    samples = 0
    with open(raw_file, 'rb') as inp, open(out_file, 'wb') as out:
        while True:
            block = inp.read(chunk_samples * 2)
            if not block:
                break
            current = decode(block)
            # Last partial sample group, if any, is discarded explicitly.
            keep = len(current) // 10 * 10
            if not keep:
                break
            current = current[:keep]
            upcoming = inp.read(overlap * 2)
            inp.seek(-len(upcoming), os.SEEK_CUR)
            after = decode(upcoming[:len(upcoming)//2*2]) if upcoming else np.empty(0, np.complex64)
            extended = np.concatenate((previous, current, after))
            filtered = resample_poly(extended, up=1, down=10)
            left = len(previous) // 10
            converted = np.asarray(filtered[left:left + keep // 10], dtype=np.complex64)
            if len(converted) != keep // 10:
                raise RuntimeError('Native IQ resampler output length mismatch')
            converted.tofile(out)
            samples += len(converted)
            previous = current[-overlap:].copy()
    if not samples:
        raise RuntimeError('Native IQ conversion produced no samples')
    return samples


def run_rx(output_file, manifest_file, kind='rtl', rf_frequency=162e6,
           duration_s=20, device_args=None, gain=35, lna_gain=16, vga_gain=16,
           capture_backend='auto'):
    if device_args is None:
        device_args = 'hackrf=0' if kind == 'hackrf' else 'rtl=0'
    validate_rx(kind, rf_frequency, duration_s, device_args, gain, lna_gain, vga_gain)
    if capture_backend not in ('auto', 'native', 'osmosdr'):
        raise ValueError('capture_backend must be auto, native or osmosdr')
    output = Path(output_file).expanduser().resolve()
    manifest = Path(manifest_file).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_name(output.name + '.partial')
    partial.unlink(missing_ok=True)
    output.unlink(missing_ok=True)
    manifest.unlink(missing_ok=True)
    required_samples = int(AIS_RATE * float(duration_s))
    native_available = native_rx_executable(kind) is not None
    backend = ('native' if native_available else 'osmosdr') if capture_backend == 'auto' else capture_backend
    try:
        if backend == 'native':
            with tempfile.TemporaryDirectory(prefix='fissure_ais_native_rx_') as scratch:
                raw_path = Path(scratch) / ('ais_%s_iq8.raw' % kind)
                command = native_rx_command(kind, raw_path, rf_frequency, duration_s,
                                            device_args, gain, lna_gain, vga_gain)
                _run_native_capture(command, float(duration_s) + 15.0)
                got = convert_native_iq8(raw_path, partial, kind)
        else:
            try:
                graph, sink = make_rx_graph(partial, duration_s, kind, rf_frequency,
                                            device_args, gain, lna_gain, vga_gain, probe())
                _run_bounded(graph, float(duration_s) + 2.0)
            except RuntimeError as exc:
                if 'list contains invalid format' in str(exc):
                    raise RuntimeError('GNU Radio/gr-osmosdr source ABI mismatch. '
                                       'The installed gr-osmosdr may link GNU Radio 3.8/3.10.1 '
                                       'while Python loads 3.8.5. Rebuild gr-osmosdr '
                                       'or install %s for native IQ capture.' %
                                       ('rtl_sdr' if kind == 'rtl' else 'hackrf_transfer')) from exc
                raise
            try:
                sink.close()
            except AttributeError:
                pass
            got = partial.stat().st_size // 8 if partial.exists() else 0
        if not partial.exists() or partial.stat().st_size < 8192 or partial.stat().st_size % 8:
            raise RuntimeError('%s RX produced no complex64 samples' % kind)
        if got < int(required_samples * 0.95):
            raise RuntimeError('%s RX capture incomplete: %s/%s' % (kind, got, required_samples))
        partial.replace(output)
        result = {'schema': 'fissure.ais.osmosdr_rx.v2', 'device': kind,
                  'capture_backend': 'native_cli_iq8' if backend == 'native' else 'gr_osmosdr',
                  'rf_transmitted': False, 'rf_center_frequency_hz': float(rf_frequency),
                  'capture_sample_rate_hz': AIS_RATE, 'radio_sample_rate_hz': DEVICE_RATE,
                  'samples_received': got, 'capture_path': str(output),
                  'duration_s': float(duration_s), 'rx_device_args': device_args,
                  'simulated_input': False,
                  'position_semantics': 'ais_self_reported_not_rf_geolocation'}
        if kind == 'rtl':
            result['rx_tuner_gain_db'] = float(gain)
        else:
            result['rx_lna_gain_db'] = float(lna_gain)
            result['rx_vga_gain_db'] = float(vga_gain)
            result['rx_rf_amp_enabled'] = False
        manifest.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
        return result
    finally:
        partial.unlink(missing_ok=True)


def main(argv=None):
    p = argparse.ArgumentParser(description='FISSURE HackRF/RTL-SDR AIS hardware helper (GNU Radio 3.8)')
    p.add_argument('--probe', action='store_true')
    p.add_argument('--mode', choices=('tx', 'rx'))
    p.add_argument('--device', choices=('hackrf', 'rtl'), default='rtl')
    p.add_argument('--input')
    p.add_argument('--output')
    p.add_argument('--manifest')
    p.add_argument('--rf-frequency', type=float, default=None)
    p.add_argument('--device-args')
    p.add_argument('--tx-gain', type=float, default=10)
    p.add_argument('--rx-gain', type=float, default=35)
    p.add_argument('--lna-gain', type=float, default=16)
    p.add_argument('--vga-gain', type=float, default=16)
    p.add_argument('--duration-s', type=float, default=20)
    p.add_argument('--capture-backend', choices=('auto', 'native', 'osmosdr'), default='auto')
    p.add_argument('--tx-backend', choices=('auto', 'native', 'osmosdr'), default='auto')
    a = p.parse_args(argv)
    try:
        if a.probe:
            print('AIS gr-osmosdr available: GNU Radio %s; native RTL tool: %s; native HackRF tool: %s (NO RF)' % (probe()[-1], bool(shutil.which('rtl_sdr')), bool(shutil.which('hackrf_transfer'))))
        elif a.mode == 'tx':
            if a.device != 'hackrf' or not a.input or not a.manifest:
                p.error('HackRF TX requires --device hackrf, --input, and --manifest')
            result = run_tx(a.input, a.manifest, a.rf_frequency or 915e6, a.tx_gain,
                            a.device_args or 'hackrf=0', a.tx_backend)
            print('AIS HackRF TX completed: %d baseband samples' % result['tx_input_samples'])
        elif a.mode == 'rx':
            if not a.output or not a.manifest:
                p.error('RX requires --output and --manifest')
            result = run_rx(a.output, a.manifest, a.device,
                            a.rf_frequency if a.rf_frequency is not None else 162e6,
                            a.duration_s, a.device_args, a.rx_gain, a.lna_gain, a.vga_gain, a.capture_backend)
            print('AIS %s RX captured: %d complex64 samples' % (a.device, result['samples_received']))
        else:
            p.error('--mode is required unless --probe is used')
        return 0
    except KeyboardInterrupt:
        print('AIS osmosdr operation interrupted', file=sys.stderr)
        return 130
    except Exception as exc:
        print('AIS osmosdr error: %s: %s' % (type(exc).__name__, exc), file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
