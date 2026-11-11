#!/usr/bin/env python3
"""Continuous AIS RF RX: rtl_sdr/hackrf_transfer -> IQ8 -> cf32 -> gr-ais.

No intermediate IQ recordings. Fixed-size buffers, persistent radio process,
continuous resampling, and a persistent GNU Radio decoder. On GNU Radio
3.10, HackRF uses 200 kS/s, as validated with the standalone B210 graph. Streaming stdout is
NMEA only, for the FISSURE Sensor Node to parse into Detections/Targets.
"""
from __future__ import annotations

import argparse
from collections import deque
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading

from ais_osmosdr_hardware import AIS_RATE, DEVICE_RATE, validate_rx

HACKRF_GR310_RX_RATE = 200000  # 2.4 MS/s native -> 200 kS/s GRC reference DSP

ROOT = Path(__file__).resolve().parent
STOP = threading.Event()


def native_stream_command(kind, freq, device_args, gain, lna_gain, vga_gain):
    from ais_osmosdr_hardware import _validate_args
    if kind not in ('rtl', 'hackrf'):
        raise ValueError('Only RTL-SDR and HackRF are supported for native streams')
    selector = _validate_args(device_args, kind).split('=', 1)[1]
    if ',' in selector or ' ' in selector:
        raise ValueError('Native receive requires one device selector')
    binary = shutil.which('rtl_sdr' if kind == 'rtl' else 'hackrf_transfer')
    if not binary:
        raise RuntimeError('Missing native RX utility %s in PATH' %
                           ('rtl_sdr' if kind == 'rtl' else 'hackrf_transfer'))
    if kind == 'rtl':
        # No -n: RTL-SDR captures until terminated. '-' sends IQ8 to stdout.
        return [binary, '-d', selector, '-f', str(int(freq)), '-s', str(DEVICE_RATE),
                '-g', str(float(gain)), '-']
    command = [binary, '-r', '-', '-f', str(int(freq)), '-s', str(DEVICE_RATE),
               '-l', str(int(lna_gain)), '-g', str(int(vga_gain)), '-a', '0']
    if selector != '0':
        command += ['-d', selector]
    return command


def decode_iq8(blob, kind):
    import numpy as np
    values = np.frombuffer(blob, dtype=np.uint8 if kind == 'rtl' else np.int8)
    if len(values) % 2:
        raise ValueError('Non-interleaved IQ8 data')
    floats = values.astype(np.float32).reshape(-1, 2)
    if kind == 'rtl':
        floats = (floats - 127.5) * (1.0 / 128.0)
    else:
        floats *= (1.0 / 128.0)
    return np.asarray(floats[:, 0] + 1j * floats[:, 1], dtype=np.complex64)


def hackrf_spectral_diagnostic(iq, sample_rate=AIS_RATE):
    """Bounded, approximate RF activity estimate; not a demodulation verdict.

    A 1-second baseband window is inspected *in memory* around the two
    nominal +/-25 kHz AIS test channels. This never writes or retains IQ.
    The spectral-peak offsets help distinguish mistuning from a broken pipe.
    """
    import numpy as np
    from scipy.signal import welch
    iq = np.asarray(iq, dtype=np.complex64)
    if len(iq) < 8192:
        return 'insufficient_samples'
    frequencies, power = welch(iq, fs=float(sample_rate),
                               nperseg=8192, noverlap=4096,
                               return_onesided=False)
    floor = power[(abs(frequencies) >= 60000) & (abs(frequencies) <= 100000)]
    if not len(floor):
        return 'insufficient_noise_reference'
    reference = max(float(np.median(floor)), 1e-20)
    rms = float(np.sqrt(np.mean(np.abs(iq)**2)))
    parts = ['rms=%.5f' % rms]
    for name, center in (('A', -25000), ('B', 25000)):
        band = np.where(abs(frequencies - center) <= 7500)[0]
        peak_index = band[np.argmax(power[band])]
        snr = float(10 * np.log10(max(float(power[peak_index]), 1e-20) / reference))
        if snr >= 9:
            parts.append('%s_peak_hz=%+.0f %s_offset_hz=%+.0f %s_peak_above_floor_db=%.1f' %
                         (name, frequencies[peak_index], name,
                          frequencies[peak_index] - center, name, snr))
        else:
            parts.append('%s_no_strong_peak(%.1f_dB)' % (name, snr))
    return ' '.join(parts)


def stream_decimate(raw, sink, kind, chunk_samples=240000, overlap=1200, output_rate=AIS_RATE):
    """Forward continuous IQ8 to cf32 sink with a polyphase anti-alias filter.

    Every chunk includes past/future RF samples for FIR continuity. The fixed
    lookahead adds less than 0.2 seconds of delay at 2.4 MS/s. No bytes are
    written to files. Returns total samples delivered at ``output_rate`` samples/s.
    """
    import numpy as np
    from scipy.signal import resample_poly
    chunk_samples = int(chunk_samples)
    overlap = int(overlap)
    output_rate = int(output_rate)
    if output_rate <= 0 or DEVICE_RATE % output_rate:
        raise ValueError('Output sample rate must divide hardware rate exactly')
    ratio = int(DEVICE_RATE // output_rate)
    if chunk_samples < overlap * 2 or chunk_samples % ratio or overlap % ratio:
        raise ValueError('chunk_samples and overlap must be multiples of decimation ratio')
    prev = np.empty(0, np.complex64)

    def read_block():
        # BufferedReader.read(n) fills the buffer, unless EOF; output remains
        # bounded and sample aligned even when kernel reads are fragmented.
        block = raw.read(2 * chunk_samples)
        valid = (len(block) // (2 * ratio)) * (2 * ratio)
        return decode_iq8(block[:valid], kind) if valid else np.empty(0, np.complex64)

    current = read_block()
    total = 0
    next_report = int(output_rate * 5)
    diagnostic_segments = deque(maxlen=10) if kind == 'hackrf' else None
    while len(current) and not STOP.is_set():
        following = read_block()
        before = prev[-overlap:]
        after = following[:overlap]
        window = np.concatenate((before, current, after))
        filtered = resample_poly(window, up=1, down=ratio)
        offset = len(before) // ratio
        converted = np.asarray(filtered[offset:offset + len(current) // ratio], dtype='<c8')
        if len(converted) != len(current) // ratio:
            raise RuntimeError('Continuous IQ resampler output length mismatch')
        # Popen.stdin is opened unbuffered (bufsize=0). A write may be partial.
        view = memoryview(converted.tobytes())
        while view and not STOP.is_set():
            written = sink.write(view)
            if written is None or written <= 0:
                raise BrokenPipeError('GNU Radio decoder input pipe closed')
            view = view[written:]
        total += len(converted)
        if diagnostic_segments is not None:
            diagnostic_segments.append(converted.copy())
        if total >= next_report:
            print('AIS RX %s: %d baseband samples delivered to GNU Radio' %
                  (kind.upper(), total), file=sys.stderr, flush=True)
            if diagnostic_segments is not None:
                try:
                    window = np.concatenate(diagnostic_segments)
                    print('AIS RX HACKRF spectral activity: %s' %
                          hackrf_spectral_diagnostic(window, sample_rate=output_rate),
                          file=sys.stderr, flush=True)
                except Exception as exc:
                    print('AIS RX HACKRF spectral diagnostic unavailable: %s' % exc,
                          file=sys.stderr, flush=True)
            next_report = total + int(output_rate * 5)
        prev = current[-overlap:].copy()
        current = following
    return total


def _drain_stderr(stream, label, errors):
    for raw_line in iter(stream.readline, b''):
        msg = raw_line.decode('utf-8', 'replace').strip()
        if msg:
            errors.append('%s: %s' % (label, msg[:400]))
            # stderr is small control/diagnostic data, never IQ.
            if (msg.startswith(('AIS streaming decoder started:', 'AIS RX AFC:', 'AIS RX carrier sync ')) or
                    any(keyword in msg.lower() for keyword in ('error', 'overflow', 'dropped', 'failed', 'underrun'))):
                print('AIS live RX %s: %s' % (label, msg[:400]), file=sys.stderr, flush=True)


def _forward_nmea(stream):
    for raw_line in iter(stream.readline, b''):
        if raw_line.startswith((b'!AIVDM,', b'!AIVDO,')):
            sys.stdout.buffer.write(raw_line)
            sys.stdout.buffer.flush()


def _terminate(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def run_native_stream(kind, command,
                      decoder_rate=AIS_RATE, receiver_profile=None,
                      hardware_tuning_summary=''):
    STOP.clear()
    errors = deque(maxlen=30)
    rx = decoder = None
    threads = []

    def stopping(signum, frame):
        STOP.set()
        for proc in (rx, decoder):
            if proc is not None and proc.poll() is None:
                proc.terminate()

    signal.signal(signal.SIGTERM, stopping)
    signal.signal(signal.SIGINT, stopping)
    try:
        decoder_command = [sys.executable, '-X', 'faulthandler', '-u', str(ROOT / 'ais_live_decoder.py'),
                           '--source', 'stdin', '--sample-rate', str(int(decoder_rate))]
        if kind == 'hackrf':
            decoder_command += ['--loop-bandwidth', '0.033']
        if receiver_profile is not None:
            decoder_command += ['--receiver-profile', receiver_profile]
        if hardware_tuning_summary:
            print(hardware_tuning_summary, file=sys.stderr, flush=True)
        decoder = subprocess.Popen(decoder_command, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   bufsize=0)
        rx = subprocess.Popen(command, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, bufsize=1024*1024)
        for method, stream, label in (( _drain_stderr, rx.stderr, kind),
                                       (_drain_stderr, decoder.stderr, 'gr-ais')):
            t = threading.Thread(target=method, args=(stream, label, errors), daemon=True)
            t.start()
            threads.append(t)
        t = threading.Thread(target=_forward_nmea, args=(decoder.stdout,), daemon=True)
        t.start()
        threads.append(t)
        delivered = stream_decimate(rx.stdout, decoder.stdin, kind,
                                    output_rate=decoder_rate)
        if decoder.stdin is not None:
            decoder.stdin.close()
        if not STOP.is_set():
            rx_code = rx.wait(timeout=5)
            dec_code = decoder.wait(timeout=5)
            if rx_code or dec_code:
                raise RuntimeError('%s RX or gr-ais decoder ended unexpectedly (%s/%s): %s' %
                                   (kind, rx_code, dec_code, '; '.join(errors)[-1200:]))
            raise RuntimeError('%s RF receiver unexpectedly ended after %d AIS samples: %s' %
                               (kind, delivered, '; '.join(errors)[-1200:]))
        return 0
    except (BrokenPipeError, OSError) as exc:
        if STOP.is_set():
            return 0
        # EPIPE means the decoder closed stdin. It does NOT establish that
        # HackRF failed. Preserve the actual child exit status: exit -11 is
        # SIGSEGV, -9 is SIGKILL/OOM, exit 1 is a handled decoder failure.
        if decoder is not None and decoder.poll() is None:
            try:
                decoder.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                pass
        for thread in threads:
            if not thread.is_alive():
                continue
            thread.join(timeout=0.1)
        decoder_code = decoder.poll() if decoder is not None else None
        radio_code = rx.poll() if rx is not None else None
        if decoder_code is not None and decoder_code < 0:
            try:
                reason = signal.Signals(-decoder_code).name
            except ValueError:
                reason = 'signal_%d' % -decoder_code
            decoder_status = 'signal %s (exit %d)' % (reason, decoder_code)
        else:
            decoder_status = str(decoder_code) if decoder_code is not None else 'running'
        raise RuntimeError(
            '%s native stream pipe failed: %s; decoder_exit=%s, radio_exit=%s; decoder_stderr=%s' % (
                kind, exc, decoder_status,
                radio_code if radio_code is not None else 'running',
                '; '.join(errors)[-2000:])) from exc
    finally:
        STOP.set()
        _terminate(rx)
        _terminate(decoder)
        for t in threads:
            t.join(timeout=1)


def main(argv=None):
    p = argparse.ArgumentParser(description='Continuous native RTL/HackRF AIS receive-to-NMEA stream')
    p.add_argument('--device', choices=('rtl', 'hackrf'), required=True)
    p.add_argument('--rf-frequency', type=float, default=162000000)
    p.add_argument('--device-args', default='')
    # Ignore this retired internal option if an older launcher survives a hot update.
    # It is not a user Action parameter; GNU Radio 3.10 uses automatic AFC.
    p.add_argument('--frequency-correction-hz', type=float, default=None, help=argparse.SUPPRESS)
    p.add_argument('--rx-gain', type=float, default=35)
    p.add_argument('--lna-gain', type=float, default=16)
    p.add_argument('--vga-gain', type=float, default=16)
    a = p.parse_args(argv)
    if a.frequency_correction_hz is not None:
        print('AIS live RX compatibility: retired frequency correction argument '
              'ignored; automatic AFC remains enabled', file=sys.stderr, flush=True)
    args = a.device_args or ('rtl=0' if a.device == 'rtl' else 'hackrf=0')
    import math
    try:
        validate_rx(a.device, a.rf_frequency, 20, args, a.rx_gain, a.lna_gain, a.vga_gain)
        from gnuradio import gr
        from ais_gr_compat import gr_minor_version
        minor, _ = gr_minor_version(gr)
        use_reference = a.device == 'hackrf' and minor == 10
        # No manual oscillator offset. GNU Radio 3.10 estimates and
        # corrects any common frequency error from incoming AIS bursts.
        cmd = native_stream_command(a.device, a.rf_frequency, args,
                                    a.rx_gain, a.lna_gain, a.vga_gain)
        decoder_rate = HACKRF_GR310_RX_RATE if use_reference else AIS_RATE
        tuning_summary = ('AIS HACKRF RX auto frequency: center=%.0f Hz native_sample_rate=%d decoder_rate=%d' % (
            a.rf_frequency, DEVICE_RATE, decoder_rate)) if use_reference else ''
        return run_native_stream(a.device, cmd,
                                 decoder_rate=decoder_rate,
                                 receiver_profile='grc_reference' if use_reference else None,
                                 hardware_tuning_summary=tuning_summary)
    except Exception as exc:
        print('AIS live RX error: %s: %s' % (type(exc).__name__, exc), file=sys.stderr, flush=True)
        return 0 if STOP.is_set() else 1


if __name__ == '__main__':
    raise SystemExit(main())
