"""Shared lifetime and FISSURE routing for persistent AIS SDR monitoring.

B210 -> UHD directly feeding gr-ais. RTL/HackRF -> native IQ8 pipe ->
polyphase decimator -> gr-ais. No IQ files or per-message Artifacts are made.
"""
from __future__ import annotations

import asyncio
from collections import deque
import inspect
from pathlib import Path
import sys
import time

from ais_codec import require_pyais
from ais_monitor_summary_v084 import create_monitor_summary

PLUGIN = Path(__file__).resolve().parents[1]


def build_stream_command(op, radio):
    if radio == 'b210':
        return [sys.executable, '-u', str(PLUGIN / 'scripts' / 'ais_live_decoder.py'),
                '--source', 'b210', '--sample-rate', str(op.sample_rate),
                '--rf-frequency', str(op.rf_frequency), '--device-args', op.device_args,
                '--rx-gain', str(op.rx_gain),
                '--rf-channel', str(getattr(op, 'rf_channel', 0)),
                '--rx-antenna', str(getattr(op, 'rx_antenna', 'TX/RX'))]
    cmd = [sys.executable, '-u', str(PLUGIN / 'scripts' / 'ais_native_stream.py'),
           '--device', radio, '--rf-frequency', str(op.rf_frequency),
           '--device-args', op.device_args]
    if radio == 'rtl':
        cmd.extend(['--rx-gain', str(op.rx_gain)])
    else:
        cmd.extend(['--lna-gain', str(op.lna_gain), '--vga-gain', str(op.vga_gain)])
    return cmd


async def run_stream_monitor(op, radio):
    """Receive decoded NMEA continuously while one hardware stream stays open.

    `duration_s=0` monitors until FISSURE Stop. Every positive duration
    monitors for the requested wall-clock time; no IQ file is created.
    """
    require_pyais()
    if op.artifact_manager is None:
        raise RuntimeError('AIS live RX requires FISSURE ArtifactManager for final session summary')
    interval = float(getattr(op, 'detection_interval_s', 5.0))
    if not 0 <= interval <= 3600:
        raise ValueError('AIS streaming Detection interval must be 0..3600 seconds')
    if radio == 'b210':
        op.lock_b210()
        unlock = op.unlock_b210
    else:
        op.lock_radio(radio)
        unlock = op.unlock_radio

    proc = None
    stderr_task = None
    stop_watcher_task = None
    diag = deque(maxlen=40)
    reason = 'finished'
    original_artifact_setting = op.save_artifact
    original_detection_callback = op.detection_callback
    last_det = {}
    # Apply independent limits to position and static AIS observations.
    # Static Type 24 reports arrive first in our demo TX; the older shared
    # limit suppressed the subsequent position reports for 30 seconds, leaving
    # Tactical without the geolocated Detections although Targets updated.
    # These are callback handoff counts, not Dashboard row counts. A successful
    # callback means the Sensor Node accepted the Detection for routing.
    stats = {'generated': 0, 'callback_succeeded': 0,
             'throttled': 0, 'callback_missing': 0, 'callback_failed': 0,
             'position_generated': 0, 'position_callback_succeeded': 0,
             'position_throttled': 0, 'nonposition_generated': 0,
             'nonposition_callback_succeeded': 0}
    op._rx_detection_delivery = stats

    async def sampled_detection(detection):
        stats['generated'] += 1
        is_position = (detection.get('location_valid') is True and
                       detection.get('latitude') is not None and
                       detection.get('longitude') is not None)
        kind = 'position' if is_position else 'nonposition'
        stats[kind + '_generated'] += 1
        if original_detection_callback is None:
            stats['callback_missing'] += 1
            return None
        mmsi = str(detection.get('mmsi', ''))
        throttle_key = (mmsi, kind)
        now = time.monotonic()
        if interval and throttle_key in last_det and now - last_det[throttle_key] < interval:
            stats['throttled'] += 1
            if is_position:
                stats['position_throttled'] += 1
            return None
        try:
            result = original_detection_callback(detection)
            if inspect.isawaitable(result):
                result = await result
        except asyncio.CancelledError:
            raise
        except Exception:
            stats['callback_failed'] += 1
            raise
        # Advance the throttle only after a successful callback invocation.
        # Failure should not silence the next observation for this vessel.
        last_det[throttle_key] = time.monotonic()
        stats['callback_succeeded'] += 1
        stats[kind + '_callback_succeeded'] += 1
        return result

    async def stop_process_on_request():
        """Release the SDR as soon as Stop is requested, even during callbacks.

        The FISSURE Operation.stop wrapper only sets ``_stop`` and awaits
        ``run``. Without an independent monitor, a busy Detection/Target
        callback can delay reaching the stream loop's stop check, leaving the
        HackRF open even though the Dashboard requested Stop.
        """
        while not op._stop:
            await asyncio.sleep(0.05)
        if proc is not None:
            await op.stop_sdr_process()

    async def drain_stderr(reader):
        while True:
            line = await reader.readline()
            if not line:
                return
            message = line.decode('utf-8', 'replace').strip()
            if message:
                if message.startswith('AIS B210 RX UHD tune:'):
                    op._b210_uhd_tune_text = message[:400]
                elif 'AIS streaming decoder started:' in message:
                    op._decoder_start_text = message[:400]
                    op._rx_frequency_control = (
                        'automatic_gr310' if ('frequency_control=auto' in message or
                         'frequency_control=parallel_4_candidate' in message)
                        else 'legacy_gr38_builtin')
                elif 'AIS RX AFC:' in message:
                    op._auto_frequency_text = message[:400]
                    if 'valid HDLC frame; channel=' in message:
                        op._auto_frequency_lock_text = message[:400]
                diag.append(message[:600])
                if any(k in message.lower() for k in ('error', 'failed', 'overflow', 'drop', 'underflow')):
                    op.logger.warning('AIS %s stream: %s', radio, message)
                else:
                    op.logger.debug('AIS %s stream: %s', radio, message)

    try:
        op.save_artifact = False
        op.detection_callback = sampled_detection
        op.input_mode = '%s_stream' % radio
        op._input_metadata.update({
            'input_mode': '%s_stream' % radio,
            'rx_capture_backend': 'uhd_live_gr_ais' if radio == 'b210' else 'native_cli_stdout_gr_ais',
            'rf_center_frequency_hz': float(op.rf_frequency),
            'rx_requested_sample_rate_hz': float(op.sample_rate) if radio == 'b210' else None,
            'rx_native_sample_rate_hz': 2400000.0 if radio in ('rtl', 'hackrf') else None,
            'simulated': bool(op._simulated),
            'continuous_rf_stream': True,
            'capture_gaps_possible': False,
            'raw_iq_archived': False,
            'rx_frequency_control': 'auto_on_gr310_legacy_gr38_unchanged',
            'b210_gr310_reference_profile': radio == 'b210',
            'hackrf_gr310_reference_profile': radio == 'hackrf',
            'rx_detection_interval_per_mmsi_s': interval,
            'rx_detection_throttle_groups': 'per_mmsi_position_and_nonposition',
        })
        command = build_stream_command(op, radio)
        await op._status('AIS %s RX streaming at %.3f MHz until %s (no IQ files)' % (
            radio.upper(), op.rf_frequency / 1e6,
            'Stop' if not op.duration_s else '%.0f seconds' % op.duration_s))
        proc = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            cwd=str(PLUGIN), start_new_session=True,
        )
        # AIS native RX is a process tree (wrapper, hackrf_transfer/rtl_sdr,
        # GNU Radio decoder). Own a private session so Stop can signal all of it.
        op._sdr_process_group_id = proc.pid
        op._sdr_proc = proc
        # Stop is an independent hardware-control event, not contingent on
        # the NMEA message loop getting through callbacks promptly.
        stop_watcher_task = asyncio.create_task(stop_process_on_request())
        stderr_task = asyncio.create_task(drain_stderr(proc.stderr))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + op.duration_s if op.duration_s > 0 else None
        status_at = loop.time() + 15.0
        while not op._stop:
            now = loop.time()
            if deadline is not None and now >= deadline:
                break
            if now >= status_at:
                await op._status('AIS %s RX streaming: %d messages / %d MMSIs' % (
                    radio.upper(), op._message_count, len(op._vessels)))
                status_at = now + 15.0
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=0.25)
            except asyncio.TimeoutError:
                if proc.returncode is not None and proc.stdout.at_eof():
                    break
                continue
            if not line:
                break
            if line.startswith((b'!AIVDM,', b'!AIVDO,')):
                await op._receive(line.decode('ascii', 'replace'))
        if proc.returncode is not None and proc.returncode != 0 and not op._stop:
            raise RuntimeError('AIS %s stream exited %s: %s' % (
                radio, proc.returncode, '; '.join(diag)[-1500:] or 'no diagnostic output'))
        if op._stop:
            reason = 'stopped'
        elif deadline is not None and loop.time() >= deadline:
            reason = 'finished'
        else:
            await asyncio.wait_for(proc.wait(), timeout=2)
            if proc.returncode != 0:
                raise RuntimeError('AIS %s stream exited %s: %s' % (
                    radio, proc.returncode, '; '.join(diag)[-1500:] or 'no diagnostic output'))
            raise RuntimeError('AIS %s stream ended unexpectedly: %s' % (
                radio, '; '.join(diag)[-1500:] or 'device or decoder closed stream'))
    except asyncio.CancelledError:
        reason = 'stopped' if op._stop else 'cancelled'
        if not op._stop:
            raise
    except Exception as exc:
        reason = 'error'
        await op._status('AIS %s streaming RX failed: %s' % (radio, str(exc)[:220]))
        raise
    finally:
        op.detection_callback = original_detection_callback
        op.save_artifact = original_artifact_setting
        try:
            # The watcher may already be shutting down the process group;
            # cancel/join it before the final idempotent cleanup to avoid two
            # concurrent waits or signals against the same process group.
            if stop_watcher_task is not None:
                stop_watcher_task.cancel()
                await asyncio.gather(stop_watcher_task, return_exceptions=True)
            if proc is not None:
                await op.stop_sdr_process()
            if stderr_task:
                try:
                    await asyncio.wait_for(stderr_task, timeout=2.0)
                except asyncio.TimeoutError:
                    stderr_task.cancel()
        finally:
            op._sdr_proc = None
            op._sdr_process_group_id = None
            op._rx_stream_diagnostics = list(diag)[-20:]
            unlock()
            try:
                aid = create_monitor_summary(op, radio, 0, reason, streaming=True)
                op.logger.info('AIS %s streaming summary Artifact: %s', radio, aid)
            except Exception:
                op.logger.exception('AIS %s streaming summary Artifact failed', radio)
            await op._status('AIS %s streaming RX %s: %d messages / %d MMSIs / %d position Detections handed off (%d total, %d suppressed)' % (
                radio, reason, op._message_count, len(op._vessels),
                stats['position_callback_succeeded'], stats['callback_succeeded'],
                stats['throttled']))
