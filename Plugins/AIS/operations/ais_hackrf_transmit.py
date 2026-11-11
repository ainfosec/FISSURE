#!/usr/bin/env python3
"""Finite synthetic AIS GMSK TX over HackRF One via gr-osmosdr.

HackRF must not be used on live maritime AIS channels; only shielded,
receiver-safe authorized test setups. HackRF is half-duplex.
"""
from __future__ import annotations
import asyncio
import json
import logging
from pathlib import Path
import sys
from typing import Callable, Optional

ROOT = Path(__file__).resolve().parents[1]
for loc in (ROOT / 'operations', ROOT / 'scripts'):
    if str(loc) not in sys.path:
        sys.path.insert(0, str(loc))
from ais_iq_loopback import OperationMain as AISIQLoopback, sha256_file
from ais_codec import boolean, require_pyais
from ais_sdr_operation_runtime import AISB210OperationRuntime
from ais_osmosdr_hardware import validate_tx
from ais_device_lock_v081 import lock_radio as _lock_radio, unlock_radio as _unlock_radio


from ais_status_runtime_v091 import AISStatusMixin
from ais_tx_repeat_v093 import validate_repeat_settings, send_repeated_batches


class OperationMain(AISStatusMixin, AISIQLoopback, AISB210OperationRuntime):
    # Explicit override survives stale ais_sdr_operation_runtime in Sensor Node.
    lock_radio = _lock_radio
    unlock_radio = _unlock_radio

    def __init__(self, vessel_count=3, position_updates=3, include_static_data=True,
                 base_latitude=40.722, base_longitude=-74.020,
                 gap_ms=350, rf_frequency=915000000, device_args='',
                 tx_gain=40, save_tx_artifact=False, repeat_count=0, repeat_pause_s=2.0,
                 tx_backend='auto',
                 node_uid='', logger=logging.getLogger(__name__),
                 detection_callback: Optional[Callable] = None,
                 target_callback: Optional[Callable] = None,
                 status_callback: Optional[Callable] = None, artifact_manager=None):
        super().__init__(vessel_count=vessel_count, position_updates=position_updates,
                         include_static_data=include_static_data,
                         base_latitude=base_latitude, base_longitude=base_longitude,
                         sample_rate=240000, gap_ms=gap_ms, emit_targets=False,
                         node_uid=node_uid, logger=logger,
                         detection_callback=detection_callback,
                         target_callback=target_callback,
                         status_callback=status_callback,
                         artifact_manager=artifact_manager)
        self.rf_frequency = float(rf_frequency)
        self.device_args = str(device_args or '').strip()
        self.tx_gain = float(tx_gain)
        self.tx_backend = str(tx_backend or 'auto').strip().lower()
        if self.tx_backend not in ('auto', 'native', 'osmosdr'):
            raise ValueError('TX backend must be auto, native or osmosdr')
        self.save_tx_artifact = boolean(save_tx_artifact, False)
        self.repeat_count, self.repeat_pause_s = validate_repeat_settings(repeat_count, repeat_pause_s)
        self.tx_batches_completed = 0
        self._last_tx_backend = ''
        validate_tx(self.rf_frequency, self.tx_gain, self.device_args or 'hackrf=0')

    @staticmethod
    def get_resources():
        return {}

    async def run(self):
        require_pyais()
        if not self.artifact_manager:
            raise RuntimeError('AIS HackRF TX requires FISSURE ArtifactManager for temporary files')
        self.lock_radio('hackrf')
        try:
            _, folder = self.artifact_manager.create_operation_dir(self.opid)
            folder = Path(folder)
            source = folder / 'ais_hackrf_tx.nmea'
            iq = folder / 'ais_hackrf_tx.cf32'
            gen_manifest = folder / 'ais_hackrf_tx_iq_manifest.json'
            hw_manifest = folder / 'ais_hackrf_tx_hardware.json'
            count = self._create_nmea(source)
            await self._status('AIS HackRF TX: generating %d synthetic messages' % count)
            await self.call_sdr_process([
                sys.executable, '-u', str(ROOT / 'scripts' / 'ais_iq_generator.py'),
                '--input', str(source), '--output', str(iq),
                '--manifest', str(gen_manifest), '--sample-rate', '240000',
                '--gap-ms', str(self.gap_ms), '--max-frames', str(count)],
                180, 'HackRF AIS IQ generation', ROOT)
            generated = json.loads(gen_manifest.read_text())
            if generated.get('frame_count') != count or generated.get('skipped_nmea_sentences'):
                raise RuntimeError('AIS HackRF TX waveform generation was incomplete')
            await self._status('AIS HackRF TX: %.3f MHz, IF gain %.1f dB; batch repeat=%s, pause=%gs (lab only)' % (
                self.rf_frequency / 1e6, self.tx_gain,
                'until Stop' if not self.repeat_count else str(self.repeat_count), self.repeat_pause_s))

            async def transmit_once(batch_index):
                await self.call_sdr_process([
                    sys.executable, '-u', str(ROOT / 'scripts' / 'ais_osmosdr_hardware.py'),
                    '--mode', 'tx', '--device', 'hackrf', '--input', str(iq),
                    '--manifest', str(hw_manifest), '--rf-frequency', str(self.rf_frequency),
                    '--device-args', self.device_args, '--tx-gain', str(self.tx_gain),
                    '--tx-backend', self.tx_backend],
                    180, 'AIS HackRF RF TX batch %d' % batch_index, ROOT)
                info = json.loads(hw_manifest.read_text())
                if info.get('rf_transmitted') is not True:
                    raise RuntimeError('AIS HackRF TX batch %d did not finish' % batch_index)
                self._last_tx_backend = str(info.get('tx_backend') or '')
                if batch_index == 1:
                    await self._status('AIS HackRF TX backend: %s, radio IQ rate %.1f MS/s' % (
                        self._last_tx_backend, float(info.get('radio_sample_rate_hz', 0)) / 1e6))

            batches = await send_repeated_batches(self, transmit_once, count, 'AIS HackRF TX')
            if self.save_tx_artifact:
                self.create_artifact(
                    files=[str(source), str(iq), str(gen_manifest), str(hw_manifest)],
                    name='AIS HackRF TX Stimulus', artifact_type='ais_sdr_tx_stimulus',
                    metadata={'schema': 'fissure.ais.hackrf_tx_stimulus.v1',
                              'operation_id': self.opid, 'device': 'HackRF',
                              'synthetic': True, 'rf_transmitted': True,
                              'messages': count, 'iq_sha256': sha256_file(iq),
                              'nmea_sha256': sha256_file(source),
                              'rf_frequency_hz': self.rf_frequency,
                              'repeat_count': self.repeat_count,
                              'completed_batches': self.tx_batches_completed,
                              'messages_sent': self.tx_batches_completed * count})
            await self._status('AIS HackRF TX %s: %d batches / %d messages; saved IQ Artifact: %s' % (
                'stopped' if self._stop else 'complete', batches, batches * count, self.save_tx_artifact))
        except Exception as exc:
            self.logger.exception("AIS HackRF TX failed: %s", exc)
            await self._status("AIS HackRF TX failed: %s" % exc)
            raise
        finally:
            await self.stop_sdr_process()
            await self._stop_generator()
            self.unlock_radio()
