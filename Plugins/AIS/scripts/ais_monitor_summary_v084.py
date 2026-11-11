"""Compact AIS live RX session summary, without recording raw IQ.

After streaming stops, publish one bounded vessel-state JSON Artifact rather
than retaining raw IQ, per-message NMEA files or per-message Artifacts.
"""
from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path

SUMMARY_MAX_VESSELS = 20000
FIELDS = ('first_seen', 'last_seen', 'count', 'ship_name', 'callsign',
          'ship_type', 'latitude', 'longitude', 'speed_kt', 'course_deg',
          'heading_deg', 'destination', 'last_message_type')


def create_monitor_summary(operation, device, segments, reason, streaming=False):
    if operation.artifact_manager is None:
        return ''
    _, directory = operation.artifact_manager.create_operation_dir(operation.opid)
    path = Path(directory) / ('ais_%s_monitor_summary.json' % device)
    vessels = operation._vessels
    # One record per distinct MMSI, never one record per AIS message.
    entries = []
    for mmsi, state in sorted(vessels.items())[:SUMMARY_MAX_VESSELS]:
        entry = {'mmsi': str(mmsi)}
        entry.update({key: state[key] for key in FIELDS if key in state})
        entries.append(entry)
    metadata = {
        'schema': 'fissure.ais.monitor_summary.v1',
        'operation_id': operation.opid,
        'node_uid': operation.node_uid,
        'receiver': device,
        'completion_reason': reason,
        'completed_at_utc': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'decoded_messages': operation._message_count,
        'unique_mmsi': len(vessels),
        'vessels_in_summary': len(entries),
        'vessel_list_truncated': len(vessels) > len(entries),
        'capture_segments': int(segments),
        'simulated': bool(getattr(operation, '_simulated', False)),
        'continuous_mode': operation.duration_s == 0,
        'segment_s': 0 if streaming else 20,
        'streaming_mode': bool(streaming),
        'capture_gaps_possible': not streaming,
        'raw_iq_archived': False,
        'rx_frequency_control': str(getattr(operation, '_rx_frequency_control',
                                           'auto_on_gr310_legacy_gr38_unchanged')), 
        'auto_frequency_diagnostics': str(getattr(operation, '_auto_frequency_text', ''))[:400],
        'auto_frequency_lock': str(getattr(operation, '_auto_frequency_lock_text', ''))[:400],
        'b210_uhd_tuning': str(getattr(operation, '_b210_uhd_tune_text', ''))[:400],
        'decoder_configuration': str(getattr(operation, '_decoder_start_text', ''))[:400],
        'receive_diagnostics': [str(x)[:400] for x in
                                (getattr(operation, '_rx_stream_diagnostics', []) or [])[-20:]],
        'detection_delivery': dict(getattr(operation, '_rx_detection_delivery', {}) or {}),
        'raw_nmea_archived': False,
        'position_semantics': 'ais_self_reported_not_rf_geolocation',
    }
    path.write_text(json.dumps({'metadata': metadata, 'vessels': entries},
                               sort_keys=True, indent=2, default=str) + '\n',
                    encoding='utf-8')
    result = operation.create_artifact(
        files=[str(path)],
        name='AIS %s RX Monitoring Summary' % str(device).upper(),
        artifact_type='ais_rx_monitor_summary',
        metadata=metadata,
    )
    if not result:
        raise RuntimeError('AIS RX monitoring summary Artifact registration failed')
    return str(result)
