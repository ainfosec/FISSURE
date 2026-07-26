#! /usr/bin/env python3
"""Dummy Target reference operation.

This operation is intentionally feature-rich. It serves as an executable
example of how a plugin should create or update a Target, register a logical
multifile Target artifact, relate that artifact to the Target, and append a
deduplicated operational-history entry.
"""

from __future__ import annotations

import asyncio
import csv
import json
import logging
import os
import sys
import time
import uuid

from typing import Any, Callable, Dict, List, Optional, Union


try:
    from fissure.utils.plugins.operations import Operation
except ImportError:
    sys.path.insert(
        0,
        os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "../../..",
            )
        ),
    )

    from fissure.utils.plugins.operations import Operation


def _to_float(
    value: Any,
    default: float,
) -> float:
    try:
        if value is None:
            return float(default)

        return float(value)

    except Exception:
        return float(default)


def _to_int(
    value: Any,
    default: int,
) -> int:
    try:
        if value is None:
            return int(default)

        return int(float(value))

    except Exception:
        return int(default)


def _to_str(
    value: Any,
    default: str = "",
) -> str:
    if value is None:
        return default

    text = str(value).strip()

    return text if text else default


def _to_bool(
    value: Any,
    default: bool = False,
) -> bool:
    if isinstance(value, bool):
        return value

    if value is None:
        return default

    return str(value).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
        "enabled",
    }


def _clamp(
    value: float,
    minimum: float,
    maximum: float,
) -> float:
    return max(
        minimum,
        min(
            maximum,
            value,
        ),
    )


class OperationMain(Operation):
    """Reference implementation for creating and updating Targets."""

    def __init__(
        self,
        target_id: str = "",
        source_soi_id: str = "",
        frequency_mhz: float = 315.0,
        display_label: str = "Garage Door Opener",
        protocol: str = "OOK",
        subtype: str = "Fixed Code Remote",
        manufacturer: str = "FISSURE Test Devices",
        model: str = "DT-315",
        device_id: str = "DUMMY-315-0001",
        serial_number: str = "SN-DUMMY-0001",
        channel: int = 1,
        state: str = "active",
        confidence_pct: float = 96.0,
        rssi_dbm: float = -43.5,
        ce_m: float = 25.0,
        use_node_location: Union[str, bool] = True,
        observation_count: int = 5,
        blob_size_kb: int = 128,
        description: str = "Dummy Target reference implementation",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(
            __name__
        ),
        alert_callback: Optional[
            Callable
        ] = None,
        tak_cot_callback: Optional[
            Callable
        ] = None,
        status_callback: Optional[
            Callable
        ] = None,
        target_callback: Optional[
            Callable
        ] = None,
        artifact_manager=None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            status_callback=status_callback,
            target_callback=target_callback,
            artifact_manager=artifact_manager,
        )

        self.requested_target_id = _to_str(
            target_id
        )
        self.source_soi_id = _to_str(
            source_soi_id
        )

        self.frequency_mhz = _to_float(
            frequency_mhz,
            315.0,
        )
        self.display_label = _to_str(
            display_label,
            "Garage Door Opener",
        )
        self.protocol = _to_str(
            protocol,
            "OOK",
        )
        self.subtype = _to_str(
            subtype,
            "Fixed Code Remote",
        )
        self.manufacturer = _to_str(
            manufacturer,
            "FISSURE Test Devices",
        )
        self.model = _to_str(
            model,
            "DT-315",
        )
        self.device_id = _to_str(
            device_id,
            "DUMMY-315-0001",
        )
        self.serial_number = _to_str(
            serial_number,
            "SN-DUMMY-0001",
        )
        self.channel = max(
            1,
            _to_int(
                channel,
                1,
            ),
        )
        self.state = _to_str(
            state,
            "active",
        )
        self.confidence_pct = _clamp(
            _to_float(
                confidence_pct,
                96.0,
            ),
            0.0,
            100.0,
        )
        self.rssi_dbm = _to_float(
            rssi_dbm,
            -43.5,
        )
        self.ce_m = _clamp(
            _to_float(
                ce_m,
                25.0,
            ),
            1.0,
            10000.0,
        )
        self.use_node_location = _to_bool(
            use_node_location,
            True,
        )
        self.observation_count = max(
            1,
            min(
                100,
                _to_int(
                    observation_count,
                    5,
                ),
            ),
        )
        self.blob_size_kb = max(
            1,
            min(
                10240,
                _to_int(
                    blob_size_kb,
                    128,
                ),
            ),
        )
        self.description = _to_str(
            description,
            "Dummy Target reference implementation",
        )

        self.resource_args = {
            "frequency_mhz":
                self.frequency_mhz,
        }

    async def _maybe_await(
        self,
        result,
    ):
        if (
            asyncio.iscoroutine(
                result
            )
            or isinstance(
                result,
                asyncio.Future,
            )
        ):
            return await result

        return result

    async def _set_status(
        self,
        message: str,
    ) -> None:
        if not self.status_callback:
            return

        await self._maybe_await(
            self.status_callback(
                message
            )
        )

    async def _emit_target_patch(
        self,
        *,
        target_id: str,
        patch: Dict[str, Any],
        history_entry: Dict[
            str,
            Any,
        ],
        artifact_id: str,
    ) -> None:
        if not self.target_callback:
            raise RuntimeError(
                "dummy_target requires "
                "target_callback to be wired"
            )

        try:
            await self._maybe_await(
                self.target_callback(
                    target_id=target_id,
                    patch=patch,
                    history_entry=(
                        history_entry
                    ),
                    artifact_id=(
                        artifact_id
                    ),
                )
            )
            return

        except TypeError as exc:
            self.logger.warning(
                "Target callback keyword "
                "call failed; trying payload "
                "fallback: %s",
                exc,
            )

        await self._maybe_await(
            self.target_callback(
                {
                    "target_id":
                        target_id,
                    "patch":
                        patch,
                    "history_entry":
                        history_entry,
                    "artifact_id":
                        artifact_id,
                }
            )
        )

    def _build_identity(
        self,
    ) -> Dict[str, Any]:
        return {
            "protocol":
                self.protocol,
            "subtype":
                self.subtype,
            "manufacturer":
                self.manufacturer,
            "model":
                self.model,
            "device_id":
                self.device_id,
            "serial_number":
                self.serial_number,
            "channel":
                self.channel,
            "network_id":
                "dummy-network-001",
            "talkgroup_id":
                "dummy-talkgroup-7",
            "callsign":
                "DUMMY-TARGET",
            "communicates_with": [
                "dummy-controller-01",
                "dummy-receiver-02",
            ],
        }

    def _build_classification(
        self,
    ) -> Dict[str, Any]:
        confidence_fraction = (
            self.confidence_pct
            / 100.0
        )

        return {
            "display_label":
                self.display_label,
            "selected_source":
                "dummy_reference",
            "confidence":
                confidence_fraction,
            "confidence_pct":
                self.confidence_pct,
            "candidates": [
                {
                    "source":
                        "database",
                    "label":
                        self.display_label,
                    "confidence":
                        1.0,
                },
                {
                    "source":
                        "model",
                    "label":
                        self.display_label,
                    "confidence":
                        confidence_fraction,
                },
            ],
        }

    def _build_location(
        self,
        now_iso: str,
    ) -> Dict[str, Any]:
        if self.use_node_location:
            return {
                # True is resolved by SensorNode using the current node
                # location and time before forwarding the Target patch.
                "lat": True,
                "lon": True,
                "hae_m": True,
                "ce_m": self.ce_m,
                "timestamp": True,
                "source":
                    "sensor_node_current",
            }

        return {
            "lat": 42.089800,
            "lon": -76.807700,
            "hae_m": 320.0,
            "ce_m": self.ce_m,
            "timestamp": now_iso,
            "source":
                "dummy_fixed",
        }

    def _build_observations(
        self,
        operation_id: str,
        now_epoch: float,
    ) -> List[Dict[str, Any]]:
        observations = []

        for index in range(
            self.observation_count
        ):
            timestamp_epoch = (
                now_epoch
                - (
                    self.observation_count
                    - index
                    - 1
                )
                * 2.0
            )

            observations.append(
                {
                    "sequence":
                        index + 1,
                    "operation_id":
                        operation_id,
                    "timestamp":
                        time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ",
                            time.gmtime(
                                timestamp_epoch
                            ),
                        ),
                    "frequency_mhz":
                        round(
                            self.frequency_mhz
                            + (
                                index
                                - (
                                    self.observation_count
                                    / 2.0
                                )
                            )
                            * 0.0002,
                            6,
                        ),
                    "rssi_dbm":
                        round(
                            self.rssi_dbm
                            + (
                                index
                                % 3
                            )
                            - 1.0,
                            1,
                        ),
                    "protocol":
                        self.protocol,
                    "device_id":
                        self.device_id,
                    "channel":
                        self.channel,
                }
            )

        return observations

    def _write_reference_files(
        self,
        *,
        files_dir: str,
        target_id: str,
        operation_id: str,
        now_iso: str,
        classification: Dict[
            str,
            Any,
        ],
        identity: Dict[
            str,
            Any,
        ],
        location: Dict[
            str,
            Any,
        ],
        observations: List[
            Dict[str, Any]
        ],
    ):
        snapshot_path = os.path.join(
            files_dir,
            "target_snapshot.json",
        )

        observations_path = os.path.join(
            files_dir,
            "observations.csv",
        )

        decoded_path = os.path.join(
            files_dir,
            "decoded_messages.jsonl",
        )

        notes_path = os.path.join(
            files_dir,
            "operator_notes.txt",
        )

        blob_path = os.path.join(
            files_dir,
            "sample_capture.bin",
        )

        snapshot = {
            "schema":
                "fissure.target.reference.v1",
            "target_id":
                target_id,
            "source_soi_id":
                self.source_soi_id,
            "operation_id":
                operation_id,
            "node_uid":
                self.node_uid,
            "created_time":
                now_iso,
            "frequency_mhz":
                self.frequency_mhz,
            "classification":
                classification,
            "identity":
                identity,
            "location":
                location,
            "state":
                self.state,
            "rf": {
                "center_frequency_mhz":
                    self.frequency_mhz,
                "modulation":
                    self.protocol,
                "bandwidth_khz":
                    25.0,
                "rssi_dbm":
                    self.rssi_dbm,
            },
            "observations":
                observations,
            "description":
                self.description,
        }

        with open(
            snapshot_path,
            "w",
            encoding="utf-8",
        ) as stream:
            json.dump(
                snapshot,
                stream,
                indent=2,
                default=str,
            )

        with open(
            observations_path,
            "w",
            newline="",
            encoding="utf-8",
        ) as stream:
            writer = csv.DictWriter(
                stream,
                fieldnames=[
                    "sequence",
                    "operation_id",
                    "timestamp",
                    "frequency_mhz",
                    "rssi_dbm",
                    "protocol",
                    "device_id",
                    "channel",
                ],
            )

            writer.writeheader()
            writer.writerows(
                observations
            )

        with open(
            decoded_path,
            "w",
            encoding="utf-8",
        ) as stream:
            for observation in (
                observations
            ):
                decoded_record = {
                    "timestamp":
                        observation[
                            "timestamp"
                        ],
                    "target_id":
                        target_id,
                    "device_id":
                        self.device_id,
                    "message_type":
                        "button_press",
                    "button":
                        (
                            "open"
                            if observation[
                                "sequence"
                            ]
                            % 2
                            else "close"
                        ),
                    "rolling_code":
                        (
                            100000
                            + observation[
                                "sequence"
                            ]
                        ),
                    "crc_valid":
                        True,
                }

                stream.write(
                    json.dumps(
                        decoded_record
                    )
                    + "\n"
                )

        with open(
            notes_path,
            "w",
            encoding="utf-8",
        ) as stream:
            stream.write(
                "Dummy Target reference operation\n"
            )
            stream.write(
                "================================\n\n"
            )
            stream.write(
                f"Target ID: {target_id}\n"
            )
            stream.write(
                f"Operation ID: {operation_id}\n"
            )
            stream.write(
                f"Source SOI ID: "
                f"{self.source_soi_id or '(none)'}\n"
            )
            stream.write(
                f"Classification: "
                f"{self.display_label}\n"
            )
            stream.write(
                f"Device ID: "
                f"{self.device_id}\n"
            )
            stream.write(
                f"Frequency: "
                f"{self.frequency_mhz} MHz\n"
            )
            stream.write(
                f"Description: "
                f"{self.description}\n\n"
            )
            stream.write(
                "This operation demonstrates "
                "canonical Target identity, "
                "history, artifact relations, "
                "and multifile artifact "
                "registration.\n"
            )

        bytes_remaining = (
            self.blob_size_kb
            * 1024
        )

        with open(
            blob_path,
            "wb",
        ) as stream:
            while bytes_remaining > 0:
                if self._stop:
                    break

                chunk_size = min(
                    bytes_remaining,
                    64 * 1024,
                )

                stream.write(
                    os.urandom(
                        chunk_size
                    )
                )

                bytes_remaining -= (
                    chunk_size
                )

        files = [
            snapshot_path,
            observations_path,
            decoded_path,
            notes_path,
            blob_path,
        ]

        file_metadata = {
            snapshot_path: {
                "role":
                    "target_snapshot",
                "content_type":
                    "application/json",
                "schema":
                    "fissure.target.reference.v1",
            },
            observations_path: {
                "role":
                    "observation_log",
                "content_type":
                    "text/csv",
                "observation_count":
                    len(observations),
            },
            decoded_path: {
                "role":
                    "decoded_messages",
                "content_type":
                    "application/x-ndjson",
                "message_count":
                    len(observations),
            },
            notes_path: {
                "role":
                    "operator_notes",
                "content_type":
                    "text/plain",
            },
            blob_path: {
                "role":
                    "sample_capture",
                "content_type":
                    "application/octet-stream",
                "frequency_mhz":
                    self.frequency_mhz,
                "sample_format":
                    "dummy_bytes",
            },
        }

        return files, file_metadata

    async def run(
        self,
    ) -> None:
        if not self.target_callback:
            raise RuntimeError(
                "dummy_target requires "
                "target_callback to be wired"
            )

        if not self.artifact_manager:
            raise RuntimeError(
                "dummy_target requires "
                "artifact_manager to be passed in"
            )

        target_id = (
            self.requested_target_id
            or f"tgt-{uuid.uuid4()}"
        )

        operation_id = str(
            getattr(
                self,
                "opid",
                "",
            )
            or uuid.uuid4()
        )

        now_epoch = time.time()

        now_iso = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(
                now_epoch
            ),
        )

        await self._set_status(
            "Running: Build Dummy Target reference data"
        )

        classification = (
            self._build_classification()
        )
        identity = (
            self._build_identity()
        )
        location = (
            self._build_location(
                now_iso
            )
        )
        observations = (
            self._build_observations(
                operation_id,
                now_epoch,
            )
        )

        _, files_dir = (
            self.artifact_manager
            .create_operation_dir(
                operation_id
            )
        )

        files, file_metadata = (
            self._write_reference_files(
                files_dir=files_dir,
                target_id=target_id,
                operation_id=operation_id,
                now_iso=now_iso,
                classification=(
                    classification
                ),
                identity=identity,
                location=location,
                observations=(
                    observations
                ),
            )
        )

        if self._stop:
            await self._set_status(
                "Stopped: Dummy Target"
            )
            return

        await self._set_status(
            "Running: Register Dummy Target artifact"
        )

        artifact_id = (
            self.artifact_manager
            .create_artifact(
                source_id=str(
                    self.node_uid
                    or "sensor_node"
                ),
                operation_id=(
                    operation_id
                ),
                files=files,
                name=(
                    "Dummy Target reference data "
                    f"for {target_id}"
                ),
                artifact_type=(
                    "target_reference"
                ),
                metadata={
                    "workflow":
                        "dummy_target",
                    "role":
                        "target_operation_data",
                    "target_id":
                        target_id,
                    "source_soi_id":
                        self.source_soi_id,
                    "operation_id":
                        operation_id,
                    "node_uid":
                        self.node_uid,
                    "frequency_mhz":
                        self.frequency_mhz,
                    "display_label":
                        self.display_label,
                    "protocol":
                        self.protocol,
                    "device_id":
                        self.device_id,
                    "observation_count":
                        len(observations),
                    "description":
                        self.description,
                    "created_time":
                        now_iso,
                },
                relations=[
                    (
                        "target",
                        target_id,
                        "operation_data",
                    )
                ],
                file_metadata=(
                    file_metadata
                ),
            )
        )

        if not artifact_id:
            raise RuntimeError(
                "Dummy Target artifact "
                "registration failed"
            )

        artifact_link = {
            "artifact_id":
                artifact_id,
            "operation_id":
                operation_id,
            "role":
                "operation_data",
            "description":
                self.description,
            "created_time":
                now_iso,
        }

        patch = {
            "target_id":
                target_id,
            "node_uid":
                self.node_uid,
            "source_soi_id":
                self.source_soi_id,

            "created_time":
                now_iso,
            "frequency_mhz":
                self.frequency_mhz,
            "state":
                self.state,

            "classification":
                classification,
            "identity":
                identity,
            "location":
                location,

            "rf": {
                "center_frequency_mhz":
                    self.frequency_mhz,
                "modulation":
                    self.protocol,
                "bandwidth_khz":
                    25.0,
                "rssi_dbm":
                    self.rssi_dbm,
                "last_observation_time":
                    True,
            },

            "observation_summary": {
                "count":
                    len(observations),
                "first_seen":
                    observations[0][
                        "timestamp"
                    ],
                "last_seen":
                    observations[-1][
                        "timestamp"
                    ],
                "latest_rssi_dbm":
                    observations[-1][
                        "rssi_dbm"
                    ],
            },

            "geolocate": {
                "status":
                    "idle",
                "mode":
                    "",
                "plugin":
                    "",
                "action":
                    "",
                "node_uids": [],
                "had_detections":
                    True,
                "error":
                    "",
                "updated_time":
                    now_iso,
            },

            "artifact_id":
                artifact_id,
            "artifact_ids": [
                artifact_id
            ],
            "artifact_links": [
                artifact_link
            ],

            "description":
                self.description,
        }

        history_entry = {
            "event":
                (
                    "dummy_target_updated"
                    if self.requested_target_id
                    else "dummy_target_created"
                ),
            "operation_id":
                operation_id,
            "artifact_id":
                artifact_id,
            "artifact_ids": [
                artifact_id
            ],
            "role":
                "reference_operation",
            "plugin":
                "Dummy",
            "action":
                "dummy_target",
            "node_uid":
                self.node_uid,
            "timestamp":
                now_iso,
            "state":
                self.state,
            "frequency_mhz":
                self.frequency_mhz,
            "display_label":
                self.display_label,
            "observation_count":
                len(observations),
            "description":
                self.description,
        }

        await self._set_status(
            "Running: Publish Dummy Target"
        )

        await self._emit_target_patch(
            target_id=target_id,
            patch=patch,
            history_entry=(
                history_entry
            ),
            artifact_id=artifact_id,
        )

        await self._set_status(
            "Finished: Dummy Target"
        )

        self.logger.info(
            "Dummy Target complete: "
            "target_id=%s operation_id=%s "
            "artifact_id=%s files=%s",
            target_id,
            operation_id,
            artifact_id,
            len(files),
        )


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import (
        run_test,
    )

    run_test(
        OperationMain,
        {},
        {},
    )
