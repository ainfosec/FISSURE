#! /usr/bin/env python3
"""Dummy Target Operation

Fabricates junk files + zips them, then reports a target patch via target_callback.
"""

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from typing import Any, Callable, Union

try:
    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT
except ImportError:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT


def _to_float(v: Any, default: float) -> float:
    try:
        if v is None:
            return float(default)
        return float(v)
    except Exception:
        return float(default)


def _to_str(v: Any, default: str) -> str:
    if v is None:
        return default
    s = str(v).strip()
    return s if s else default


def _clamp(x: float, lo: float, hi: float) -> float:
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


class OperationMain(Operation):
    """Dummy Target Operation"""

    HARDCODED_MODEL_CONFIDENCE = 0.75  # 0..1

    def __init__(
        self,
        frequency_mhz: float = 311.0,
        display_label: str = "Garage Door Opener",
        ce_m: float = 50.0,
        description: str = "Dummy Target",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        status_callback: Union[Callable, None] = None,
        target_callback: Union[Callable, None] = None,
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

        self.frequency_mhz = _to_float(frequency_mhz, 311.0)
        self.display_label = _to_str(display_label, "Garage Door Opener")
        self.ce_m = _clamp(_to_float(ce_m, 50.0), 1.0, 10000.0)
        self.description = _to_str(description, "Dummy Target")

        self.model_conf = float(self.HARDCODED_MODEL_CONFIDENCE)

        self.logger.info(
            "dummy_target init params: "
            f"frequency_mhz={self.frequency_mhz}, display_label={self.display_label}, "
            f"ce_m={self.ce_m}, description={self.description}"
        )

        self.resource_args = {"frequency_mhz": self.frequency_mhz}

    async def _maybe_await(self, result):
        if asyncio.iscoroutine(result) or isinstance(result, asyncio.Future):
            return await result
        return result

    async def _emit_target_patch(
        self,
        target_id: str,
        patch: dict,
        history_entry: dict = None,
        artifact_id: str = "",
    ) -> None:
        cb = self.target_callback
        if not cb:
            return

        try:
            await self._maybe_await(
                cb(
                    target_id=target_id,
                    patch=patch,
                    history_entry=history_entry or {},
                    artifact_id=artifact_id or "",
                )
            )
            return
        except TypeError as e:
            self.logger.warning(f"target_callback keyword call failed: {e}")

        # Only use payload-dict fallback if your framework explicitly supports it.
        try:
            await self._maybe_await(
                cb({
                    "target_id": target_id,
                    "patch": patch,
                    "history_entry": history_entry or {},
                    "artifact_id": artifact_id or "",
                })
            )
        except Exception as e:
            self.logger.error(f"target_callback patch emit failed: {e}")
            raise

    async def run(self) -> None:
        if not self.target_callback:
            raise RuntimeError("dummy_target requires target_callback to be wired")
        if not self.artifact_manager:
            raise RuntimeError("dummy_target requires artifact_manager to be passed in")

        target_id = f"tgt-{uuid.uuid4()}"
        operation_id = str(uuid.uuid4())
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        classification = {
            "display_label": self.display_label,
            "candidates": [
                {"source": "database", "label": self.display_label},
                {"source": "model", "label": self.display_label, "confidence": self.model_conf},
            ],
        }

        lat = 41.2457
        lon = -76.9983
        alt = 0.0

        location = {
            "lat": lat,
            "lon": lon,
            "hae_m": alt,
            "ce_m": self.ce_m,
            "timestamp": now_iso,
            "source": "dummy",
        }

        _, capture_folder = self.artifact_manager.create_operation_dir(operation_id)

        if self.status_callback:
            await self.status_callback("Running: Dummy Target")

        bin_count = 3
        bin_size_kb = 256
        bytes_total = bin_size_kb * 1024
        chunk = 256 * 1024

        for i in range(bin_count):
            if self._stop:
                return

            path = os.path.join(capture_folder, f"target_blob_{i:03d}.bin")
            with open(path, "wb") as f:
                remaining = bytes_total
                while remaining > 0:
                    if self._stop:
                        return
                    n = min(chunk, remaining)
                    f.write(os.urandom(n))
                    remaining -= n

            await asyncio.sleep(0)

        if self._stop:
            return

        snapshot_path = os.path.join(capture_folder, "target_snapshot.json")
        with open(snapshot_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "target_id": target_id,
                    "node_uid": self.node_uid,
                    "frequency_mhz": self.frequency_mhz,
                    "classification": classification,
                    "location": location,
                    "state": "detected",
                    "created_time": now_iso,
                },
                f,
                indent=2,
            )

        artifact_id = self.artifact_manager.create_zip_artifact_from_folder(
            source_id="",
            operation_id=operation_id,
            folder=capture_folder,
            name=f"Dummy Target evidence @ {self.frequency_mhz} MHz",
            metadata={
                "role": "target_evidence_dummy_v1",
                "target_id": target_id,
                "operation_id": operation_id,
                "frequency_mhz": self.frequency_mhz,
                "display_label": self.display_label,
            },
            arc_prefix=f"target_{operation_id}",
        )

        patch = {
            "target_id": target_id,
            "node_uid": self.node_uid,
            "source_soi_id": "",

            "created_time": now_iso,
            "frequency_mhz": self.frequency_mhz,

            "classification": classification,
            "location": location,

            "state": "detected",

            "geolocate": {
                "status": "idle",
                "mode": "",
                "plugin": "",
                "action": "",
                "node_uids": [],
                "error": "",
                "updated_time": "",
            },
        }

        await self._emit_target_patch(
            target_id=target_id,
            patch=patch,
            history_entry={
                "event": "dummy_target_created",
                "artifact_id": artifact_id,
                "operation_id": operation_id,
            },
            artifact_id=artifact_id,
        )

        self.logger.info(
            f"Dummy Target complete: target_id={target_id}, "
            f"artifact_id={artifact_id}, opid={operation_id}"
        )


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})