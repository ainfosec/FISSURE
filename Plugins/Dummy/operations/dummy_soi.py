#! /usr/bin/env python3
"""Dummy SOI Operation

Creates a small set of dummy evidence files, registers a zip artifact, and
emits SOI lifecycle updates via soi_callback.

UI/Action parameters (minimal):
  - frequency_mhz: float (default 915.0)
  - model_label: str (default "dummy_protocol")
  - model_confidence: int 0-100 (default 87)
  - description: str (default "Dummy SOI")
"""

import asyncio
import logging
import os
import sys
import time
import uuid
import json
from typing import Any, Callable, Dict, Union

try:
    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT
except ImportError:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT


class OperationMain(Operation):
    """Dummy SOI Operation"""

    def __init__(
        self,
        frequency_mhz: float = 915.0,
        model_label: str = "dummy_protocol",
        model_confidence: float = 87,
        description: str = "Dummy SOI",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        status_callback: Union[Callable, None] = None,
        target_callback: Union[Callable, None] = None,
        soi_callback: Union[Callable, None] = None,
        artifact_manager=None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            status_callback=status_callback,
            target_callback=target_callback,
            soi_callback=soi_callback,
            artifact_manager=artifact_manager,
        )

        # --- parameters (from UI schema) ---
        try:
            self.frequency_mhz = float(frequency_mhz)
        except Exception:
            self.frequency_mhz = 915.0

        self.model_label = (model_label or "dummy_protocol").strip()

        try:
            conf = int(float(model_confidence))
        except Exception:
            conf = 87
        self.model_confidence = max(0, min(100, conf))

        self.description = (description or "Dummy SOI").strip()

        self.logger.info(
            f"dummy_soi init params: frequency_mhz={self.frequency_mhz}, "
            f"model_label={self.model_label}, model_confidence={self.model_confidence}, "
            f"description={self.description}"
        )

        # Keep structure for future expansion / resource claims
        self.resource_args = {"frequency_mhz": self.frequency_mhz}

    async def run(self) -> None:
        params: Dict[str, Any] = getattr(self, "parameters", {}) or {}

        if not self.soi_callback:
            raise RuntimeError("dummy_soi requires soi_callback to be wired")

        if not self.artifact_manager:
            raise RuntimeError("dummy_soi requires artifact_manager to be passed in")

        freq = self.frequency_mhz

        # Minimal fixed “evidence payload” knobs (not in UI)
        bin_count = 3
        bin_size_kb = 256
        json_count = 2
        data_type = "Complex Float 32"

        # allow overrides for determinism/testing (optional, not exposed in schema)
        soi_id = str(params.get("soi_id") or uuid.uuid4())
        operation_id = str(params.get("operation_id") or uuid.uuid4())
        artifact_id = ""

        STAGE_ORDER = {
            "STARTED": 10,
            "CAPTURE_COMPLETE": 20,
            "FEATURES_READY": 30,
            "MODEL_ANALYZED": 40,
            "EVIDENCE_READY": 50,
            "FAILED": 90,
        }

        async def _send(status: str, stage: str, extra: Dict[str, Any] = None) -> None:
            summary = {
                "stage": stage,
                "stage_order": STAGE_ORDER.get(status, 0),
                "folder": None,
                "files_present": None,
                "model_classification": self.model_label,
                "model_confidence": self.model_confidence,
                "description": self.description,
            }
            if extra:
                summary.update(extra)

            try:
                await self.soi_callback(
                    node_uid=self.node_uid,
                    soi_id=soi_id,
                    frequency_mhz=freq,
                    status=status,
                    operation_id=operation_id,
                    artifact_id=artifact_id,
                    summary=summary,
                    # keep your existing semantics (True = use node GPS)
                    lat=True,
                    lon=True,
                    alt=True,
                    observation_time=True,
                )
            except Exception:
                self.logger.exception(f"SOI update failed (status={status})")

        # 1) STARTED
        await _send("STARTED", "starting", {"files_present": False})

        # 2) Create folder + write junk
        try:
            _, capture_folder = self.artifact_manager.create_operation_dir(operation_id)

            for i in range(bin_count):
                if self._stop:
                    self.logger.info("Stop requested; exiting early during dummy file write.")
                    return
                p = os.path.join(capture_folder, f"iq_chunk_{i:03d}.bin")
                with open(p, "wb") as f:
                    f.write(os.urandom(bin_size_kb * 1024))

            now = time.time()
            for j in range(json_count):
                if self._stop:
                    self.logger.info("Stop requested; exiting early during dummy json write.")
                    return
                p = os.path.join(capture_folder, f"meta_{j:02d}.json")
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(
                        {
                            "soi_id": soi_id,
                            "frequency_mhz": freq,
                            "data_type": data_type,
                            "operation_id": operation_id,
                            "index": j,
                            "created_ts": now,
                            "note": "dummy soi payload",
                        },
                        f,
                        indent=2,
                    )

            await _send(
                "CAPTURE_COMPLETE",
                "capture_complete",
                {"folder": capture_folder, "files_present": True},
            )

        except Exception as e:
            await _send("FAILED", "capture_failed", {"error": repr(e)})
            return

        # 3) FEATURES_READY
        try:
            p = os.path.join(capture_folder, "tsi_features.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "features": {
                            "dummy": True,
                            "snr_db": 12.3,
                            "bw_hz": 250000,
                            "notes": "fabricated features",
                        }
                    },
                    f,
                    indent=2,
                )

            await _send(
                "FEATURES_READY",
                "features_ready",
                {"folder": capture_folder, "features_file": "tsi_features.json"},
            )

        except Exception as e:
            await _send("FAILED", "features_failed", {"folder": capture_folder, "error": repr(e)})
            return

        # 4) MODEL_ANALYZED
        try:
            p = os.path.join(capture_folder, "classification_report.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "batch": {
                            "label": self.model_label,
                            "confidence": self.model_confidence / 100.0,
                        }
                    },
                    f,
                    indent=2,
                )

            await _send(
                "MODEL_ANALYZED",
                "model_analyzed",
                {
                    "folder": capture_folder,
                    "model_classification": self.model_label,
                    "model_confidence": self.model_confidence,
                },
            )

        except Exception as e:
            await _send("FAILED", "classification_failed", {"folder": capture_folder, "error": repr(e)})
            return

        # 5) Zip + register artifact
        try:
            artifact_id = self.artifact_manager.create_zip_artifact_from_folder(
                source_id=str(params.get("source_id", "")),
                operation_id=operation_id,
                folder=capture_folder,
                name=f"{self.description} evidence @ {freq} MHz",
                metadata={
                    "role": "soi_evidence_dummy_v1",
                    "frequency_mhz": freq,
                    "soi_id": soi_id,
                    "operation_id": operation_id,
                    "model_classification": self.model_label,
                    "model_confidence": self.model_confidence,
                    "description": self.description,
                },
                arc_prefix=f"soi_{operation_id}",
            )

            await _send(
                "EVIDENCE_READY",
                "evidence_ready",
                {
                    "folder": capture_folder,
                    "artifact_id": artifact_id,
                    "model_classification": self.model_label,
                    "model_confidence": self.model_confidence,
                },
            )

        except Exception as e:
            await _send("FAILED", "evidence_bundle_failed", {"folder": capture_folder, "error": repr(e)})
            return

        self.logger.info(
            f"Dummy SOI complete: soi_id={soi_id}, op_id={operation_id}, "
            f"label={self.model_label}, conf={self.model_confidence}%, artifact_id={artifact_id}"
        )


if __name__ == "__main__":
    """Run as standalone script for testing."""
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})