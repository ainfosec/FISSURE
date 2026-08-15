#! /usr/bin/env python3
"""Take Photo Operation

Captures N images from a webcam and registers them as a single zip artifact.

- Writes files to: FISSURE_ROOT/artifacts/<operation_id>/files/
- Registers zip via: artifact_manager.create_zip_artifact_from_folder(...)
- Stop-aware: if stop requested mid-capture, exits cleanly without creating artifact.
"""

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from typing import Any, Callable, Union


PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

try:
    import cv2
except Exception:  # pragma: no cover
    cv2 = None

try:
    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT
except ImportError:
    if FISSURE_REPO_ROOT not in sys.path:
        sys.path.insert(0, FISSURE_REPO_ROOT)

    if PLUGIN_ROOT not in sys.path:
        sys.path.insert(0, PLUGIN_ROOT)

    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT


def _to_float(v: Any, default: float) -> float:
    try:
        if v is None:
            return float(default)
        return float(v)
    except Exception:
        return float(default)


def _to_int(v: Any, default: int) -> int:
    try:
        if v is None:
            return int(default)
        return int(float(v))
    except Exception:
        return int(default)


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


def _to_bool_yn(v: Any, default: bool = True) -> bool:
    if isinstance(v, bool):
        return v

    if v is None:
        return default

    s = str(v).strip().lower()

    if s in {"1", "true", "t", "yes", "y", "on", "enabled"}:
        return True

    if s in {"0", "false", "f", "no", "n", "off", "disabled"}:
        return False

    return default


class OperationMain(Operation):
    """Take Photo Operation"""

    def __init__(
        self,
        count: int = 5,
        interval_s: float = 0.3,
        name: str = "Photo capture evidence",
        emit_tak_pin: Union[str, bool] = "yes",
        emit_alert: Union[str, bool] = "yes",
        description: str = "Take Photo",
        operation_id: str = "",
        source_id: str = "",
        warmup_frames: int = 2,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        status_callback: Union[Callable, None] = None,
        artifact_manager=None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            status_callback=status_callback,
            artifact_manager=artifact_manager,
        )

        self.count = int(_clamp(float(_to_int(count, 5)), 1.0, 50.0))
        self.interval_s = _clamp(_to_float(interval_s, 0.3), 0.05, 10.0)

        self.camera_index = 0

        self.name = _to_str(name, "Photo capture evidence")
        self.emit_tak_pin = _to_bool_yn(emit_tak_pin, True)
        self.emit_alert = _to_bool_yn(emit_alert, True)
        self.description = _to_str(description, "Take Photo")

        opid_in = _to_str(operation_id, "")
        self.operation_id = opid_in if opid_in else str(self.opid or uuid.uuid4())

        self.source_id = _to_str(source_id, "")
        if not self.source_id:
            self.source_id = self.node_uid or "sensor_node"

        self.warmup_frames = int(_clamp(float(_to_int(warmup_frames, 2)), 0.0, 30.0))

        self.resource_args = {"camera_index": self.camera_index}

        self.logger.info(
            "take_photo init params: "
            f"operation_id={self.operation_id}, "
            f"source_id={self.source_id}, "
            f"count={self.count}, "
            f"interval_s={self.interval_s}, "
            f"camera_index={self.camera_index}, "
            f"name={self.name}, "
            f"emit_tak_pin={self.emit_tak_pin}, "
            f"emit_alert={self.emit_alert}"
        )

    async def run(self) -> None:
        """Run the photo capture operation."""

        try:
            await self._run_photo_capture()

        except asyncio.CancelledError:
            self.logger.info("take_photo cancelled")
            raise

        except Exception:
            self.logger.exception("take_photo failed")
            raise

        finally:
            if self.status_callback:
                try:
                    await self.status_callback("Idle")
                except Exception:
                    self.logger.exception("take_photo status_callback failed while setting Idle")

    async def _run_photo_capture(self) -> None:
        if cv2 is None:
            if self.status_callback:
                await self.status_callback("OpenCV not available")
            self.logger.error("cv2 import failed; cannot capture photos.")
            return

        if not self.artifact_manager:
            raise RuntimeError("take_photo requires artifact_manager to be passed in")

        _, folder = self.artifact_manager.create_operation_dir(self.operation_id)

        meta = {
            "role": "photo_capture_v1",
            "node_uid": self.node_uid,
            "source_id": self.source_id,
            "operation_id": self.operation_id,
            "description": self.description,
            "created_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "camera_index": self.camera_index,
            "count": self.count,
            "interval_s": self.interval_s,
        }

        if self.status_callback:
            await self.status_callback("Initializing camera")

        cap = cv2.VideoCapture(self.camera_index)

        try:
            if not cap.isOpened():
                if self.status_callback:
                    await self.status_callback("No camera found")
                self.logger.warning(f"Camera not available: index={self.camera_index}")
                return

            for _ in range(max(0, self.warmup_frames)):
                if self._stop:
                    break
                cap.read()
                await asyncio.sleep(0)

            if self._stop:
                if self.status_callback:
                    await self.status_callback("Stopped")
                return

            captured = await self._capture_photos(cap, folder)

        finally:
            try:
                cap.release()
            except Exception:
                pass

        if self._stop:
            if self.status_callback:
                await self.status_callback("Stopped")
            return

        photos = sorted(f for f in os.listdir(folder) if f.lower().endswith(".jpg"))

        if not photos or captured <= 0:
            if self.status_callback:
                await self.status_callback("No photos captured")
            return

        meta["captured"] = len(photos)
        meta["photos"] = photos

        meta_path = os.path.join(folder, "metadata.json")
        try:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Failed writing metadata.json: {e!r}")

        if self.status_callback:
            await self.status_callback("Bundling photos")

        artifact = self.artifact_manager.create_zip_artifact_from_folder(
            source_id=self.source_id,
            operation_id=self.operation_id,
            folder=folder,
            name=self.name,
            metadata=meta,
            arc_prefix=f"photo_{self.operation_id}",
        )

        artifact_id = getattr(artifact, "id", artifact) if artifact else ""

        self.logger.info(
            f"Photo bundle registered: artifact_id={artifact_id}, "
            f"opid={self.operation_id}, count={len(photos)}"
        )

        await self._emit_tak_pin(
            artifact_id=artifact_id,
            photo_count=len(photos),
        )

        await self._emit_alert(
            artifact_id=artifact_id,
            photo_count=len(photos),
        )

    async def _capture_photos(self, cap, folder: str) -> int:
        captured = 0

        for i in range(self.count):
            if self._stop:
                break

            if self.status_callback:
                await self.status_callback(f"Taking photo ({i + 1}/{self.count})")

            ret, frame = cap.read()
            if not ret or frame is None:
                self.logger.error("Failed to read frame from camera")
                break

            fname = os.path.join(folder, f"photo_{i + 1:02d}.jpg")
            ok = cv2.imwrite(fname, frame)

            if not ok:
                self.logger.error(f"Failed to write image: {fname}")
                break

            captured += 1
            await asyncio.sleep(self.interval_s)

        return captured

    async def _emit_tak_pin(
        self,
        *,
        artifact_id,
        photo_count: int,
    ) -> None:
        if not self.emit_tak_pin or not self.tak_cot_callback:
            return

        try:
            short_id = str(artifact_id)[:8]
            tak_msg = {
                "msg_type": "pin",
                "uid": f"photo_{artifact_id}",
                "remarks": f"Photo capture [{short_id}] (count={photo_count})",
                "lat": True,
                "lon": True,
                "alt": True,
                "time": True,
                "tak_icon": "a-h-G-E-S",
                "opid": self.opid,
                "alert_kind": "photo_capture",
                "alert_summary": f"Photo capture (count={photo_count})",
                "artifact_id": artifact_id,
                "operation_id": self.operation_id,
                "node_uid": self.node_uid,
                "source_id": self.source_id,
                "name": self.name,
            }

            await asyncio.wait_for(
                self.tak_cot_callback(tak_msg),
                timeout=2.0,
            )

            self.logger.info(f"TAK pin emitted for photo artifact_id={artifact_id}")

        except asyncio.CancelledError:
            raise

        except Exception:
            self.logger.exception("Failed emitting TAK pin for photo capture")

    async def _emit_alert(
        self,
        *,
        artifact_id,
        photo_count: int,
    ) -> None:
        if not self.emit_alert or not self.alert_callback:
            return

        try:
            payload = {
                "type": "artifact_ready",
                "kind": "alert",
                "node_uid": self.node_uid,
                "source_id": self.source_id,
                "artifact_id": artifact_id,
                "operation_id": self.operation_id,
                "opid": self.opid,
                "name": self.name,
                "role": "photo_capture_v1",
                "count": photo_count,
                "description": self.description,
            }

            await asyncio.wait_for(
                self.alert_callback(
                    self.node_uid,
                    self.opid,
                    json.dumps(payload),
                    self.logger,
                ),
                timeout=2.0,
            )

        except asyncio.CancelledError:
            raise

        except Exception:
            self.logger.exception("alert_callback failed while reporting artifact_ready")


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test

    run_test(OperationMain, {}, {})