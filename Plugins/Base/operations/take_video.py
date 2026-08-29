#! /usr/bin/env python3
"""Take Video Operation

Captures a short video from a webcam and registers it as a single zip artifact.

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
    """Take Video Operation"""

    def __init__(
        self,
        duration_s: float = 10.0,
        fps: float = 15.0,
        artifact_name: str = "Video capture evidence",
        emit_tak_pin: Union[str, bool] = "yes",
        emit_alert: Union[str, bool] = "yes",
        description: str = "Take Video",
        operation_id: str = "",
        source_id: str = "",
        tak_icon: str = "a-h-G-E-S",
        codec: str = "MJPG",
        warmup_frames: int = 5,
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

        self.duration_s = _clamp(_to_float(duration_s, 10.0), 1.0, 60.0)
        self.fps = _clamp(_to_float(fps, 15.0), 1.0, 60.0)
        self.artifact_name = _to_str(artifact_name, "Video capture evidence")
        self.emit_tak_pin = _to_bool_yn(emit_tak_pin, True)
        self.emit_alert = _to_bool_yn(emit_alert, True)
        self.description = _to_str(description, "Take Video")

        opid_in = _to_str(operation_id, "")
        self.operation_id = opid_in if opid_in else str(self.opid or uuid.uuid4())

        self.source_id = _to_str(source_id, "")
        if not self.source_id:
            self.source_id = self.node_uid or "sensor_node"

        self.tak_icon = _to_str(tak_icon, "a-h-G-E-S")
        self.codec = _to_str(codec, "MJPG").upper()[:4]
        self.warmup_frames = int(_clamp(float(_to_int(warmup_frames, 5)), 0.0, 60.0))

        self.camera_index = 0
        self.resource_args = {"camera_index": self.camera_index}

        self.logger.info(
            "take_video init params: "
            f"operation_id={self.operation_id}, "
            f"source_id={self.source_id}, "
            f"duration_s={self.duration_s}, "
            f"fps={self.fps}, "
            f"artifact_name={self.artifact_name}, "
            f"emit_tak_pin={self.emit_tak_pin}, "
            f"emit_alert={self.emit_alert}, "
            f"codec={self.codec}, "
            f"camera_index={self.camera_index}"
        )

    async def run(self) -> None:
        """Run the video capture operation."""

        try:
            await self._run_video_capture()

        except asyncio.CancelledError:
            self.logger.info("take_video cancelled")
            raise

        except Exception:
            self.logger.exception("take_video failed")
            raise

        finally:
            if self.status_callback:
                try:
                    await self.status_callback("Idle")
                except Exception:
                    self.logger.exception("take_video status_callback failed while setting Idle")

    async def _run_video_capture(self) -> None:
        if cv2 is None:
            if self.status_callback:
                await self.status_callback("OpenCV not available")
            self.logger.error("cv2 import failed; cannot record video.")
            return

        if not self.artifact_manager:
            raise RuntimeError("take_video requires artifact_manager")

        _, folder = self.artifact_manager.create_operation_dir(self.operation_id)

        video_path = os.path.join(folder, "video.avi")

        meta = {
            "role": "video_capture_v1",
            "node_uid": self.node_uid,
            "source_id": self.source_id,
            "operation_id": self.operation_id,
            "description": self.description,
            "created_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "camera_index": self.camera_index,
            "duration_s": self.duration_s,
            "fps": self.fps,
            "codec": self.codec,
        }

        if self.status_callback:
            await self.status_callback("Initializing camera")

        cap = cv2.VideoCapture(self.camera_index)
        writer = None

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

            width, height, frame0 = self._get_frame_size(cap)

            if width <= 0 or height <= 0:
                if self.status_callback:
                    await self.status_callback("Camera read failed")
                self.logger.error("Could not determine camera frame size")
                return

            fourcc = cv2.VideoWriter_fourcc(*self.codec)
            writer = cv2.VideoWriter(video_path, fourcc, self.fps, (width, height))

            if not writer.isOpened():
                if self.status_callback:
                    await self.status_callback("VideoWriter init failed")
                self.logger.error(
                    f"VideoWriter failed: codec={self.codec}, size={(width, height)}, fps={self.fps}"
                )
                return

            if self.status_callback:
                await self.status_callback(f"Recording video ({self.duration_s:.0f}s)")

            frames_written = await self._record_video(
                cap=cap,
                writer=writer,
                frame0=frame0,
            )

        finally:
            if writer is not None:
                try:
                    writer.release()
                except Exception:
                    pass

            try:
                cap.release()
            except Exception:
                pass

        if self._stop:
            if self.status_callback:
                await self.status_callback("Stopped")
            self._remove_partial_file(video_path)
            return

        if (
            frames_written <= 0
            or not os.path.isfile(video_path)
            or os.path.getsize(video_path) == 0
        ):
            if self.status_callback:
                await self.status_callback("No video captured")
            return

        meta["frames_written"] = frames_written
        meta["file_bytes"] = int(os.path.getsize(video_path))
        meta["filename"] = os.path.basename(video_path)

        try:
            with open(os.path.join(folder, "metadata.json"), "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Failed writing metadata.json: {e!r}")

        if self.status_callback:
            await self.status_callback("Bundling video")

        artifact = self.artifact_manager.create_zip_artifact_from_folder(
            source_id=self.source_id,
            operation_id=self.operation_id,
            folder=folder,
            name=self.artifact_name,
            metadata=meta,
            arc_prefix=f"video_{self.operation_id}",
        )

        artifact_id = getattr(artifact, "id", artifact) if artifact else ""

        self.logger.info(
            f"Video bundle registered: artifact_id={artifact_id}, "
            f"opid={self.operation_id}, frames={frames_written}"
        )

        await self._emit_alert(
            artifact_id=artifact_id,
            frames_written=frames_written,
        )

    def _get_frame_size(self, cap):
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
        frame0 = None

        if width <= 0 or height <= 0:
            ret, frame0 = cap.read()
            if not ret or frame0 is None:
                return 0, 0, None
            height, width = frame0.shape[:2]

        return width, height, frame0

    async def _record_video(self, *, cap, writer, frame0) -> int:
        start = time.time()
        frames_written = 0

        if frame0 is not None and not self._stop:
            writer.write(frame0)
            frames_written += 1

        while not self._stop and (time.time() - start) < self.duration_s:
            ret, frame = cap.read()

            if not ret or frame is None:
                self.logger.warning("Frame read failed during recording; stopping early")
                break

            writer.write(frame)
            frames_written += 1

            await asyncio.sleep(0)

        return frames_written

    async def _emit_alert(
        self,
        *,
        artifact_id,
        frames_written: int,
    ) -> None:
        if not (self.emit_alert or self.emit_tak_pin) or not self.alert_callback:
            return

        try:
            alert_payload = {
                "uid": f"video_{artifact_id}",
                "alert_kind": "video_capture",
                "alert_summary": f"Video capture ({self.duration_s:.0f}s)",
                "message": f"Video capture ({self.duration_s:.0f}s)",
                "node_uid": self.node_uid,
                "source_id": self.source_id,
                "artifact_id": artifact_id,
                "operation_id": self.operation_id or self.opid,
                "opid": self.opid,
                "name": self.artifact_name,
                "role": "video_capture_v1",
                "duration_s": self.duration_s,
                "fps": self.fps,
                "frames_written": frames_written,
                "description": self.description,
                "plot_pin": self.emit_tak_pin,
                "lat": True,
                "lon": True,
                "alt": True,
                "time": True,
                "tak_icon": self.tak_icon,
            }

            await asyncio.wait_for(
                self.alert_callback(alert_payload),
                timeout=2.0,
            )

        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("alert_callback failed while reporting video_capture")

    @staticmethod
    def _remove_partial_file(path: str) -> None:
        try:
            if os.path.isfile(path):
                os.remove(path)
        except Exception:
            pass


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test

    run_test(OperationMain, {}, {})