#! /usr/bin/env python3
import asyncio
import logging
import os
import sys
import time
from typing import Any, Callable, Dict, Union

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))
for path in (FISSURE_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from fissure.utils.plugins.operations import Operation


async def _emit_detection(operation, detector, description, extra=None):
    detection = {
        "kind": "detection",
        "event_type": "detection",
        "node_uid": operation.node_uid,
        "source_id": operation.node_uid,
        "description": description,
        "label": description,
        "timestamp": time.time(),
        "detector": detector,
        "opid": operation.opid,
    }
    if extra:
        detection.update(extra)

    if operation.detection_callback:
        try:
            await asyncio.wait_for(operation.detection_callback(detection), timeout=2.0)
        except asyncio.CancelledError:
            raise
        except Exception:
            operation.logger.exception("%s detection_callback failed", detector)
    else:
        operation.logger.warning("%s has no detection_callback", detector)


async def _run_blocking(func, *args):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: func(*args))

import gpsd


def _get_current_position():
    packet = gpsd.get_current()
    if getattr(packet, "mode", 0) < 2:
        return None
    return float(packet.lat), float(packet.lon)


class OperationMain(Operation):
    def __init__(
        self,
        latitude: str = "None",
        longitude: str = "None",
        comparison: str = ">",
        poll_interval_s: float = 5.0,
        description: str = "GPS line crossed",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        detection_callback: Union[Callable, None] = None,
    ) -> None:
        super().__init__(node_uid=node_uid, logger=logger, alert_callback=alert_callback, tak_cot_callback=tak_cot_callback, detection_callback=detection_callback)
        self.latitude = None if str(latitude) in {"", "None", "none"} else float(latitude)
        self.longitude = None if str(longitude) in {"", "None", "none"} else float(longitude)
        self.comparison = str(comparison or ">").strip()
        self.poll_interval_s = max(0.5, float(poll_interval_s))
        self.description = description or "GPS line crossed"

    def _crossed(self, current):
        lat, lon = current
        if self.comparison == "<":
            return (self.latitude is not None and lat < self.latitude) or (self.longitude is not None and lon < self.longitude)
        return (self.latitude is not None and lat > self.latitude) or (self.longitude is not None and lon > self.longitude)

    async def run(self) -> None:
        if self.latitude is None and self.longitude is None:
            raise ValueError("latitude or longitude threshold is required")

        await _run_blocking(gpsd.connect)
        while not self._stop:
            try:
                current = await _run_blocking(_get_current_position)
                if current and self._crossed(current):
                    await _emit_detection(self, "gps_line", self.description, {"latitude": current[0], "longitude": current[1], "latitude_threshold": self.latitude, "longitude_threshold": self.longitude, "comparison": self.comparison})
                    return
            except Exception:
                self.logger.exception("GPS line check failed")

            await self._sleep_stop_aware(self.poll_interval_s)


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})
