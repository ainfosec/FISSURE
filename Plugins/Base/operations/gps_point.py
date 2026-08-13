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
from geopy.distance import geodesic


def _get_current_position():
    packet = gpsd.get_current()
    if getattr(packet, "mode", 0) < 2:
        return None
    return float(packet.lat), float(packet.lon)


class OperationMain(Operation):
    def __init__(
        self,
        target_latitude: float = 0.0,
        target_longitude: float = 0.0,
        distance: float = 100.0,
        poll_interval_s: float = 5.0,
        description: str = "GPS point reached",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        detection_callback: Union[Callable, None] = None,
    ) -> None:
        super().__init__(node_uid=node_uid, logger=logger, alert_callback=alert_callback, tak_cot_callback=tak_cot_callback, detection_callback=detection_callback)
        self.target_latitude = float(target_latitude)
        self.target_longitude = float(target_longitude)
        self.distance = max(0.0, float(distance))
        self.poll_interval_s = max(0.5, float(poll_interval_s))
        self.description = description or "GPS point reached"

    async def run(self) -> None:
        await _run_blocking(gpsd.connect)
        target = (self.target_latitude, self.target_longitude)

        while not self._stop:
            try:
                current = await _run_blocking(_get_current_position)
                if current:
                    distance_m = geodesic(current, target).meters
                    if distance_m <= self.distance:
                        await _emit_detection(self, "gps_point", self.description, {"latitude": current[0], "longitude": current[1], "target_latitude": self.target_latitude, "target_longitude": self.target_longitude, "distance_m": distance_m, "threshold_m": self.distance})
                        return
            except Exception:
                self.logger.exception("GPS point check failed")

            await self._sleep_stop_aware(self.poll_interval_s)


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})
