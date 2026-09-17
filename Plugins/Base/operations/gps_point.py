#! /usr/bin/env python3
import asyncio
import logging
import os
import sys
import time
from typing import Callable, Union

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))
for path in (FISSURE_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from fissure.utils.plugins.operations import Operation

from geopy.distance import geodesic


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
        position_callback: Union[Callable, None] = None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            detection_callback=detection_callback,
            position_callback=position_callback,
        )
        self.target_latitude = float(target_latitude)
        self.target_longitude = float(target_longitude)
        self.distance = max(0.0, float(distance))
        self.poll_interval_s = max(0.5, float(poll_interval_s))
        self.description = description or "GPS point reached"

    async def run(self) -> None:
        target = (self.target_latitude, self.target_longitude)

        while not self._stop:
            try:
                position = self.position_callback()
                if position and position.get("valid"):
                    current = (
                        float(position["latitude"]),
                        float(position["longitude"]),
                    )
                    distance_m = geodesic(current, target).meters
                    if distance_m <= self.distance:
                        await _emit_detection(
                            self,
                            "gps_point",
                            self.description,
                            {
                                "latitude": current[0],
                                "longitude": current[1],
                                "target_latitude": self.target_latitude,
                                "target_longitude": self.target_longitude,
                                "distance_m": distance_m,
                                "threshold_m": self.distance,
                            },
                        )
                        return
            except Exception:
                self.logger.exception("GPS point check failed")

            await self._sleep_stop_aware(self.poll_interval_s)


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})
