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

import re
import requests


def _get_wind(city_name, state_code, country_code, timeout_s):
    location = city_name
    if state_code:
        location += "," + state_code
    if country_code:
        location += "," + country_code
    response = requests.get("http://wttr.in/{}?format=%w".format(location), timeout=timeout_s)
    response.raise_for_status()
    match = re.search(r"(-?\d+)\s*mph", response.text)
    if not match:
        raise ValueError("Could not parse wttr.in wind response: {}".format(response.text.strip()))
    return int(match.group(1))


class OperationMain(Operation):
    def __init__(
        self,
        wind_threshold: int = 10,
        city_name: str = "",
        state_code: str = "",
        country_code: str = "",
        poll_interval_s: float = 10.0,
        request_timeout_s: float = 5.0,
        description: str = "Wind threshold reached",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        detection_callback: Union[Callable, None] = None,
    ) -> None:
        super().__init__(node_uid=node_uid, logger=logger, alert_callback=alert_callback, tak_cot_callback=tak_cot_callback, detection_callback=detection_callback)
        self.wind_threshold = int(float(wind_threshold))
        self.city_name = str(city_name or "").strip()
        self.state_code = str(state_code or "").strip()
        self.country_code = str(country_code or "").strip()
        self.poll_interval_s = max(1.0, float(poll_interval_s))
        self.request_timeout_s = max(1.0, float(request_timeout_s))
        self.description = description or "Wind threshold reached"

    async def run(self) -> None:
        if not self.city_name:
            raise ValueError("city_name is required")

        while not self._stop:
            try:
                current = await _run_blocking(_get_wind, self.city_name, self.state_code, self.country_code, self.request_timeout_s)
                if current >= self.wind_threshold:
                    await _emit_detection(self, "wind", self.description, {"wind_mph": current, "threshold_mph": self.wind_threshold, "city": self.city_name})
                    return
            except Exception:
                self.logger.exception("wind check failed")

            await self._sleep_stop_aware(self.poll_interval_s)


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})
