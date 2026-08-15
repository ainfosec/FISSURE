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

import subprocess


def _scan_wifi_ssids(interface):
    result = subprocess.run(["iwlist", interface, "scan"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "iwlist scan failed")

    ssids = []
    for line in result.stdout.splitlines():
        if "ESSID:" not in line:
            continue
        parts = line.split('"')
        if len(parts) >= 2:
            ssids.append(parts[1])
    return ssids


class OperationMain(Operation):
    def __init__(
        self,
        interface: str = "wlan0",
        ssid: str = "",
        poll_interval_s: float = 10.0,
        description: str = "SSID detected",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        detection_callback: Union[Callable, None] = None,
    ) -> None:
        super().__init__(node_uid=node_uid, logger=logger, alert_callback=alert_callback, tak_cot_callback=tak_cot_callback, detection_callback=detection_callback)
        self.interface = str(interface or "wlan0").strip()
        self.ssid = str(ssid or "")
        self.poll_interval_s = max(1.0, float(poll_interval_s))
        self.description = description or "SSID detected"

    async def run(self) -> None:
        if not self.ssid:
            raise ValueError("ssid is required")

        while not self._stop:
            try:
                ssids = await _run_blocking(_scan_wifi_ssids, self.interface)
                if self.ssid in ssids:
                    await _emit_detection(self, "detect_ssid", self.description, {"interface": self.interface, "ssid": self.ssid})
                    return
            except Exception:
                self.logger.exception("SSID scan failed")

            await self._sleep_stop_aware(self.poll_interval_s)


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})
