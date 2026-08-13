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

import contextlib
import subprocess

async def _terminate_process(process):
    if process and process.returncode is None:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
class OperationMain(Operation):
    def __init__(
        self,
        pci: int = 0,
        frequency: float = 900.0,
        retry_interval_s: float = 10.0,
        description: str = "Cellular tower detected",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        detection_callback: Union[Callable, None] = None,
    ) -> None:
        super().__init__(node_uid=node_uid, logger=logger, alert_callback=alert_callback, tak_cot_callback=tak_cot_callback, detection_callback=detection_callback)
        self.pci = int(pci)
        self.frequency = float(frequency)
        self.retry_interval_s = max(1.0, float(retry_interval_s))
        self.description = description or "Cellular tower detected"

    async def run(self) -> None:
        executable = os.path.expanduser("~/Installed_by_FISSURE/LTE-Cell-Scanner/build/src/CellSearch")
        frequency_hz = str(self.frequency * 1e6)
        keyword = "cell ID: {}".format(self.pci)

        while not self._stop:
            process = await asyncio.create_subprocess_exec(executable, "--freq-start", frequency_hz, "--freq-end", frequency_hz, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            found = False
            try:
                while not self._stop:
                    try:
                        line = await asyncio.wait_for(process.stdout.readline(), timeout=0.25)
                    except asyncio.TimeoutError:
                        if process.returncode is not None:
                            break
                        continue
                    if not line:
                        break
                    text = line.decode(errors="ignore")
                    if keyword in text:
                        found = True
                        await _emit_detection(self, "cellular_tower", self.description, {"pci": self.pci, "frequency_mhz": self.frequency, "matched_line": text.strip()})
                        return
            finally:
                await _terminate_process(process)

            if not found and not self._stop:
                await self._sleep_stop_aware(self.retry_interval_s)


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})
