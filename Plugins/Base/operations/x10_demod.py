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
from fissure.utils import get_library_version

FLOW_GRAPH_BASE_DIR = os.path.join(PLUGIN_ROOT, "flow_graphs", "detection_flow_graphs")

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
        matching_text: str = "Bits: 01100000100111110000000011111111",
        description: str = "X10 message detected",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        detection_callback: Union[Callable, None] = None,
    ) -> None:
        super().__init__(node_uid=node_uid, logger=logger, alert_callback=alert_callback, tak_cot_callback=tak_cot_callback, detection_callback=detection_callback)
        self.matching_text = str(matching_text or "")
        self.description = description or "X10 message detected"

    def _script_path(self):
        version = get_library_version() or "maint-3.10"
        return os.path.join(FLOW_GRAPH_BASE_DIR, version, "x10_demod", "X10_OOK_USRPB2x0_Demod.py")

    async def run(self) -> None:
        if not self.matching_text:
            raise ValueError("matching_text is required")

        script = self._script_path()
        if not os.path.isfile(script):
            raise FileNotFoundError(script)

        process = await asyncio.create_subprocess_exec(sys.executable, "-u", script, cwd=os.path.dirname(script), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)

        try:
            while not self._stop:
                try:
                    line = await asyncio.wait_for(process.stdout.readline(), timeout=0.25)
                except asyncio.TimeoutError:
                    continue
                if not line:
                    break
                text = line.decode(errors="ignore")
                if self.matching_text in text:
                    await _emit_detection(self, "x10_demod", self.description, {"matching_text": self.matching_text, "matched_line": text.strip()})
                    return
        finally:
            await _terminate_process(process)


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})
