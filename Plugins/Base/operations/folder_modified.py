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

class OperationMain(Operation):
    def __init__(
        self,
        folder_modified: str = "",
        poll_interval_s: float = 0.1,
        description: str = "Folder modified",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        detection_callback: Union[Callable, None] = None,
    ) -> None:
        super().__init__(node_uid=node_uid, logger=logger, alert_callback=alert_callback, tak_cot_callback=tak_cot_callback, detection_callback=detection_callback)
        self.folder_modified = os.path.expanduser(str(folder_modified or "").strip())
        self.poll_interval_s = max(0.05, float(poll_interval_s))
        self.description = description or "Folder modified"

    async def run(self) -> None:
        if not self.folder_modified:
            raise ValueError("folder_modified is required")
        if not os.path.isdir(self.folder_modified):
            raise NotADirectoryError(self.folder_modified)

        initial_files = set(os.listdir(self.folder_modified))
        while not self._stop:
            current_files = set(os.listdir(self.folder_modified))
            new_files = sorted(current_files - initial_files)
            if new_files:
                await _emit_detection(self, "folder_modified", self.description, {"folder": self.folder_modified, "new_files": new_files})
                return
            await asyncio.sleep(self.poll_interval_s)


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})
