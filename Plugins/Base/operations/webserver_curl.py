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
        ip_address: str = "0.0.0.0",
        port: int = 8080,
        description: str = "Web request received",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        detection_callback: Union[Callable, None] = None,
    ) -> None:
        super().__init__(node_uid=node_uid, logger=logger, alert_callback=alert_callback, tak_cot_callback=tak_cot_callback, detection_callback=detection_callback)
        self.ip_address = str(ip_address or "0.0.0.0").strip()
        self.port = int(port)
        self.description = description or "Web request received"
        self._server = None
        self._request_event = asyncio.Event()
        self._peer = ""

    async def _handle_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        self._peer = str(peer)
        try:
            await reader.read(4096)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 26\r\nConnection: close\r\n\r\nRequest received. Exiting.")
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            self._request_event.set()

    async def run(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.ip_address, self.port)
        self.logger.info("webserver_curl listening on %s:%s", self.ip_address, self.port)

        try:
            while not self._stop and not self._request_event.is_set():
                await asyncio.sleep(0.1)

            if not self._stop and self._request_event.is_set():
                await _emit_detection(self, "webserver_curl", self.description, {"ip_address": self.ip_address, "port": self.port, "peer": self._peer})
        finally:
            self._server.close()
            await self._server.wait_closed()


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})
