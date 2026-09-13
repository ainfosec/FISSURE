#! /usr/bin/env python3
"""Live Audio Stream Operation

Streams the default local audio input to a remote host using Opus over RTP/UDP.
The operation owns the GStreamer sender process and terminates it when stopped.
"""

import asyncio
from collections import deque
import logging
import os
import shutil
import sys
from typing import Any, Callable, Union


PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from fissure.utils.plugins.operations import Operation


def _to_int(value: Any, default: int) -> int:
    try:
        if value is None:
            return int(default)
        return int(float(value))
    except Exception:
        return int(default)


def _to_str(value: Any, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, value))


class OperationMain(Operation):
    """Stream the Sensor Node default audio input to an RTP/UDP receiver."""

    def __init__(
        self,
        destination_ip: str = "",
        destination_port: int = 5502,
        sample_rate: int = 48000,
        channels: int = 2,
        bitrate_kbps: int = 32,
        operation_id: str = "",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        status_callback: Union[Callable, None] = None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            status_callback=status_callback,
        )

        self.destination_ip = _to_str(destination_ip, "")
        self.destination_port = _clamp(_to_int(destination_port, 5502), 1, 65535)
        self.sample_rate = _clamp(_to_int(sample_rate, 48000), 8000, 192000)
        self.channels = _clamp(_to_int(channels, 2), 1, 2)
        self.bitrate_kbps = _clamp(_to_int(bitrate_kbps, 32), 6, 510)
        self.operation_id = _to_str(operation_id, "")

        if not self.destination_ip:
            raise ValueError("destination_ip is required")

        self._process = None
        self._stderr_task = None
        self._stderr_tail = deque(maxlen=20)

    async def setup(self) -> bool:
        """Verify GStreamer and the sender elements required by this stream."""
        if not shutil.which("gst-launch-1.0") or not shutil.which("gst-inspect-1.0"):
            self.logger.error("GStreamer command-line tools are not installed.")
            return False

        for element in (
            "autoaudiosrc",
            "audioconvert",
            "audioresample",
            "opusenc",
            "rtpopuspay",
            "udpsink",
        ):
            process = await asyncio.create_subprocess_exec(
                "gst-inspect-1.0",
                element,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            if await process.wait() != 0:
                self.logger.error(f"Missing GStreamer element: {element}")
                return False

        return True

    def _pipeline_args(self):
        return [
            "gst-launch-1.0",
            "-q",
            "autoaudiosrc",
            "!",
            "audioconvert",
            "!",
            "audioresample",
            "!",
            f"audio/x-raw,rate={self.sample_rate},channels={self.channels}",
            "!",
            "opusenc",
            f"bitrate={self.bitrate_kbps * 1000}",
            "!",
            "rtpopuspay",
            "pt=96",
            "!",
            "udpsink",
            f"host={self.destination_ip}",
            f"port={self.destination_port}",
        ]

    async def _read_stderr(self) -> None:
        if self._process is None or self._process.stderr is None:
            return

        while True:
            line = await self._process.stderr.readline()
            if not line:
                return
            text = line.decode(errors="replace").rstrip()
            if text:
                self._stderr_tail.append(text)
                self.logger.debug(f"stream_audio gstreamer: {text}")

    async def _terminate_process(self) -> None:
        if self._process is None or self._process.returncode is not None:
            return

        self._process.terminate()
        try:
            await asyncio.wait_for(self._process.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            self._process.kill()
            await self._process.wait()

    async def run(self) -> None:
        """Run until stopped or until the GStreamer sender exits."""
        args = self._pipeline_args()
        self.logger.info(
            "Starting audio stream: "
            f"sample_rate={self.sample_rate}, channels={self.channels}, "
            f"bitrate={self.bitrate_kbps} kbps, "
            f"destination={self.destination_ip}:{self.destination_port}"
        )

        self._process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        self._stderr_task = asyncio.create_task(self._read_stderr())

        try:
            while not self._stop and self._process.returncode is None:
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=0.1)
                except asyncio.TimeoutError:
                    continue

            if self._stop:
                await self._terminate_process()
            elif self._process.returncode not in (None, 0):
                detail = "\n".join(self._stderr_tail)
                self.logger.error(
                    f"Audio stream exited with code {self._process.returncode}."
                    + (f"\n{detail}" if detail else "")
                )
        finally:
            await self._terminate_process()
            if self._stderr_task is not None:
                await asyncio.gather(self._stderr_task, return_exceptions=True)

    async def teardown(self) -> None:
        await self._terminate_process()


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test

    run_test(
        OperationMain,
        {
            "destination_ip": "127.0.0.1",
            "destination_port": 5502,
        },
        {},
    )
