#! /usr/bin/env python3
import asyncio
import logging
import os
import sys
import time
from typing import Callable, Union

import numpy as np
import sounddevice as sd

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))
for path in (FISSURE_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from fissure.utils.plugins.operations import Operation


class OperationMain(Operation):
    def __init__(
        self,
        get_threshold: float = 0.02,
        get_duration: float = 0.1,
        get_sample_rate: float = 44100.0,
        warmup_s: float = 0.0,
        description: str = "Sound threshold exceeded",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        detection_callback: Union[Callable, None] = None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            detection_callback=detection_callback,
        )

        self.get_threshold = float(get_threshold)
        self.get_duration = max(0.01, float(get_duration))
        self.get_sample_rate = max(1000.0, float(get_sample_rate))
        self.warmup_s = max(0.0, float(warmup_s))
        self.description = description or "Sound threshold exceeded"

    async def _emit_detection(self, amplitude: float) -> None:
        detection = {
            "kind": "detection",
            "event_type": "detection",
            "node_uid": self.node_uid,
            "source_id": self.node_uid,
            "description": self.description,
            "label": self.description,
            "timestamp": time.time(),
            "detector": "sound_threshold",
            "opid": self.opid,
            "amplitude": amplitude,
            "threshold": self.get_threshold,
            "sample_rate": self.get_sample_rate,
        }

        if self.detection_callback:
            try:
                await asyncio.wait_for(self.detection_callback(detection), timeout=2.0)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception("sound_threshold detection_callback failed")
        else:
            self.logger.warning("sound_threshold has no detection_callback")

    async def run(self) -> None:
        blocksize = max(1, int(self.get_duration * self.get_sample_rate))
        queue = asyncio.Queue()
        loop = asyncio.get_running_loop()

        def audio_callback(indata, frames, time_info, status):
            if status:
                self.logger.warning(f"sound_threshold audio status: {status}")

            samples = np.array(indata[:, 0], copy=True)
            loop.call_soon_threadsafe(queue.put_nowait, samples)

        self.logger.info(
            "Starting sound threshold detector: "
            f"threshold={self.get_threshold}, "
            f"duration={self.get_duration}s, "
            f"sample_rate={self.get_sample_rate}"
        )

        with sd.InputStream(
            samplerate=self.get_sample_rate,
            channels=1,
            dtype="float32",
            blocksize=blocksize,
            callback=audio_callback,
        ):
            warmup_end = time.time() + self.warmup_s
            while not self._stop and time.time() < warmup_end:
                try:
                    await asyncio.wait_for(queue.get(), timeout=0.25)
                except asyncio.TimeoutError:
                    pass

            while not self._stop:
                try:
                    samples = await asyncio.wait_for(queue.get(), timeout=0.25)
                except asyncio.TimeoutError:
                    continue

                amplitude = float(np.sqrt(np.mean(np.square(samples))))

                if amplitude >= self.get_threshold:
                    self.logger.info(
                        f"Sound threshold exceeded: amplitude={amplitude:.6f}, "
                        f"threshold={self.get_threshold:.6f}"
                    )
                    await self._emit_detection(amplitude)
                    return


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})