#! /usr/bin/env python3
"""Dummy Alert Burst
Generates sequential dummy alerts at regular intervals.
"""

import asyncio
import logging
import os
import sys
from typing import Callable, Union

try:
    from fissure.utils.plugins.operations import Operation
except ImportError:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
    from fissure.utils.plugins.operations import Operation

import time


class OperationMain(Operation):
    def __init__(
        self,
        interval_seconds: int = 10,
        count: int = 10,
        description: str = "Dummy alert burst",
        plot_pin: Union[bool, str] = True,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback
        )

        # UI/TAK often arrives as strings, so coerce
        self.interval_seconds = int(float(interval_seconds))
        self.count = int(float(count))
        self.description = description or "Dummy alert burst"
        self.plot_pin = self._to_bool(plot_pin)

        self.logger.info(
            f"dummy_alert_burst init params: interval_seconds={self.interval_seconds}, "
            f"count={self.count}, description={self.description}, plot_pin={self.plot_pin}"
        )

    @staticmethod
    def _to_bool(value: Union[bool, str, int, None]) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return True
        if isinstance(value, (int, float)):
            return bool(value)

        value_str = str(value).strip().lower()
        return value_str in ("true", "1", "yes", "y", "on")

    async def run(self) -> None:
        self.logger.info(
            f"Starting Dummy Alert Burst: {self.count} alerts, "
            f"{self.interval_seconds}s interval, plot_pin={self.plot_pin}."
        )

        cb_timeout_s = 2.0
        tick_s = 0.25

        for i in range(1, self.count + 1):
            if self._stop:
                self.logger.info("Stop signal received. Ending Dummy Alert Burst early.")
                break

            timestamp = str(time.time())
            uid = f"dummy_alert_burst{i}"
            alert_payload = {
                "uid": uid,
                "alert_kind": "dummy_alert_burst",
                "alert_summary": f"Dummy alert burst {i}/{self.count}",
                "message": f"Dummy Alert Burst {i}: {timestamp}",
                "node_uid": self.node_uid,
                "operation_id": self.opid,
                "opid": self.opid,
                "plot_pin": self.plot_pin,
                "lat": True,
                "lon": True,
                "alt": True,
                "time": True,
                "tak_icon": "a-h-G-E-S" if self.plot_pin else "b-t-f-r",
                "burst_index": i,
                "burst_total": self.count,
                "timestamp": timestamp,
            }

            try:
                await asyncio.wait_for(
                    self.alert_callback(alert_payload),
                    timeout=cb_timeout_s,
                )
            except asyncio.TimeoutError:
                self.logger.error(f"alert_callback timed out (>{cb_timeout_s}s) on burst {i}.")
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception(f"alert_callback failed on burst {i}.")

            self.logger.info(
                f"Sent Dummy Alert Burst {i}/{self.count} "
                f"(UID {uid}, plot_pin={self.plot_pin})"
            )

            end_time = time.time() + float(self.interval_seconds)
            while not self._stop and time.time() < end_time:
                await asyncio.sleep(tick_s)

        self.logger.info("Dummy Alert Burst operation complete.")


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})