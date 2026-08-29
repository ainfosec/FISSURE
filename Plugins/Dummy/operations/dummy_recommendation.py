#! /usr/bin/env python3
"""Dummy Target Recommendation operation."""

import logging
import os
import sys
from typing import Callable, Union

try:
    from fissure.utils.plugins.operations import Operation
except ImportError:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
    from fissure.utils.plugins.operations import Operation


class OperationMain(Operation):
    def __init__(
        self,
        target_id: str = "",
        reason: str = "Dummy analysis identified a useful follow-on action",
        interval_seconds: float = 3.0,
        count: float = 3.0,
        plot_pin: str = "false",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        recommendation_callback: Union[Callable, None] = None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            recommendation_callback=recommendation_callback,
        )
        self.target_id = str(target_id or "").strip()
        self.reason = str(reason or "").strip()
        self.interval_seconds = float(interval_seconds)
        self.count = int(float(count))
        self.plot_pin = str(plot_pin or "false").strip().lower()

    async def run(self) -> None:
        if not self.target_id:
            raise RuntimeError("Dummy Recommendation requires a Target ID.")
        if not self.recommendation_callback:
            raise RuntimeError("Dummy Recommendation requires recommendation_callback.")

        recommendation = {
            "plugin": "Dummy",
            "action": "dummy_alert_burst",
            "reason": self.reason,
            "parameters": {
                "interval_seconds": self.interval_seconds,
                "count": self.count,
                "plot_pin": self.plot_pin,
            },
            "source_plugin": "Dummy",
            "source_action": "dummy_recommendation",
            "operation_id": self.opid,
        }
        await self.recommendation_callback(self.target_id, recommendation)
        self.logger.info(
            "Dummy recommendation emitted for target %s: Dummy: dummy_alert_burst",
            self.target_id,
        )


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})