#! /usr/bin/env python3
"""IQ Inspection File Operation

Launch a GUI-based IQ file inspection flow graph on the executing Sensor Node.

This expanded version supports all currently organized file Inspection methods:

    instantaneous_frequency
    signal_envelope
    waterfall
"""

import asyncio
import logging
import os
import sys
import uuid
from typing import Callable, Union


PLUGIN_ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
    )
)
FISSURE_REPO_ROOT = os.path.abspath(
    os.path.join(
        PLUGIN_ROOT,
        "..",
        "..",
    )
)

for path in (
    FISSURE_REPO_ROOT,
    PLUGIN_ROOT,
):
    if path not in sys.path:
        sys.path.insert(
            0,
            path,
        )

from fissure.utils.plugins.operations import Operation
from fissure.utils import get_library_version


IQ_INSPECTION_FILE_METHODS = {
    "instantaneous_frequency": "instantaneous_frequency",
    "signal_envelope": "signal_envelope",
    "waterfall": "waterfall",
}


class OperationMain(Operation):
    """GUI-based IQ file inspection operation."""

    def __init__(
        self,
        operation_id: str = "",
        requester: str = "",
        inspection_method: str = "waterfall",
        filepath: str = "",
        sample_rate: Union[str, float] = 1000000.0,
        description: str = "IQ file inspection",

        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        status_callback: Union[Callable, None] = None,
        target_callback: Union[Callable, None] = None,
        soi_callback: Union[Callable, None] = None,
        artifact_manager=None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            status_callback=status_callback,
            target_callback=target_callback,
            soi_callback=soi_callback,
            artifact_manager=artifact_manager,
        )

        self.operation_id = str(
            operation_id
            or self.opid
            or uuid.uuid4()
        )
        self.requester = str(
            requester
            or ""
        ).strip()
        self.inspection_method = str(
            inspection_method
            or "waterfall"
        ).strip().lower()
        self.filepath = str(
            filepath
            or ""
        ).strip()
        self.sample_rate = self._float(
            sample_rate,
            1000000.0,
        )
        self.description = str(
            description
            or "IQ file inspection"
        ).strip()

        self.process = None

        self.logger.info(
            "iq_inspection_file init params: "
            f"operation_id={self.operation_id}, "
            f"requester={self.requester}, "
            f"inspection_method={self.inspection_method}, "
            f"filepath={self.filepath}, "
            f"sample_rate={self.sample_rate}"
        )

    async def run(self) -> None:
        """Launch and monitor the selected file Inspection GUI."""
        try:
            self._validate()

            if self.status_callback:
                await self.status_callback(
                    "Running: IQ Inspection"
                )

            await self._run_gui_process()

        except asyncio.CancelledError:
            self.logger.info(
                "iq_inspection_file cancelled"
            )
            raise

        except Exception:
            self.logger.exception(
                "iq_inspection_file failed"
            )
            raise

        finally:
            await self._terminate_process()

            if self.status_callback:
                try:
                    await self.status_callback(
                        "Idle"
                    )
                except Exception:
                    self.logger.exception(
                        "iq_inspection_file status_callback failed "
                        "while setting Idle"
                    )

    def _validate(self) -> None:
        if self.inspection_method not in IQ_INSPECTION_FILE_METHODS:
            raise RuntimeError(
                "Unsupported IQ file Inspection method: "
                f"{self.inspection_method}"
            )

        if not self.filepath:
            raise RuntimeError(
                "IQ file Inspection requires filepath"
            )

        if not os.path.isfile(
            self.filepath
        ):
            raise FileNotFoundError(
                "IQ Inspection file not found on executing node: "
                f"{self.filepath}"
            )

        if self.sample_rate <= 0:
            raise RuntimeError(
                "IQ file Inspection requires sample_rate > 0"
            )

    async def _run_gui_process(self) -> None:
        script_path = self._resolve_flow_graph_path()

        command = [
            sys.executable,
            "-u",
            script_path,
            "--filepath",
            self.filepath,
            "--sample-rate",
            str(
                self.sample_rate
            ),
        ]

        self.logger.info(
            "Starting IQ file Inspection GUI: "
            f"{command}"
        )

        self.process = await asyncio.create_subprocess_exec(
            *command,
        )

        stopped_by_request = False

        while self.process.returncode is None:
            if getattr(
                self,
                "_stop",
                False,
            ):
                stopped_by_request = True
                await self._terminate_process()
                break

            await asyncio.sleep(
                0.1
            )

        return_code = (
            await self.process.wait()
            if self.process is not None
            else 0
        )

        if (
            not stopped_by_request
            and return_code != 0
        ):
            raise RuntimeError(
                "IQ file Inspection GUI exited with return code "
                f"{return_code}"
            )

    def _resolve_flow_graph_path(self) -> str:
        version = (
            get_library_version()
            or "maint-3.10"
        )

        flow_graph_name = str(
            IQ_INSPECTION_FILE_METHODS.get(
                self.inspection_method,
                "",
            )
            or ""
        ).strip()

        if not flow_graph_name:
            raise RuntimeError(
                "No IQ file Inspection flow graph configured for "
                f"inspection_method={self.inspection_method!r}"
            )

        path = os.path.join(
            PLUGIN_ROOT,
            "flow_graphs",
            "iq_inspection_flow_graphs",
            version,
            "file",
            f"{flow_graph_name}.py",
        )

        if not os.path.isfile(
            path
        ):
            raise FileNotFoundError(
                "IQ file Inspection flow graph not found: "
                f"{path}"
            )

        return path

    async def _terminate_process(self) -> None:
        process = self.process

        if (
            process is None
            or process.returncode is not None
        ):
            return

        self.logger.info(
            "Stopping IQ file Inspection GUI..."
        )

        try:
            process.terminate()
        except ProcessLookupError:
            return

        try:
            await asyncio.wait_for(
                process.wait(),
                timeout=5.0,
            )
        except asyncio.TimeoutError:
            self.logger.warning(
                "IQ file Inspection GUI did not exit after SIGTERM; "
                "sending SIGKILL"
            )

            try:
                process.kill()
            except ProcessLookupError:
                return

            await process.wait()

    @staticmethod
    def _float(
        value,
        default: float,
    ) -> float:
        try:
            return float(
                value
            )
        except Exception:
            return float(
                default
            )


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test

    run_test(
        OperationMain,
        {},
        {},
    )