#! /usr/bin/env python3
"""IQ Inspection Live Operation

Launch a GUI-based live IQ inspection flow graph on the executing Sensor Node.

This expanded version supports all currently organized live Inspection methods:

    instantaneous_frequency
    signal_envelope
    time_sink
    time_sink_1_10_100
    waterfall

It also supports all currently organized hardware mappings across maint-3.8 and
maint-3.10. Version-specific hardware availability is enforced at runtime.
"""

import asyncio
import logging
import os
import re
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


LIVE_METHOD_PREFIXES = {
    "instantaneous_frequency": "instantaneous_frequency",
    "signal_envelope": "signal_envelope",
    "time_sink": "time_sink",
    "time_sink_1_10_100": "time_sink_1_10_100",
    "waterfall": "waterfall",
}


LIVE_HARDWARE_CONFIG = {
    "USRP B20xmini": {
        "directory": "b2x0",
        "suffix": "b20xmini",
        "versions": {
            "maint-3.8",
            "maint-3.10",
        },
    },
    "USRP B2x0": {
        "directory": "b2x0",
        "suffix": "b2x0",
        "versions": {
            "maint-3.8",
            "maint-3.10",
        },
    },
    "bladeRF": {
        "directory": "bladerf",
        "suffix": "bladerf",
        "versions": {
            "maint-3.8",
            "maint-3.10",
        },
    },
    "bladeRF 2.0": {
        "directory": "bladerf2",
        "suffix": "bladerf2",
        "versions": {
            "maint-3.8",
            "maint-3.10",
        },
    },
    "HackRF": {
        "directory": "hackrf",
        "suffix": "hackrf",
        "versions": {
            "maint-3.8",
            "maint-3.10",
        },
    },
    "LimeSDR": {
        "directory": "limesdr",
        "suffix": "limesdr",
        "versions": {
            "maint-3.8",
            "maint-3.10",
        },
    },
    "PlutoSDR": {
        "directory": "plutosdr",
        "suffix": "plutosdr",
        "versions": {
            "maint-3.8",
            "maint-3.10",
        },
    },
    "RTL2832U": {
        "directory": "rtl2832u",
        "suffix": "rtl2832u",
        "versions": {
            "maint-3.8",
            "maint-3.10",
        },
    },
    "USRP2": {
        "directory": "usrp2",
        "suffix": "usrp2",
        "versions": {
            "maint-3.8",
            "maint-3.10",
        },
    },
    "USRP N2xx": {
        "directory": "usrp_n2xx",
        "suffix": "usrp_n2xx",
        "versions": {
            "maint-3.8",
            "maint-3.10",
        },
    },
    "USRP X3x0": {
        "directory": "x3x0",
        "suffix": "x3x0",
        "versions": {
            "maint-3.8",
            "maint-3.10",
        },
    },
    "USRP X410": {
        "directory": "x410",
        "suffix": "usrp_x410",
        "versions": {
            "maint-3.8",
            "maint-3.10",
        },
    },
    "CaribouLite": {
        "directory": "cariboulite",
        "suffix": "cariboulite",
        "versions": {
            "maint-3.10",
        },
    },
    "RSPduo": {
        "directory": "rspduo",
        "suffix": "rspduo",
        "versions": {
            "maint-3.10",
        },
    },
    "RSPdx": {
        "directory": "rspdx",
        "suffix": "rspdx",
        "versions": {
            "maint-3.10",
        },
    },
    "RSPdx R2": {
        "directory": "rspdx_r2",
        "suffix": "rspdx_r2",
        "versions": {
            "maint-3.10",
        },
    },
}


class OperationMain(Operation):
    """GUI-based live IQ inspection operation."""

    def __init__(
        self,
        operation_id: str = "",
        requester: str = "",
        inspection_method: str = "waterfall",

        hardware_display_name: str = "",
        hardware_type: str = "",
        hardware_uuid: str = "",
        hardware_radio_name: str = "",
        hardware_serial: str = "",
        hardware_serial_argument: str = "False",
        hardware_interface: str = "",
        hardware_ip: str = "",
        hardware_daughterboard: str = "",

        rx_channel: str = "A:A",
        description: str = "Live IQ inspection",

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

        self.hardware_display_name = str(
            hardware_display_name
            or ""
        ).strip()
        self.hardware_type = str(
            hardware_type
            or ""
        ).strip()
        self.hardware_uuid = str(
            hardware_uuid
            or ""
        ).strip()
        self.hardware_radio_name = str(
            hardware_radio_name
            or ""
        ).strip()
        self.hardware_serial = str(
            hardware_serial
            or ""
        ).strip()
        self.hardware_serial_argument = str(
            hardware_serial_argument
            or "False"
        ).strip()
        self.hardware_interface = str(
            hardware_interface
            or ""
        ).strip()
        self.hardware_ip = str(
            hardware_ip
            or ""
        ).strip()
        self.hardware_daughterboard = str(
            hardware_daughterboard
            or ""
        ).strip()

        self.rx_channel = str(
            rx_channel
            or "A:A"
        ).strip()
        self.description = str(
            description
            or "Live IQ inspection"
        ).strip()

        self.process = None

        self.logger.info(
            "iq_inspection_live init params: "
            f"operation_id={self.operation_id}, "
            f"requester={self.requester}, "
            f"inspection_method={self.inspection_method}, "
            f"hardware_type={self.hardware_type}, "
            f"hardware_serial_argument={self.hardware_serial_argument}, "
            f"hardware_ip={self.hardware_ip}, "
            f"rx_channel={self.rx_channel}"
        )

    async def run(self) -> None:
        """Launch and monitor the selected live Inspection GUI."""
        try:
            self._validate()

            if self.status_callback:
                await self.status_callback(
                    "Running: IQ Inspection"
                )

            await self._run_gui_process()

        except asyncio.CancelledError:
            self.logger.info(
                "iq_inspection_live cancelled"
            )
            raise

        except Exception:
            self.logger.exception(
                "iq_inspection_live failed"
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
                        "iq_inspection_live status_callback failed "
                        "while setting Idle"
                    )

    def _validate(self) -> None:
        if self.inspection_method not in LIVE_METHOD_PREFIXES:
            raise RuntimeError(
                "Unsupported live IQ Inspection method: "
                f"{self.inspection_method}"
            )

        hardware_config = LIVE_HARDWARE_CONFIG.get(
            self.hardware_type
        )

        if hardware_config is None:
            raise RuntimeError(
                "Unsupported live IQ Inspection hardware: "
                f"{self.hardware_type}"
            )

        version = self._get_library_version()

        if version not in hardware_config["versions"]:
            raise RuntimeError(
                "Live IQ Inspection hardware is not available for the "
                f"current GNU Radio library version. "
                f"version={version!r}, hardware_type={self.hardware_type!r}"
            )

    async def _run_gui_process(self) -> None:
        script_path = self._resolve_flow_graph_path()
        command = self._build_command(
            script_path
        )

        self.logger.info(
            "Starting live IQ Inspection GUI: "
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
                "Live IQ Inspection GUI exited with return code "
                f"{return_code}"
            )

    def _resolve_flow_graph_path(self) -> str:
        version = self._get_library_version()
        hardware_config = LIVE_HARDWARE_CONFIG[
            self.hardware_type
        ]
        method_prefix = LIVE_METHOD_PREFIXES[
            self.inspection_method
        ]

        flow_graph_name = (
            f"{method_prefix}_{hardware_config['suffix']}"
        )

        path = os.path.join(
            PLUGIN_ROOT,
            "flow_graphs",
            "iq_inspection_flow_graphs",
            version,
            hardware_config["directory"],
            f"{flow_graph_name}.py",
        )

        if not os.path.isfile(
            path
        ):
            raise FileNotFoundError(
                "Live IQ Inspection flow graph not found: "
                f"{path}"
            )

        return path

    def _build_command(
        self,
        script_path: str,
    ):
        command = [
            sys.executable,
            "-u",
            script_path,
        ]

        constructor_args = self._discover_constructor_args(
            script_path
        )

        available_values = {
            "rx_usrp_channel": self.rx_channel,
            "serial": (
                self.hardware_serial_argument
                or self.hardware_serial
            ),
            "ip_address": self.hardware_ip,
            "uuid": self.hardware_uuid,
        }

        for argument_name in constructor_args:
            argument_value = available_values.get(
                argument_name
            )

            if argument_value is None:
                continue

            if str(
                argument_value
            ).strip() == "":
                continue

            command.extend(
                [
                    f"--{argument_name.replace('_', '-')}",
                    str(argument_value),
                ]
            )

        return command

    @staticmethod
    def _discover_constructor_args(
        script_path: str,
    ):
        with open(
            script_path,
            "r",
            encoding="utf-8",
        ) as flow_graph_file:
            flow_graph_text = flow_graph_file.read()

        match = re.search(
            r"def __init__\(self(?:,\s*(.*?))?\):",
            flow_graph_text,
        )

        if match is None:
            return []

        parameter_text = (
            match.group(1)
            or ""
        ).strip()

        if not parameter_text:
            return []

        parameter_names = []

        for raw_parameter in parameter_text.split(","):
            raw_parameter = raw_parameter.strip()

            if not raw_parameter:
                continue

            parameter_name = raw_parameter.split(
                "=",
                1,
            )[0].strip()

            if parameter_name:
                parameter_names.append(
                    parameter_name
                )

        return parameter_names

    @staticmethod
    def _get_library_version() -> str:
        return (
            get_library_version()
            or "maint-3.10"
        )

    async def _terminate_process(self) -> None:
        process = self.process

        if (
            process is None
            or process.returncode is not None
        ):
            return

        self.logger.info(
            "Stopping live IQ Inspection GUI..."
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
                "Live IQ Inspection GUI did not exit after SIGTERM; "
                "sending SIGKILL"
            )

            try:
                process.kill()
            except ProcessLookupError:
                return

            await process.wait()


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test

    run_test(
        OperationMain,
        {},
        {},
    )