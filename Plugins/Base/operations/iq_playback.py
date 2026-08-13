#! /usr/bin/env python3
"""IQ Playback Operation

IQ playback operation for the Base plugin.

Assumptions:
  - Playback files already exist on the executing Sensor Node for node_path.
  - File staging/transfer is performed by the caller before this operation.
  - Hardware-specific flow graphs are stored under:
      Plugins/Base/flow_graphs/iq_playback_flow_graphs/<maint-version>/<hardware>/
  - Public playback_mode values are:
      continuous
      single
"""

import asyncio
import importlib.util
import inspect
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
from fissure.utils import get_library_version, SENSOR_NODE_DIR


IQ_PLAYBACK_HARDWARE = {
    "USRP B20xmini": {
        "directory": "b2x0",
        "continuous": "iq_playback_b2x0",
        "single": "iq_playback_single_b2x0",
    },
    "USRP B2x0": {
        "directory": "b2x0",
        "continuous": "iq_playback_b2x0",
        "single": "iq_playback_single_b2x0",
    },
    "bladeRF": {
        "directory": "bladerf",
        "continuous": "iq_playback_bladerf",
        "single": "iq_playback_single_bladerf",
    },
    "bladeRF 2.0": {
        "directory": "bladerf2",
        "continuous": "iq_playback_bladerf2",
        "single": "iq_playback_single_bladerf2",
    },
    "HackRF": {
        "directory": "hackrf",
        "continuous": "iq_playback_hackrf",
        "single": "iq_playback_single_hackrf",
    },
    "LimeSDR": {
        "directory": "limesdr",
        "continuous": "iq_playback_limesdr",
        "single": "iq_playback_single_limesdr",
    },
    "PlutoSDR": {
        "directory": "plutosdr",
        "continuous": "iq_playback_plutosdr",
        "single": "iq_playback_single_plutosdr",
    },
    "USRP2": {
        "directory": "usrp2",
        "continuous": "iq_playback_usrp2",
        "single": "iq_playback_single_usrp2",
    },
    "USRP N2xx": {
        "directory": "usrp_n2xx",
        "continuous": "iq_playback_usrp_n2xx",
        "single": "iq_playback_single_usrp_n2xx",
    },
    "USRP X3x0": {
        "directory": "x3x0",
        "continuous": "iq_playback_x3x0",
        "single": "iq_playback_single_x3x0",
    },
    "USRP X410": {
        "directory": "x410",
        "continuous": "iq_playback_usrp_x410",
        "single": "iq_playback_single_usrp_x410",
    },
    "CaribouLite": {
        "directory": "cariboulite",
        "continuous": "iq_playback_cariboulite",
        "single": "iq_playback_single_cariboulite",
        "versions": {
            "maint-3.10",
        },
    },
}


class OperationMain(Operation):
    """IQ Playback Operation"""

    def __init__(
        self,
        operation_id: str = "",
        requester: str = "",
        playback_mode: str = "continuous",
        playback_file_mode: str = "node_path",
        filepath: str = "",

        hardware_display_name: str = "",
        hardware_type: str = "",
        hardware_uuid: str = "",
        hardware_radio_name: str = "",
        hardware_serial: str = "",
        hardware_serial_argument: str = "False",
        hardware_interface: str = "",
        hardware_ip: str = "",
        hardware_daughterboard: str = "",

        tx_frequency: Union[str, float] = 915.0,
        tx_channel: str = "A:A",
        tx_antenna: str = "TX/RX",
        tx_gain: Union[str, float] = 70.0,
        sample_rate_msps: Union[str, float] = 1.0,
        data_type: str = "Complex Float 32",
        description: str = "IQ playback",

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

        # Use the caller-visible operation ID as the Sensor Node registry ID.
        # This allows callers to stop only this playback operation by opid.
        self.opid = self.operation_id

        self.requester = str(
            requester
            or ""
        ).strip()

        self.playback_mode = str(
            playback_mode
            or "continuous"
        ).strip().lower()
        self.playback_file_mode = str(
            playback_file_mode
            or "node_path"
        ).strip().lower()
        self.filepath = str(
            filepath
            or ""
        ).strip()

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

        self.tx_frequency = self._float(
            tx_frequency,
            915.0,
        )
        self.tx_channel = str(
            tx_channel
            or "A:A"
        ).strip()
        self.tx_antenna = str(
            tx_antenna
            or "TX/RX"
        ).strip()
        self.tx_gain = self._float(
            tx_gain,
            70.0,
        )
        self.sample_rate_msps = self._float(
            sample_rate_msps,
            1.0,
        )
        self.data_type = str(
            data_type
            or "Complex Float 32"
        ).strip()
        self.description = str(
            description
            or "IQ playback"
        ).strip()

        hardware_config = (
            IQ_PLAYBACK_HARDWARE.get(
                self.hardware_type
            )
        )

        if hardware_config is not None:
            self.flow_graph_name = str(
                hardware_config.get(
                    self.playback_mode,
                    "",
                )
                or ""
            ).strip()
        else:
            self.flow_graph_name = ""

        self.logger.info(
            "iq_playback init params: "
            f"operation_id={self.operation_id}, "
            f"requester={self.requester}, "
            f"playback_mode={self.playback_mode}, "
            f"flow_graph_name={self.flow_graph_name}, "
            f"playback_file_mode={self.playback_file_mode}, "
            f"filepath={self.filepath}, "
            f"hardware_type={self.hardware_type}, "
            f"hardware_serial_argument={self.hardware_serial_argument}, "
            f"hardware_ip={self.hardware_ip}, "
            f"tx_frequency={self.tx_frequency}, "
            f"tx_channel={self.tx_channel}, "
            f"tx_antenna={self.tx_antenna}, "
            f"sample_rate_msps={self.sample_rate_msps}, "
            f"tx_gain={self.tx_gain}, "
            f"data_type={self.data_type}"
        )

    async def run(self) -> None:
        """Run IQ playback."""

        try:
            self._validate()

            await self._play_file()

        except asyncio.CancelledError:
            self.logger.info(
                "iq_playback cancelled"
            )
            raise

        except Exception:
            self.logger.exception(
                "iq_playback failed"
            )
            raise

        finally:
            if self.status_callback:
                try:
                    await self.status_callback(
                        "Idle"
                    )
                except Exception:
                    self.logger.exception(
                        "iq_playback status_callback failed "
                        "while setting Idle"
                    )

    def _validate(
        self,
    ) -> None:
        if self.playback_mode not in {
            "continuous",
            "single",
        }:
            raise RuntimeError(
                "Unsupported IQ playback mode: "
                f"{self.playback_mode}"
            )

        hardware_config = (
            IQ_PLAYBACK_HARDWARE.get(
                self.hardware_type
            )
        )

        if hardware_config is None:
            raise RuntimeError(
                "Unsupported IQ playback hardware: "
                f"{self.hardware_type}"
            )

        version = (
            get_library_version()
            or "maint-3.10"
        )

        supported_versions = (
            hardware_config.get(
                "versions"
            )
        )

        if (
            supported_versions
            and version not in supported_versions
        ):
            raise RuntimeError(
                "IQ playback hardware is not available "
                f"for {version}: {self.hardware_type}"
            )

        expected_flow_graph = str(
            hardware_config.get(
                self.playback_mode,
                "",
            )
            or ""
        ).strip()

        if not expected_flow_graph:
            raise RuntimeError(
                "No IQ playback flow graph configured for "
                f"hardware_type={self.hardware_type!r}, "
                f"playback_mode={self.playback_mode!r}"
            )

        if self.flow_graph_name != expected_flow_graph:
            raise RuntimeError(
                "IQ playback hardware/flow-graph mismatch: "
                f"hardware_type={self.hardware_type!r}, "
                f"playback_mode={self.playback_mode!r}, "
                f"flow_graph_name={self.flow_graph_name!r}, "
                f"expected={expected_flow_graph!r}"
            )

        if self.playback_file_mode not in {
            "node_path",
            "transfer",
        }:
            raise RuntimeError(
                "Unsupported playback_file_mode: "
                f"{self.playback_file_mode}"
            )

        if not self.filepath:
            raise RuntimeError(
                "IQ playback requires filepath"
            )

        if (
            self.playback_file_mode
            == "transfer"
        ):
            transfer_path = str(
                self.filepath
                or ""
            ).strip()

            relative_path = os.path.normpath(
                transfer_path.lstrip(
                    "/"
                )
            )

            if (
                not relative_path
                or relative_path == "."
                or relative_path == ".."
                or relative_path.startswith(
                    "../"
                )
            ):
                raise RuntimeError(
                    "Invalid staged IQ playback filepath: "
                    f"{transfer_path}"
                )

            self.filepath = os.path.join(
                SENSOR_NODE_DIR,
                relative_path,
            )

            self.logger.info(
                "Resolved staged IQ playback filepath: "
                f"{transfer_path} -> {self.filepath}"
            )

        if not os.path.isfile(
            self.filepath
        ):
            raise FileNotFoundError(
                "IQ playback file not found on executing node: "
                f"{self.filepath}"
            )

        data_type_key = str(
            self.data_type
            or ""
        ).strip().lower()

        supported_complex_types = {
            "complex",
            "complex float 32",
            "complex float32",
            "cf32",
            "fc32",
            "gr_complex",
        }

        if (
            data_type_key
            not in supported_complex_types
        ):
            raise RuntimeError(
                "Unsupported IQ playback data_type: "
                f"{self.data_type}"
            )

        self.data_type = (
            "Complex Float 32"
        )

    async def _play_file(
        self,
    ) -> None:
        module_path = (
            self._resolve_flow_graph_path()
        )
        module = self._load_module(
            module_path
        )

        top_block_cls = getattr(
            module,
            self.flow_graph_name,
        )

        self.logger.info(
            "Starting IQ playback flow graph: "
            f"{module_path}"
        )

        available_arguments = {
            "filepath":
                self.filepath,
            "serial":
                self.hardware_serial_argument,
            "tx_channel":
                self.tx_channel,
            "tx_frequency":
                self.tx_frequency,
            "sample_rate":
                self.sample_rate_msps,
            "tx_gain":
                self.tx_gain,
            "tx_antenna":
                self.tx_antenna,
            "ip_address":
                self.hardware_ip,
        }

        constructor_signature = (
            inspect.signature(
                top_block_cls.__init__
            )
        )

        constructor_arguments = {
            name: value
            for name, value
            in available_arguments.items()
            if name
            in constructor_signature.parameters
        }

        self.logger.info(
            "IQ playback flow-graph constructor arguments: "
            f"{constructor_arguments}"
        )

        tb = top_block_cls(
            **constructor_arguments
        )

        loop = (
            asyncio.get_running_loop()
        )
        wait_future = None

        try:
            tb.start()

            self.logger.info(
                "IQ playback flow graph started."
            )

            if self.status_callback:
                await self.status_callback(
                    "Running: IQ Playback"
                )

            wait_future = (
                loop.run_in_executor(
                    None,
                    tb.wait,
                )
            )

            while not getattr(
                self,
                "_stop",
                False,
            ):
                if wait_future.done():
                    await wait_future
                    break

                await asyncio.sleep(
                    0.1
                )

        finally:
            self.logger.info(
                "Stopping IQ playback flow graph..."
            )

            try:
                tb.stop()
            except Exception:
                self.logger.exception(
                    "iq_playback tb.stop failed"
                )

            if wait_future is not None:
                try:
                    await asyncio.wait_for(
                        wait_future,
                        timeout=5.0,
                    )
                except asyncio.TimeoutError:
                    self.logger.warning(
                        "iq_playback flow graph wait "
                        "timed out after stop"
                    )
                except Exception:
                    self.logger.exception(
                        "iq_playback wait_future failed "
                        "after stop"
                    )

            try:
                tb.wait()
            except Exception:
                pass

            self.logger.info(
                "IQ playback flow graph stopped."
            )

    def _resolve_flow_graph_path(
        self,
    ) -> str:
        version = (
            get_library_version()
            or "maint-3.10"
        )

        hardware_config = (
            IQ_PLAYBACK_HARDWARE.get(
                self.hardware_type
            )
        )

        if hardware_config is None:
            raise RuntimeError(
                "Unsupported IQ playback hardware: "
                f"{self.hardware_type}"
            )

        hardware_dir = (
            hardware_config[
                "directory"
            ]
        )
        expected_flow_graph = str(
            hardware_config.get(
                self.playback_mode,
                "",
            )
            or ""
        ).strip()

        if (
            self.flow_graph_name
            != expected_flow_graph
        ):
            raise RuntimeError(
                "IQ playback hardware/flow-graph mismatch: "
                f"hardware_type={self.hardware_type!r}, "
                f"playback_mode={self.playback_mode!r}, "
                f"flow_graph_name={self.flow_graph_name!r}, "
                f"expected={expected_flow_graph!r}"
            )

        path = os.path.join(
            PLUGIN_ROOT,
            "flow_graphs",
            "iq_playback_flow_graphs",
            version,
            hardware_dir,
            f"{self.flow_graph_name}.py",
        )

        if not os.path.isfile(
            path
        ):
            raise FileNotFoundError(
                "IQ playback flow graph not found: "
                f"{path}"
            )

        return path

    def _load_module(
        self,
        path: str,
    ):
        module_name = (
            "fissure_plugin_iq_playback_"
            f"{uuid.uuid4().hex}"
        )
        module_dir = (
            os.path.dirname(
                path
            )
        )

        if module_dir not in sys.path:
            sys.path.insert(
                0,
                module_dir,
            )

        spec = (
            importlib.util.spec_from_file_location(
                module_name,
                path,
            )
        )

        if (
            spec is None
            or spec.loader is None
        ):
            raise ImportError(
                "Could not load IQ playback flow graph: "
                f"{path}"
            )

        module = (
            importlib.util.module_from_spec(
                spec
            )
        )

        sys.modules[
            module_name
        ] = module

        spec.loader.exec_module(
            module
        )

        return module

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