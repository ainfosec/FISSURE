 #! /usr/bin/env python3
"""X10 OOK Library-backed field fuzzing operation."""

import asyncio
import importlib.util
import logging
import os
import sys
import uuid
from typing import Callable, Union


PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from fissure.utils.plugins.operations import Operation
from fissure.utils import get_library_version


X10_FUZZING_HARDWARE = {
    "USRP B20xmini": {
        "maint-3.8": ("X10_OOK_USRPB205mini_Fields.py", "X10_OOK_USRPB205mini_Fields"),
    },
    "USRP B2x0": {
        "maint-3.8": ("X10_OOK_USRPB210_Fields.py", "X10_OOK_USRPB210_Fields"),
    },
}


class OperationMain(Operation):
    """Run one X10 OOK field-fuzzing flow graph."""

    def __init__(
        self,
        operation_id: str = "",
        requester: str = "",
        hardware_display_name: str = "",
        hardware_type: str = "",
        hardware_uuid: str = "",
        hardware_radio_name: str = "",
        hardware_serial: str = "",
        hardware_serial_argument: str = "False",
        hardware_interface: str = "",
        hardware_ip: str = "",
        hardware_daughterboard: str = "",
        tx_frequency_mhz: Union[str, float] = 310.7,
        sample_rate_msps: Union[str, float] = 1.0,
        tx_gain: Union[str, float] = 60.0,
        tx_channel: str = "A:A",
        transmit_interval_s: Union[str, float] = 4.0,
        fuzzing_protocol: str = "X10",
        fuzzing_packet_type: str = "Default",
        fuzzing_fields: str = "[]",
        fuzzing_type: str = "[]",
        fuzzing_min: str = "[]",
        fuzzing_max: str = "[]",
        fuzzing_data: str = "0",
        fuzzing_seed: str = "0",
        fuzzing_interval: str = "5",
        packet_types_fields: str = "{}",
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

        self.operation_id = str(operation_id or self.opid or uuid.uuid4())
        self.opid = self.operation_id
        self.requester = str(requester or "").strip()
        self.hardware_display_name = str(hardware_display_name or "").strip()
        self.hardware_type = str(hardware_type or "").strip()
        self.hardware_uuid = str(hardware_uuid or "").strip()
        self.hardware_radio_name = str(hardware_radio_name or "").strip()
        self.hardware_serial = str(hardware_serial or "").strip()
        self.hardware_serial_argument = str(hardware_serial_argument or "False").strip()
        self.hardware_interface = str(hardware_interface or "").strip()
        self.hardware_ip = str(hardware_ip or "").strip()
        self.hardware_daughterboard = str(hardware_daughterboard or "").strip()

        self.tx_frequency_mhz = float(tx_frequency_mhz)
        self.sample_rate_msps = float(sample_rate_msps)
        self.tx_gain = float(tx_gain)
        self.tx_channel = str(tx_channel or "A:A").strip()
        self.transmit_interval_s = float(transmit_interval_s)

        self.fuzzing_protocol = str(fuzzing_protocol or "X10")
        self.fuzzing_packet_type = str(fuzzing_packet_type or "Default")
        self.fuzzing_fields = str(fuzzing_fields or "[]")
        self.fuzzing_type = str(fuzzing_type or "[]")
        self.fuzzing_min = str(fuzzing_min or "[]")
        self.fuzzing_max = str(fuzzing_max or "[]")
        self.fuzzing_data = str(fuzzing_data or "0")
        self.fuzzing_seed = str(fuzzing_seed or "0")
        self.fuzzing_interval = str(fuzzing_interval or "5")
        self.packet_types_fields = str(packet_types_fields or "{}")

    async def run(self) -> None:
        try:
            module_path, class_name = self._resolve_flow_graph()
            module = self._load_module(module_path)
            top_block_cls = getattr(module, class_name)

            tb = top_block_cls(
                serial=self.hardware_serial_argument,
                tx_frequency=self.tx_frequency_mhz * 1e6,
                tx_usrp_gain=self.tx_gain,
                tx_usrp_channel=self.tx_channel,
                sample_rate=self.sample_rate_msps * 1e6,
                transmit_interval=self.transmit_interval_s,
                fuzzing_seed=self.fuzzing_seed,
                fuzzing_fields=self.fuzzing_fields,
                fuzzing_type=self.fuzzing_type,
                fuzzing_min=self.fuzzing_min,
                fuzzing_max=self.fuzzing_max,
                fuzzing_data=self.fuzzing_data,
                fuzzing_interval=self.fuzzing_interval,
                fuzzing_protocol=self.fuzzing_protocol,
                fuzzing_packet_type=self.fuzzing_packet_type,
                packet_types_fields=self.packet_types_fields,
            )

            loop = asyncio.get_running_loop()
            wait_future = None
            try:
                tb.start()
                if self.status_callback:
                    await self.status_callback("Running: X10 Field Fuzzing")
                wait_future = loop.run_in_executor(None, tb.wait)
                while not getattr(self, "_stop", False):
                    if wait_future.done():
                        await wait_future
                        break
                    await asyncio.sleep(0.1)
            finally:
                try:
                    tb.stop()
                except Exception:
                    self.logger.exception("X10 fuzzing tb.stop failed")
                if wait_future is not None:
                    try:
                        await asyncio.wait_for(wait_future, timeout=5.0)
                    except asyncio.TimeoutError:
                        self.logger.warning("X10 fuzzing flow graph wait timed out after stop")
                    except Exception:
                        self.logger.exception("X10 fuzzing wait failed after stop")
                try:
                    tb.wait()
                except Exception:
                    pass
        except asyncio.CancelledError:
            self.logger.info("X10 field fuzzing cancelled")
            raise
        except Exception:
            self.logger.exception("X10 field fuzzing failed")
            raise
        finally:
            if self.status_callback:
                try:
                    await self.status_callback("Idle")
                except Exception:
                    self.logger.exception("X10 fuzzing status_callback failed while setting Idle")

    def _resolve_flow_graph(self):
        version = get_library_version() or "maint-3.8"
        hardware_config = X10_FUZZING_HARDWARE.get(self.hardware_type, {})
        flow_graph = hardware_config.get(version)
        if flow_graph is None:
            raise RuntimeError(f"X10 field fuzzing is not available for {self.hardware_type} on {version}.")

        filename, class_name = flow_graph
        path = os.path.join(
            PLUGIN_ROOT,
            "flow_graphs",
            "fuzzing_flow_graphs",
            version,
            filename,
        )
        if not os.path.isfile(path):
            raise FileNotFoundError(f"X10 fuzzing flow graph not found: {path}")
        return path, class_name

    @staticmethod
    def _load_module(module_path: str):
        module_name = f"fissure_x10_fuzz_{uuid.uuid4().hex}"
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load X10 fuzzing flow graph: {module_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module