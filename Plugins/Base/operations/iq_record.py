#! /usr/bin/env python3
"""IQ Record Operation

IQ recorder operation for the Base plugin.

Assumptions:
  - Artifact files are local/unpacked under FISSURE/artifacts/<operation_id>/files.
  - B2x0/B20xmini record flow graph files are under:
      Plugins/Base/flow_graphs/iq_record_flow_graphs/<maint-version>/b2x0/
  - Zip transfer/download behavior is handled elsewhere.
"""

import asyncio
import datetime
import importlib.util
import json
import logging
import os
import sys
import time
import uuid
from typing import Any, Callable, Dict, Union


PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from fissure.utils.plugins.operations import Operation
from fissure.utils import FISSURE_ROOT, get_library_version


class OperationMain(Operation):
    """IQ Record Operation"""

    def __init__(
        self,
        operation_id: str = "",
        requester: str = "",
        flow_graph_name: str = "iq_recorder_b2x0",
        base_file_name: str = "capture.sigmf-data",
        artifact_format: str = "raw",

        hardware_display_name: str = "",
        hardware_type: str = "",
        hardware_uuid: str = "",
        hardware_radio_name: str = "",
        hardware_serial: str = "",
        hardware_serial_argument: str = "False",
        hardware_interface: str = "",
        hardware_ip: str = "",
        hardware_daughterboard: str = "",

        frequency_mhz: Union[str, float] = 915.0,
        rx_frequency: Union[str, float] = 915.0,
        rx_channel: str = "A:A",
        rx_antenna: str = "TX/RX",
        rx_gain: Union[str, float] = 20.0,
        sample_rate_msps: Union[str, float] = 1.0,
        file_length: Union[str, int] = 100000,
        number_of_files: Union[str, int] = 1,
        file_interval: Union[str, float] = 0.0,
        data_type: str = "Complex Float 32",

        sigmf_enabled: Union[str, bool] = True,
        sigmf_metadata: Union[Dict[str, Any], None] = None,
        description: str = "IQ recording",

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
        self.requester = str(requester or "").strip()

        self.flow_graph_name = str(flow_graph_name or "iq_recorder_b2x0").strip()
        self.base_file_name = os.path.basename(
            str(base_file_name or "capture.sigmf-data").strip()
        )

        self.artifact_format = str(artifact_format or "raw").strip().lower()
        if self.artifact_format not in {"raw", "zip"}:
            self.artifact_format = "raw"

        self.hardware_display_name = str(hardware_display_name or "").strip()
        self.hardware_type = str(hardware_type or "").strip()
        self.hardware_uuid = str(hardware_uuid or "").strip()
        self.hardware_radio_name = str(hardware_radio_name or "").strip()
        self.hardware_serial = str(hardware_serial or "").strip()
        self.hardware_serial_argument = str(hardware_serial_argument or "False").strip()
        self.hardware_interface = str(hardware_interface or "").strip()
        self.hardware_ip = str(hardware_ip or "").strip()
        self.hardware_daughterboard = str(hardware_daughterboard or "").strip()

        self.frequency_mhz = self._float(frequency_mhz, self._float(rx_frequency, 915.0))
        self.rx_frequency = self._float(rx_frequency, self.frequency_mhz)
        self.rx_channel = str(rx_channel or "A:A").strip()
        self.rx_antenna = str(rx_antenna or "TX/RX").strip()
        self.rx_gain = self._float(rx_gain, 20.0)
        self.sample_rate_msps = self._float(sample_rate_msps, 1.0)
        self.file_length = max(1, self._int(file_length, 100000))
        self.number_of_files = max(1, self._int(number_of_files, 1))
        self.file_interval = max(0.0, self._float(file_interval, 0.0))
        self.data_type = str(data_type or "Complex Float 32").strip()

        self.sigmf_enabled = self._bool(sigmf_enabled, True)
        self.sigmf_metadata = sigmf_metadata if isinstance(sigmf_metadata, dict) else {}
        self.description = str(description or "IQ recording").strip()

        self.logger.info(
            "iq_record init params: "
            f"operation_id={self.operation_id}, "
            f"requester={self.requester}, "
            f"flow_graph_name={self.flow_graph_name}, "
            f"base_file_name={self.base_file_name}, "
            f"artifact_format={self.artifact_format}, "
            f"hardware_type={self.hardware_type}, "
            f"hardware_serial_argument={self.hardware_serial_argument}, "
            f"rx_frequency={self.rx_frequency}, "
            f"rx_channel={self.rx_channel}, "
            f"rx_antenna={self.rx_antenna}, "
            f"sample_rate_msps={self.sample_rate_msps}, "
            f"rx_gain={self.rx_gain}, "
            f"file_length={self.file_length}, "
            f"number_of_files={self.number_of_files}, "
            f"file_interval={self.file_interval}, "
            f"data_type={self.data_type}, "
            f"sigmf_enabled={self.sigmf_enabled}"
        )

    async def run(self) -> None:
        """Run IQ recording."""

        try:
            self._validate()

            if self.status_callback:
                await self.status_callback("Running: IQ Record")

            await self._record_files()

        except asyncio.CancelledError:
            self.logger.info("iq_record cancelled")
            raise

        except Exception:
            self.logger.exception("iq_record failed")
            raise

        finally:
            if self.status_callback:
                try:
                    await self.status_callback("Idle")
                except Exception:
                    self.logger.exception("iq_record status_callback failed while setting Idle")

    def _validate(self) -> None:
        if not self.artifact_manager:
            raise RuntimeError("iq_record requires artifact_manager to be passed in")

        if self.flow_graph_name != "iq_recorder_b2x0":
            raise RuntimeError(
                f"Unsupported IQ recorder flow graph for first pass: {self.flow_graph_name}"
            )

        if self.hardware_type not in {"USRP B20xmini", "USRP B2x0"}:
            raise RuntimeError(
                f"Unsupported IQ recording hardware for first pass: {self.hardware_type}"
            )

        data_type_key = str(self.data_type or "").strip().lower()
        supported_complex_types = {
            "complex",
            "complex float 32",
            "complex float32",
            "cf32",
            "fc32",
            "gr_complex",
        }

        if data_type_key not in supported_complex_types:
            raise RuntimeError(
                f"Unsupported IQ recording data_type for first pass: {self.data_type}"
            )

        self.data_type = "Complex Float 32"

    async def _record_files(self) -> None:
        operation_id = self.operation_id
        artifact_name = f"IQ Recording {self.rx_frequency:g} MHz"

        _, folder = self.artifact_manager.create_operation_dir(operation_id)

        recorded_files = []
        stopped_early = False

        for file_index in range(self.number_of_files):
            if getattr(self, "_stop", False):
                stopped_early = True
                break

            output_path = self._make_output_path(folder, file_index)

            await self._record_one_file(output_path)
            recorded_files.append(output_path)

            if self.sigmf_enabled:
                self._write_sigmf_meta(output_path, file_index)

            if getattr(self, "_stop", False):
                stopped_early = True
                break

            if self.file_interval > 0 and file_index < self.number_of_files - 1:
                await self._sleep_interruptible(self.file_interval)

        if not recorded_files:
            self.logger.info(
                f"iq_record stopped before any files were recorded: operation_id={operation_id}"
            )
            return

        manifest_path = self._write_manifest(folder, recorded_files, stopped_early)

        metadata = {
            "role": (
                "iq_recording_raw_v1"
                if self.artifact_format == "raw"
                else "iq_recording_bundle_v1"
            ),
            "artifact_format": self.artifact_format,
            "operation_id": operation_id,
            "node_uid": self.node_uid,
            "source_id": self.node_uid,
            "description": self.description,
            "stopped_early": stopped_early,

            "flow_graph_name": self.flow_graph_name,
            "hardware_type": self.hardware_type,
            "hardware_display_name": self.hardware_display_name,
            "hardware_uuid": self.hardware_uuid,
            "hardware_radio_name": self.hardware_radio_name,
            "hardware_serial": self.hardware_serial,
            "hardware_ip": self.hardware_ip,
            "hardware_daughterboard": self.hardware_daughterboard,

            "frequency_mhz": self.rx_frequency,
            "sample_rate_msps": self.sample_rate_msps,
            "rx_gain": self.rx_gain,
            "rx_channel": self.rx_channel,
            "rx_antenna": self.rx_antenna,
            "file_length": self.file_length,
            "requested_number_of_files": self.number_of_files,
            "recorded_file_count": len(recorded_files),
            "file_interval": self.file_interval,
            "data_type": self.data_type,
            "sigmf_enabled": self.sigmf_enabled,
            "manifest_path": manifest_path,
            "recorded_files": recorded_files,
            "created_at": datetime.datetime.utcnow().isoformat("T") + "Z",
        }

        artifact_id = ""

        if self.artifact_format == "zip":
            artifact_id = (
                self.artifact_manager
                .create_zip_artifact_from_folder(
                    source_id=(
                        self.node_uid
                        or "sensor_node"
                    ),
                    operation_id=operation_id,
                    folder=folder,
                    name=artifact_name,
                    metadata=metadata,
                    arc_prefix=(
                        f"iq_recording_"
                        f"{operation_id}"
                    ),
                )
            )

        else:
            artifact_files = list(
                recorded_files
            )

            if (
                manifest_path
                and os.path.isfile(
                    manifest_path
                )
            ):
                artifact_files.append(
                    manifest_path
                )

            artifact_files = list(
                dict.fromkeys(
                    artifact_files
                )
            )

            file_metadata = {}

            for recorded_path in (
                recorded_files
            ):
                file_metadata[
                    recorded_path
                ] = {
                    "role": (
                        "sigmf_data"
                        if recorded_path.endswith(
                            ".sigmf-data"
                        )
                        else "iq_data"
                    ),
                    "content_type":
                        "application/octet-stream",
                    "data_type":
                        self.data_type,
                    "frequency_mhz":
                        self.rx_frequency,
                    "sample_rate_msps":
                        self.sample_rate_msps,
                }

                if recorded_path.endswith(
                    ".sigmf-data"
                ):
                    sigmf_meta_path = (
                        recorded_path.replace(
                            ".sigmf-data",
                            ".sigmf-meta",
                        )
                    )

                    if os.path.isfile(
                        sigmf_meta_path
                    ):
                        artifact_files.append(
                            sigmf_meta_path
                        )
                        file_metadata[
                            sigmf_meta_path
                        ] = {
                            "role":
                                "sigmf_metadata",
                            "content_type":
                                "application/json",
                            "data_file_name":
                                os.path.basename(
                                    recorded_path
                                ),
                        }

            if (
                manifest_path
                and os.path.isfile(
                    manifest_path
                )
            ):
                file_metadata[
                    manifest_path
                ] = {
                    "role":
                        "operation_metadata",
                    "content_type":
                        "application/json",
                }

            artifact_files = list(
                dict.fromkeys(
                    artifact_files
                )
            )

            artifact_id = (
                self.artifact_manager
                .create_artifact(
                    source_id=(
                        self.node_uid
                        or "sensor_node"
                    ),
                    operation_id=operation_id,
                    files=artifact_files,
                    name=artifact_name,
                    artifact_type="iq_recording",
                    metadata=metadata,
                    file_metadata=file_metadata,
                )
            )

        self.logger.info(
            f"iq_record created artifact_id={artifact_id}, "
            f"operation_id={operation_id}, folder={folder}, "
            f"recorded_file_count={len(recorded_files)}, stopped_early={stopped_early}"
        )

    async def _record_one_file(self, output_path: str) -> None:
        """Run one generated GNU Radio recorder flow graph and wait for it to finish."""

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        module_path = self._resolve_flow_graph_path()
        module = self._load_module(module_path)

        top_block_cls = getattr(module, self.flow_graph_name)

        self.logger.info(f"Starting IQ record flow graph: {module_path}")

        tb = top_block_cls(
            filepath=output_path,
            serial=self.hardware_serial_argument,
            rx_channel=self.rx_channel,
            rx_frequency=self.rx_frequency,
            sample_rate=self.sample_rate_msps,
            rx_gain=self.rx_gain,
            rx_antenna=self.rx_antenna,
            ip_address=self.hardware_ip,
            file_length=self.file_length,
        )

        loop = asyncio.get_running_loop()
        wait_future = None

        try:
            tb.start()
            wait_future = loop.run_in_executor(None, tb.wait)

            while True:
                if wait_future.done():
                    await wait_future
                    break

                if getattr(self, "_stop", False):
                    self.logger.info(
                        "iq_record stop requested. Waiting for current recorder flow graph to finish/stop."
                    )
                    break

                await asyncio.sleep(0.1)

        finally:
            self.logger.info("Stopping IQ record flow graph...")

            try:
                tb.stop()
            except Exception:
                self.logger.exception("iq_record tb.stop failed")

            if wait_future is not None:
                try:
                    await asyncio.wait_for(wait_future, timeout=5.0)
                except asyncio.TimeoutError:
                    self.logger.warning("iq_record flow graph wait timed out after stop")
                except Exception:
                    self.logger.exception("iq_record wait_future failed after stop")

            try:
                tb.wait()
            except Exception:
                pass

            self.logger.info("IQ record flow graph stopped.")

        self._wait_for_file(output_path)

    def _resolve_flow_graph_path(self) -> str:
        version = get_library_version() or "maint-3.10"
        hardware_dir = "b2x0"

        path = os.path.join(
            PLUGIN_ROOT,
            "flow_graphs",
            "iq_record_flow_graphs",
            version,
            hardware_dir,
            f"{self.flow_graph_name}.py",
        )

        if not os.path.isfile(path):
            raise FileNotFoundError(f"IQ recorder flow graph not found: {path}")

        return path

    def _load_module(self, path: str):
        module_name = f"fissure_plugin_iq_record_{uuid.uuid4().hex}"
        module_dir = os.path.dirname(path)

        if module_dir not in sys.path:
            sys.path.insert(0, module_dir)

        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load flow graph module: {path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        return module

    def _make_output_path(self, folder: str, file_index: int) -> str:
        root, ext = os.path.splitext(self.base_file_name)

        if not ext:
            ext = ".iq"

        if self.sigmf_enabled and ext == ".iq":
            ext = ".sigmf-data"

        if self.number_of_files > 1:
            filename = f"{root}_{file_index:03d}{ext}"
        else:
            filename = f"{root}{ext}"

        return os.path.join(folder, filename)

    def _write_sigmf_meta(self, data_path: str, file_index: int) -> str:
        meta = json.loads(json.dumps(self.sigmf_metadata or {}))

        if not meta:
            meta = {
                "global": {},
                "captures": [{}],
                "annotations": [],
            }

        meta.setdefault("global", {})
        meta.setdefault("captures", [{}])

        if not meta["captures"]:
            meta["captures"].append({})

        meta["global"]["core:sample_rate"] = float(self.sample_rate_msps) * 1e6
        meta["global"]["core:datatype"] = "cf32_le"
        meta["global"]["core:version"] = meta["global"].get("core:version", "1.0.0")

        meta["captures"][0]["core:sample_start"] = 0
        meta["captures"][0]["core:frequency"] = float(self.rx_frequency) * 1e6
        meta["captures"][0]["core:datetime"] = (
            datetime.datetime.utcnow().isoformat("T") + "Z"
        )

        meta["fissure"] = {
            "operation_id": self.operation_id,
            "node_uid": self.node_uid,
            "hardware_type": self.hardware_type,
            "hardware_display_name": self.hardware_display_name,
            "flow_graph_name": self.flow_graph_name,
            "file_index": file_index,
        }

        meta_path = data_path.replace(".sigmf-data", ".sigmf-meta")
        if meta_path == data_path:
            meta_path = data_path + ".sigmf-meta"

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        return meta_path

    def _write_manifest(self, folder: str, recorded_files, stopped_early: bool) -> str:
        manifest = {
            "operation_id": self.operation_id,
            "node_uid": self.node_uid,
            "source_id": self.node_uid,
            "description": self.description,
            "artifact_format": self.artifact_format,
            "stopped_early": stopped_early,
            "flow_graph_name": self.flow_graph_name,
            "hardware_type": self.hardware_type,
            "frequency_mhz": self.rx_frequency,
            "sample_rate_msps": self.sample_rate_msps,
            "rx_gain": self.rx_gain,
            "rx_channel": self.rx_channel,
            "rx_antenna": self.rx_antenna,
            "file_length": self.file_length,
            "requested_number_of_files": self.number_of_files,
            "recorded_file_count": len(recorded_files),
            "file_interval": self.file_interval,
            "data_type": self.data_type,
            "sigmf_enabled": self.sigmf_enabled,
            "recorded_files": [os.path.basename(p) for p in recorded_files],
            "created_at": datetime.datetime.utcnow().isoformat("T") + "Z",
        }

        manifest_path = os.path.join(folder, "iq_record_manifest.json")

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return manifest_path

    async def _sleep_interruptible(self, seconds: float) -> None:
        deadline = time.time() + float(seconds)

        while time.time() < deadline:
            if getattr(self, "_stop", False):
                break
            await asyncio.sleep(0.1)

    def _wait_for_file(self, path: str, timeout_s: float = 5.0) -> None:
        deadline = time.time() + timeout_s

        while time.time() < deadline:
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                return
            time.sleep(0.05)

        if not os.path.isfile(path):
            raise FileNotFoundError(f"IQ output file was not created: {path}")

        if os.path.getsize(path) == 0:
            raise RuntimeError(f"IQ output file was created but is empty: {path}")

    @staticmethod
    def _float(value, default: float) -> float:
        try:
            return float(value)
        except Exception:
            return float(default)

    @staticmethod
    def _int(value, default: int) -> int:
        try:
            return int(float(value))
        except Exception:
            return int(default)

    @staticmethod
    def _bool(value, default: bool = False) -> bool:
        if isinstance(value, bool):
            return value

        if value is None:
            return default

        if isinstance(value, (int, float)):
            return bool(value)

        if isinstance(value, str):
            v = value.strip().lower()

            if v in {"true", "1", "yes", "y", "on", "enabled"}:
                return True

            if v in {"false", "0", "no", "n", "off", "disabled"}:
                return False

        return default


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test

    run_test(OperationMain, {}, {})