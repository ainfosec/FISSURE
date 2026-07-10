#! /usr/bin/env python3
"""Signal Conditioning File Operation

File/folder signal-conditioning operation for the Base plugin.

This operation runs file-source Conditioner flow graphs, writes operation
metadata for the Dashboard, optionally generates SigMF sidecar metadata, and
optionally builds a zip bundle.
"""

import asyncio
import datetime
import hashlib
import inspect
import json
import logging
import os
import shutil
import sys
import time
import uuid
import zipfile
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from fissure.utils.plugins.operations import Operation
from fissure.utils import FISSURE_ROOT, get_library_version


def _maybe_await(value):
    if inspect.isawaitable(value):
        return value

    async def _done():
        return value

    return _done()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except Exception:
        return int(default)


def _safe_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value

    if value is None:
        return default

    if isinstance(value, (int, float)):
        return bool(value)

    if isinstance(value, str):
        text = value.strip().lower()

        if text in {"true", "1", "yes", "y", "on", "enabled"}:
            return True

        if text in {"false", "0", "no", "n", "off", "disabled"}:
            return False

    return default


def _sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()

    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def _sha512_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha512()

    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def _regular_file_snapshot(folder: str) -> Dict[str, os.stat_result]:
    snapshot = {}

    if not os.path.isdir(folder):
        return snapshot

    for name in os.listdir(folder):
        path = os.path.join(folder, name)

        if not os.path.isfile(path):
            continue

        try:
            snapshot[name] = os.stat(path)
        except Exception:
            pass

    return snapshot


async def _wait_for_file_settle(
    paths: List[str],
    timeout_s: float = 5.0,
    stable_checks: int = 3,
    interval_s: float = 0.10,
) -> None:
    if not paths:
        return

    deadline = time.time() + timeout_s
    previous_sizes = {}
    stable_count = 0

    while time.time() < deadline:
        current_sizes = {}

        for path in paths:
            try:
                current_sizes[path] = os.path.getsize(path)
            except Exception:
                current_sizes[path] = -1

        if current_sizes == previous_sizes and all(size >= 0 for size in current_sizes.values()):
            stable_count += 1
        else:
            stable_count = 0

        if stable_count >= stable_checks:
            return

        previous_sizes = current_sizes
        await asyncio.sleep(interval_s)


def _bytes_per_sample(data_type: str) -> int:
    data_type = str(data_type or "").strip()

    mapping = {
        "Complex Float 64": 16,
        "Complex Float 32": 8,
        "Float/Float 32": 4,
        "Short/Int 16": 2,
        "Int/Int 32": 4,
        "Byte/Int 8": 1,
        "Complex Int 16": 4,
        "Complex Int 8": 2,
        "Complex Int 64": 16,
        "Unsigned Int 8": 1,
        "Unsigned Int 16": 2,
        "Unsigned Int 32": 4,
        "Complex Unsigned Int 64": 16,
        "Complex Unsigned Int 16": 4,
        "Complex Unsigned Int 8": 2,
    }

    return mapping.get(data_type, 8)


def _samples_from_size(size_bytes: int, data_type: str) -> int:
    sample_bytes = max(1, _bytes_per_sample(data_type))
    return int(size_bytes // sample_bytes)


def _data_type_path_component(data_type: str) -> str:
    data_type = str(data_type or "").strip().lower()

    mapping = {
        "complex float 32": "complex_float32",
        "complex float32": "complex_float32",
        "cf32": "complex_float32",
        "complex int 16": "complex_int16",
        "complex int16": "complex_int16",
        "ci16": "complex_int16",
    }

    return mapping.get(data_type, "complex_float32")


def _sigmf_datatype_for_data_type(data_type: str) -> str:
    data_type = str(data_type or "").strip()

    mapping = {
        "Complex Float 32": "cf32_le",
        "Complex Float 64": "cf64_le",
        "Float/Float 32": "rf32_le",
        "Short/Int 16": "ri16_le",
        "Int/Int 32": "ri32_le",
        "Byte/Int 8": "ri8",
        "Complex Int 16": "ci16_le",
        "Complex Int 8": "ci8",
        "Complex Int 64": "ci64_le",
        "Unsigned Int 8": "ru8",
        "Unsigned Int 16": "ru16_le",
        "Unsigned Int 32": "ru32_le",
        "Complex Unsigned Int 64": "cu64_le",
        "Complex Unsigned Int 16": "cu16_le",
        "Complex Unsigned Int 8": "cu8",
    }

    return mapping.get(data_type, "cf32_le")


def _conditioner_output_uses_sigmf(output_format: str) -> bool:
    """Return True when the selected Conditioner output should be SigMF."""
    text = str(output_format or "").strip().lower().replace("_", " ")
    return "sigmf" in text


def _conditioner_output_uses_zip(output_format: str) -> bool:
    """Return True when the selected Conditioner output should be bundled."""
    text = str(output_format or "").strip().lower().replace("_", " ")
    return "zip" in text or "bundle" in text


def conditioner_dtype_for_saturation(data_type: str):
    """
    Returns numpy dtype and saturation limits for a Conditioner result format.
    """
    try:
        import numpy as np
    except Exception:
        return None, None, None

    data_type = str(data_type or "").strip()

    dtype_map = {
        "Complex Float 32": (np.float32, -1.0, 1.0),
        "Float/Float 32": (np.float32, -1.0, 1.0),
        "Complex Float 64": (np.float64, -1.0, 1.0),
        "Byte/Int 8": (np.int8, -128, 127),
        "Complex Int 8": (np.int8, -128, 127),
        "Unsigned Int 8": (np.uint8, 0, 255),
        "Complex Unsigned Int 8": (np.uint8, 0, 255),
        "Short/Int 16": (np.int16, -32768, 32767),
        "Complex Int 16": (np.int16, -32768, 32767),
        "Unsigned Int 16": (np.uint16, 0, 65535),
        "Complex Unsigned Int 16": (np.uint16, 0, 65535),
        "Int/Int 32": (np.int32, -2147483648, 2147483647),
        "Complex Int 32": (np.int32, -2147483648, 2147483647),
        "Unsigned Int 32": (np.uint32, 0, 4294967295),
        "Complex Unsigned Int 32": (np.uint32, 0, 4294967295),
        "Complex Int 64": (np.int64, -9223372036854775808, 9223372036854775807),
        "Complex Unsigned Int 64": (np.uint64, 0, 18446744073709551615),
    }

    return dtype_map.get(data_type, (None, None, None))


def conditioner_file_is_saturated(
    filepath: str,
    data_type: str,
    chunk_bytes: int = 64 * 1024 * 1024,
) -> bool:
    """
    Performs a full-file saturation check.

    Returns True if any sample hits the min/max representable range for the
    selected data type. For normalized float formats, checks <= -1.0 or >= 1.0.
    """
    try:
        import numpy as np
    except Exception as e:
        raise RuntimeError(f"NumPy is required for saturation checking: {e}")

    dtype, min_value, max_value = conditioner_dtype_for_saturation(data_type)

    if dtype is None:
        raise ValueError(f"Unsupported saturation data type: {data_type}")

    if not filepath or not os.path.isfile(filepath):
        raise FileNotFoundError(filepath)

    dtype = np.dtype(dtype)
    item_size = dtype.itemsize

    chunk_bytes = max(item_size, int(chunk_bytes))
    chunk_bytes = chunk_bytes - (chunk_bytes % item_size)

    with open(filepath, "rb") as handle:
        while True:
            chunk = handle.read(chunk_bytes)

            if not chunk:
                break

            usable_size = len(chunk) - (len(chunk) % item_size)

            if usable_size <= 0:
                continue

            values = np.frombuffer(chunk[:usable_size], dtype=dtype)

            if values.size <= 0:
                continue

            if np.issubdtype(dtype, np.floating):
                if np.any(values <= min_value) or np.any(values >= max_value):
                    return True
            else:
                if np.any(values == min_value) or np.any(values == max_value):
                    return True

    return False


def apply_saturation_check_to_records(
    records: List[Dict[str, Any]],
    data_type: str,
    logger: Optional[logging.Logger] = None,
) -> Dict[str, int]:
    """
    Adds saturation metadata to result records in-place.
    """
    stats = {"checked": 0, "saturated": 0, "errors": 0}

    for record in records:
        if not isinstance(record, dict):
            continue

        filepath = str(record.get("path", "") or "").strip()
        record_data_type = str(
            record.get("data_type", "")
            or record.get("format", "")
            or data_type
            or ""
        ).strip()

        try:
            is_saturated = conditioner_file_is_saturated(
                filepath=filepath,
                data_type=record_data_type,
            )

            value = "Yes" if is_saturated else "No"
            record["saturated"] = value
            record["saturation_check"] = "full"
            record["saturation_checked_at"] = datetime.datetime.utcnow().isoformat("T") + "Z"

            stats["checked"] += 1
            if is_saturated:
                stats["saturated"] += 1

        except Exception as e:
            record["saturated"] = "Error"
            record["saturation_check"] = "full"
            record["saturation_error"] = str(e)
            stats["errors"] += 1

            if logger is not None:
                logger.warning(
                    "Conditioner saturation check failed for %s: %s",
                    filepath,
                    e,
                )

    return stats


class OperationMain(Operation):
    """Signal Conditioning File Operation"""

    def __init__(
        self,
        operation_id: str = "",
        requester: str = "",
        source_id: str = "",
        source_type: str = "file",
        category: str = "energy",
        method: str = "normal_decay",
        all_filepaths: Optional[List[str]] = None,
        output_directory: str = "",
        output_mode: str = "Local Folder",
        output_format: str = "Raw IQ Files",
        check_saturation: Union[str, bool] = False,
        saturation_check: str = "",
        prefix: str = "output_",
        data_type: str = "Complex Float 32",
        sample_rate: Union[str, float] = 1000000.0,
        tuned_frequency: Union[str, float] = "",
        frequency_mhz: Union[str, float] = "",
        threshold: Union[str, float] = 0.004,
        decay: Union[str, float] = 0.0002,
        max_files: Union[str, int] = 15,
        min_samples: Union[str, int] = 1,
        description: str = "File-source Conditioner output",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        status_callback: Union[Callable, None] = None,
        target_callback: Union[Callable, None] = None,
        soi_callback: Union[Callable, None] = None,
        artifact_manager=None,
        **kwargs,
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
        self.source_id = str(source_id or node_uid or "sensor_node").strip()
        self.source_type = str(source_type or "file").strip().lower()
        self.category = str(category or "energy").strip()
        self.method = str(method or "normal_decay").strip().lower().replace(" ", "_").replace("-", "_")

        self.all_filepaths = list(all_filepaths or [])
        self.output_directory = str(output_directory or "").strip()
        self.output_mode = self._normalize_output_mode(output_mode)
        self.output_format = self._normalize_output_format(output_format)
        self.check_saturation = _safe_bool(check_saturation, False)
        saturation_check_text = str(saturation_check or "").strip().lower()
        if saturation_check_text in {"full", "yes", "true", "1", "on"}:
            self.check_saturation = True
        self.prefix = str(prefix or "output_")

        self.data_type = str(data_type or "Complex Float 32").strip()
        self.sample_rate = _safe_float(sample_rate, 1000000.0)

        self.tuned_frequency = tuned_frequency
        if str(self.tuned_frequency).strip() == "" and str(frequency_mhz).strip() != "":
            self.tuned_frequency = frequency_mhz

        self.threshold = _safe_float(threshold, 0.004)
        self.decay = _safe_float(decay, 0.0002)
        self.max_files = max(1, _safe_int(max_files, 15))
        self.min_samples = max(0, _safe_int(min_samples, 1))
        self.description = str(description or "File-source Conditioner output").strip()

        self.rows: List[Dict[str, Any]] = []
        self.artifact_id = ""
        self.artifact_payload: Dict[str, Any] = {}

        self.logger.info(
            "signal_conditioning_file init params: "
            f"operation_id={self.operation_id}, "
            f"source_type={self.source_type}, "
            f"category={self.category}, "
            f"method={self.method}, "
            f"input_count={len(self.all_filepaths)}, "
            f"output_directory={self.output_directory}, "
            f"output_mode={self.output_mode}, "
            f"output_format={self.output_format}, "
            f"check_saturation={self.check_saturation}, "
            f"data_type={self.data_type}, "
            f"sample_rate={self.sample_rate}, "
            f"threshold={self.threshold}, "
            f"decay={self.decay}, "
            f"max_files={self.max_files}, "
            f"min_samples={self.min_samples}"
        )

    async def run(self) -> None:
        await self._set_progress(1, "Starting file signal conditioning")

        try:
            self._validate()

            output_dir = self._destination_dir()
            os.makedirs(output_dir, exist_ok=True)

            await self._set_progress(5, "Preparing Conditioner output")

            flow_graph_path = self._flow_graph_path()

            self.logger.info("Using Conditioner flow graph: %s", flow_graph_path)

            rows: List[Dict[str, Any]] = []
            valid_input_paths = self._valid_input_paths()

            if not valid_input_paths:
                raise ValueError("No valid Conditioner input files were found.")

            total_inputs = max(1, len(valid_input_paths))
            uses_sigmf = _conditioner_output_uses_sigmf(self.output_format)
            uses_zip = _conditioner_output_uses_zip(self.output_format)

            for input_index, input_path in enumerate(valid_input_paths, start=1):
                if getattr(self, "_stop", False):
                    self.logger.info("Stop requested before processing next input file.")
                    break

                start_percent = 10 + int(((input_index - 1) / total_inputs) * 75)
                start_percent = max(10, min(85, start_percent))

                await self._set_progress(
                    start_percent,
                    f"Conditioning {input_index}/{total_inputs}: {os.path.basename(input_path)}",
                )

                outputs = await self._run_flow_graph_for_file(
                    input_path=input_path,
                    output_dir=output_dir,
                    flow_graph_path=flow_graph_path,
                )

                for output_name, output_path in outputs:
                    row = self._build_row(
                        output_name=output_name,
                        output_path=output_path,
                        source_path=input_path,
                    )

                    if row is None:
                        continue

                    rows.append(row)
                    self.rows = rows

                    if uses_sigmf:
                        self._write_sigmf_meta_for_row(
                            row=row,
                            source_path=input_path,
                            file_index=len(rows) - 1,
                        )

                end_percent = 10 + int((input_index / total_inputs) * 75)
                end_percent = max(start_percent, min(85, end_percent))

                await self._set_progress(
                    end_percent,
                    (
                        f"Finished {input_index}/{total_inputs}: "
                        f"{len(outputs)} files from this input, "
                        f"{len(rows)} total"
                    ),
                )

            if self.check_saturation and rows:
                await self._set_progress(88, "Checking Conditioner output saturation")
                saturation_stats = apply_saturation_check_to_records(
                    rows,
                    self.data_type,
                    logger=self.logger,
                )
                self.logger.info(
                    "Conditioner saturation check complete: checked=%s saturated=%s errors=%s",
                    saturation_stats.get("checked", 0),
                    saturation_stats.get("saturated", 0),
                    saturation_stats.get("errors", 0),
                )

            await self._set_progress(90, "Writing Conditioner metadata")

            payload = self._build_payload(output_dir, rows)
            metadata_path = self._metadata_path(output_dir)

            payload["metadata_name"] = os.path.basename(metadata_path)
            payload["metadata_path"] = metadata_path

            with open(metadata_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)

            if uses_zip:
                await self._set_progress(95, "Building Conditioner artifact bundle")

                zip_path = self._create_zip_bundle(
                    output_dir=output_dir,
                    rows=rows,
                    metadata_path=metadata_path,
                )

                if uses_sigmf:
                    payload["artifact_format"] = "sigmf_zip_bundle"
                else:
                    payload["artifact_format"] = "raw_iq_zip_bundle"

                payload["bundle_path"] = zip_path
                payload["bundle_name"] = os.path.basename(zip_path)
                payload["bundle_size"] = os.path.getsize(zip_path)
                payload["bundle_relative_path"] = os.path.relpath(
                    zip_path,
                    FISSURE_ROOT,
                )

            elif uses_sigmf:
                payload["artifact_format"] = "sigmf_files"

            else:
                payload["artifact_format"] = "local_iq_files"

            creates_artifact = self.output_mode == "Artifact"

            if creates_artifact:
                await self._set_progress(97, "Registering Conditioner artifact")
                artifact_id = await self._create_artifact(payload)
            else:
                artifact_id = ""

            payload["artifact_id"] = artifact_id
            self.artifact_id = artifact_id
            self.artifact_payload = payload

            await self._set_progress(98, "Finalizing Conditioner metadata")

            with open(metadata_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)

            latest_metadata_path = os.path.join(
                output_dir,
                "signal_conditioning_file_artifact.json",
            )

            with open(latest_metadata_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)

            # Rebuild the zip after final metadata/artifact_id is known so the
            # bundled metadata matches the files written beside it.
            if uses_zip:
                zip_path = self._create_zip_bundle(
                    output_dir=output_dir,
                    rows=rows,
                    metadata_path=metadata_path,
                )
                payload["bundle_path"] = zip_path
                payload["bundle_name"] = os.path.basename(zip_path)
                payload["bundle_size"] = os.path.getsize(zip_path)
                payload["bundle_relative_path"] = os.path.relpath(
                    zip_path,
                    FISSURE_ROOT,
                )

                with open(metadata_path, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2, sort_keys=True)

                with open(latest_metadata_path, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2, sort_keys=True)

            await self._set_progress(
                100,
                f"Conditioner complete: {len(rows)} files",
            )

            # File conditioning does not publish alerts or TAK CoT directly.
            # Downstream actions can promote conditioned files into SOIs, alerts,
            # classifications, or TAK messages when operationally meaningful.
            self.logger.info(
                "File signal conditioning complete: artifact_id=%s file_count=%s output_dir=%s",
                artifact_id,
                len(rows),
                output_dir,
            )

        finally:
            await self._set_status("Idle")

    def _validate(self) -> None:
        if not self.all_filepaths:
            raise ValueError("No input files supplied in all_filepaths.")

        if self.max_files <= 0:
            raise ValueError("max_files must be greater than zero.")

        if self.method != "normal_decay":
            raise RuntimeError(
                f"Unsupported signal_conditioning_file method for first pass: {self.method}"
            )

        supported_types = {
            "Complex Float 32",
            "Complex Int 16",
        }

        if self.data_type not in supported_types:
            raise RuntimeError(
                f"Unsupported Conditioner data_type for first pass: {self.data_type}"
            )

    def _valid_input_paths(self) -> List[str]:
        valid_input_paths = []

        for input_path in self.all_filepaths:
            input_path = os.path.abspath(str(input_path))

            if not os.path.isfile(input_path):
                self.logger.warning("Skipping missing input file: %s", input_path)
                continue

            input_size = os.path.getsize(input_path)
            input_samples = _samples_from_size(input_size, self.data_type)

            if input_samples < self.min_samples:
                self.logger.info(
                    "Skipping %s: samples=%s min_samples=%s",
                    input_path,
                    input_samples,
                    self.min_samples,
                )
                continue

            valid_input_paths.append(input_path)

        return valid_input_paths

    async def _set_status(self, status: str) -> None:
        callback = getattr(self, "status_callback", None)
        if not callback:
            return

        try:
            await _maybe_await(callback(str(status or "")))
        except Exception:
            self.logger.exception("status_callback failed")

    async def _set_progress(self, percent: int, status: str = "") -> None:
        try:
            percent = int(percent)
        except Exception:
            percent = 0

        percent = max(0, min(100, percent))
        status = str(status or "").strip()

        if status:
            await self._set_status(f"{percent}% | {status}")
        else:
            await self._set_status(f"{percent}%")

    def _destination_dir(self) -> str:
        """
        Returns the directory where Conditioner output files are written.

        Local Folder:
            use the explicit user-selected output_directory.

        Artifact:
            ignore output_directory and always use managed FISSURE artifact
            storage. This keeps local and remote artifact runs consistent and
            prevents Dashboard-selected paths from leaking into remote nodes.
        """
        if self.output_mode == "Local Folder" and self.output_directory:
            return os.path.abspath(os.path.expanduser(self.output_directory))

        operation_id = self._operation_id() or "conditioner"

        return os.path.join(
            FISSURE_ROOT,
            "artifacts",
            operation_id,
            "files",
        )

    def _operation_id(self) -> str:
        return str(self.operation_id or self.opid or "").strip()

    def _metadata_name(self) -> str:
        operation_id = self._operation_id() or "conditioner"
        return f"conditioner_{operation_id}.json"

    def _metadata_path(self, output_dir: str) -> str:
        return os.path.join(output_dir, self._metadata_name())

    def _zip_bundle_name(self) -> str:
        operation_id = self._operation_id() or "conditioner"
        return f"conditioner_{operation_id}.zip"

    def _flow_graph_path(self) -> str:
        version = get_library_version() or "maint-3.10"
        data_type_dir = _data_type_path_component(self.data_type)

        path = os.path.join(
            PLUGIN_ROOT,
            "flow_graphs",
            "conditioner_flow_graphs",
            version,
            "file_source",
            data_type_dir,
            "burst_tagger",
            "normal_decay.py",
        )

        if not os.path.isfile(path):
            raise FileNotFoundError(f"Conditioner flow graph not found: {path}")

        return path

    def _build_command(
        self,
        python_path: str,
        flow_graph_path: str,
        input_path: str,
    ) -> List[str]:
        return [
            python_path,
            flow_graph_path,
            "--filepath",
            input_path,
            "--sample-rate",
            str(self.sample_rate),
            "--threshold",
            str(self.threshold),
            "--decay",
            str(self.decay),
        ]

    async def _run_flow_graph_for_file(
        self,
        input_path: str,
        output_dir: str,
        flow_graph_path: str,
    ) -> List[Tuple[str, str]]:
        before = _regular_file_snapshot(output_dir)

        python_path = shutil.which("python3") or shutil.which("python") or sys.executable
        cmd = self._build_command(python_path, flow_graph_path, input_path)

        self.logger.info("Conditioner flow graph argv: %r", cmd)
        self.logger.info("Conditioner output directory: %s", output_dir)

        env = os.environ.copy()

        pythonpath_parts = [
            os.path.dirname(flow_graph_path),
            PLUGIN_ROOT,
            FISSURE_REPO_ROOT,
        ]

        existing_pythonpath = env.get("PYTHONPATH", "")
        if existing_pythonpath:
            pythonpath_parts.append(existing_pythonpath)

        env["PYTHONPATH"] = os.pathsep.join(pythonpath_parts)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=output_dir,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await proc.communicate()

        if stdout:
            self.logger.info(
                "Conditioner stdout:\n%s",
                stdout.decode(errors="ignore").strip(),
            )

        if stderr:
            self.logger.warning(
                "Conditioner stderr:\n%s",
                stderr.decode(errors="ignore").strip(),
            )

        if proc.returncode != 0:
            raise RuntimeError(
                f"Conditioner flow graph failed with return code {proc.returncode}"
            )

        after = _regular_file_snapshot(output_dir)

        new_names = [
            fname
            for fname in after
            if fname not in before
        ]

        new_names = sorted(
            new_names,
            key=lambda name: (
                after[name].st_mtime,
                name,
            ),
        )

        if self.max_files > 0:
            extra_names = new_names[self.max_files:]
            new_names = new_names[:self.max_files]

            for extra_name in extra_names:
                extra_path = os.path.join(output_dir, extra_name)
                self.logger.info(
                    "Max files per input reached; leaving extra generated file unlisted: %s",
                    extra_path,
                )

        new_paths = [os.path.join(output_dir, fname) for fname in new_names]
        await _wait_for_file_settle(new_paths)

        renamed_outputs = []
        uses_sigmf = _conditioner_output_uses_sigmf(self.output_format)

        for fname in new_names:
            original_path = os.path.join(output_dir, fname)

            output_index = len(self.rows) + len(renamed_outputs) + 1
            output_name = self._output_file_name(
                output_index,
                sigmf_data=uses_sigmf,
            )
            output_path = os.path.join(output_dir, output_name)

            while os.path.exists(output_path):
                output_index += 1
                output_name = self._output_file_name(
                    output_index,
                    sigmf_data=uses_sigmf,
                )
                output_path = os.path.join(output_dir, output_name)

            if os.path.abspath(original_path) != os.path.abspath(output_path):
                os.rename(original_path, output_path)

            renamed_outputs.append((output_name, output_path))

        return renamed_outputs

    def _safe_filename_component(
        self,
        value: Any,
        default: str = "",
    ) -> str:
        """
        Returns a filesystem-safe filename component.
        """
        text = str(value or "").strip()

        if not text:
            return default

        safe = []

        for char in text:
            if char.isalnum() or char in ("-", "_", "."):
                safe.append(char)
            elif char in (" ", ":", "/", "\\"):
                safe.append("_")
            else:
                safe.append("_")

        text = "".join(safe)

        while "__" in text:
            text = text.replace("__", "_")

        return text.strip("_") or default

    def _output_file_name(
        self,
        output_index: int,
        sigmf_data: bool = False,
    ) -> str:
        """
        Builds the final user-facing Conditioner output filename for
        file/folder-source conditioning.
        """
        operation_id = self._operation_id() or "conditioner"
        short_id = operation_id.split("-")[0] if "-" in operation_id else operation_id[:8]
        short_id = self._safe_filename_component(short_id, default="conditioner")

        clean_prefix = self._safe_filename_component(
            self.prefix,
            default="output_",
        )

        if clean_prefix and not clean_prefix.endswith("_"):
            clean_prefix = f"{clean_prefix}_"

        extension = ".sigmf-data" if sigmf_data else ".dat"
        return f"{clean_prefix}{short_id}_{output_index:05d}{extension}"

    def _build_row(
        self,
        output_name: str,
        output_path: str,
        source_path: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Builds one Conditioner output row.

        Important:
            format/data_type must remain the IQ sample data type.
            SigMF is represented by file_type and sigmf fields, not by format.
        """
        if not os.path.isfile(output_path):
            return None

        size_bytes = os.path.getsize(output_path)
        samples = _samples_from_size(size_bytes, self.data_type)

        is_sigmf_data = output_name.endswith(".sigmf-data")

        row = {
            "name": output_name,
            "path": output_path,
            "relative_path": os.path.relpath(output_path, FISSURE_ROOT),
            "size": size_bytes,
            "samples": samples,

            # Keep this as the actual IQ data type.
            # Dashboard strip/preview depends on this being Complex Float 32,
            # Complex Int 16, etc.
            "format": self.data_type,
            "data_type": self.data_type,

            # Store container/file representation separately.
            "file_type": "sigmf-data" if is_sigmf_data else "iq",
            "sigmf": bool(is_sigmf_data),

            "sample_rate": self.sample_rate,
            "frequency_mhz": self.tuned_frequency,
            "source": source_path,
            "source_name": os.path.basename(source_path),
            "sha256": _sha256_file(output_path),
        }

        return row

    def _write_sigmf_meta_for_row(
        self,
        row: Dict[str, Any],
        source_path: str,
        file_index: int,
    ) -> str:
        data_path = str(row.get("path", "") or "")

        if not data_path:
            return ""

        if data_path.endswith(".sigmf-data"):
            meta_path = data_path.replace(".sigmf-data", ".sigmf-meta")
        else:
            meta_path = data_path + ".sigmf-meta"

        frequency_hz = None
        try:
            if str(self.tuned_frequency).strip():
                frequency_hz = float(self.tuned_frequency) * 1e6
        except Exception:
            frequency_hz = None

        checksum = ""
        try:
            checksum = _sha512_file(data_path)
        except Exception:
            self.logger.exception("Failed to calculate SigMF sha512 for %s", data_path)

        capture = {
            "core:sample_start": 0,
            "core:datetime": datetime.datetime.utcnow().isoformat("T") + "Z",
        }

        if frequency_hz is not None:
            capture["core:frequency"] = frequency_hz

        meta = {
            "global": {
                "core:datatype": _sigmf_datatype_for_data_type(self.data_type),
                "core:sample_rate": float(self.sample_rate),
                "core:version": "1.0.0",
                "core:dataset": os.path.basename(data_path),
                "core:sha512": checksum,
                "core:description": (
                    f"FISSURE Conditioner output. "
                    f"category={self.category}, method={self.method}, "
                    f"source_type={self.source_type}"
                ),
            },
            "captures": [capture],
            "annotations": [],
            "fissure": {
                "operation_id": self._operation_id(),
                "node_uid": self.node_uid,
                "source_id": self.source_id,
                "source_type": self.source_type,
                "source_file": source_path,
                "category": self.category,
                "method": self.method,
                "data_type": self.data_type,
                "sample_rate": self.sample_rate,
                "frequency_mhz": self.tuned_frequency,
                "file_index": file_index,
            },
        }

        with open(meta_path, "w", encoding="utf-8") as handle:
            json.dump(meta, handle, indent=2, sort_keys=True)

        row["sigmf_meta_name"] = os.path.basename(meta_path)
        row["sigmf_meta_path"] = meta_path
        row["sigmf_meta_relative_path"] = os.path.relpath(meta_path, FISSURE_ROOT)

        return meta_path

    def _build_payload(
        self,
        output_dir: str,
        rows: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        uses_sigmf = _conditioner_output_uses_sigmf(self.output_format)
        uses_zip = _conditioner_output_uses_zip(self.output_format)

        if uses_sigmf and uses_zip:
            artifact_format = "sigmf_zip_bundle"
        elif uses_sigmf:
            artifact_format = "sigmf_files"
        elif uses_zip:
            artifact_format = "raw_iq_zip_bundle"
        else:
            artifact_format = "local_iq_files"

        return {
            "kind": "artifact",
            "event_type": "signal_conditioning_artifact",
            "node_uid": self.node_uid,
            "source_id": self.source_id,
            "operation_id": self._operation_id(),
            "artifact_id": "",
            "artifact_type": "iq_file_conditioning",
            "artifact_format": artifact_format,
            "name": "Local Signal Conditioning",
            "description": self.description,
            "source_type": self.source_type,
            "category": self.category,
            "method": self.method,
            "frequency_mhz": self.tuned_frequency,
            "sample_rate": self.sample_rate,
            "data_type": self.data_type,
            "output_mode": self.output_mode,
            "output_format": self.output_format,
            "prefix": self.prefix,
            "check_saturation": bool(self.check_saturation),
            "saturation_check": "full" if self.check_saturation else "none",
            "output_dir": output_dir,
            "files_dir": output_dir,
            "file_count": len(rows),
            "sigmf_enabled": uses_sigmf,
            "zip_enabled": uses_zip,
            "files": rows,
            "created_at": datetime.datetime.utcnow().isoformat("T") + "Z",
        }

    def _create_zip_bundle(
        self,
        output_dir: str,
        rows: List[Dict[str, Any]],
        metadata_path: str,
    ) -> str:
        zip_name = self._zip_bundle_name()
        zip_path = os.path.join(output_dir, zip_name)

        if os.path.exists(zip_path):
            os.remove(zip_path)

        with zipfile.ZipFile(
            zip_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as zip_handle:
            for row in rows:
                path = str(row.get("path", "") or "")
                name = str(row.get("name", "") or "")

                if path and name and os.path.isfile(path):
                    zip_handle.write(path, arcname=os.path.join("files", name))

                sigmf_meta_path = str(row.get("sigmf_meta_path", "") or "")
                sigmf_meta_name = str(row.get("sigmf_meta_name", "") or "")

                if sigmf_meta_path and sigmf_meta_name and os.path.isfile(sigmf_meta_path):
                    zip_handle.write(
                        sigmf_meta_path,
                        arcname=os.path.join("files", sigmf_meta_name),
                    )

            if metadata_path and os.path.isfile(metadata_path):
                zip_handle.write(
                    metadata_path,
                    arcname=self._metadata_name(),
                )

        return zip_path

    async def _create_artifact(self, payload: Dict[str, Any]) -> str:
        """
        Register file/folder Conditioner output with the Sensor Node
        ArtifactManager.

        The SensorNode wraps ArtifactManager.create_artifact() and sends
        updateArtifact to HIPRFISR after creation.
        """
        self.artifact_payload = payload

        artifact_manager = getattr(self, "artifact_manager", None)

        if artifact_manager is None:
            self.logger.info(
                "No artifact_manager available; skipping artifact registration."
            )
            self.artifact_id = ""
            self.artifact_payload["artifact_id"] = ""
            return ""

        operation_id = self._operation_id()
        source_id = str(
            payload.get("source_id", "")
            or self.source_id
            or self.node_uid
            or "sensor_node"
        ).strip()

        bundle_path = str(payload.get("bundle_path", "") or "").strip()

        if bundle_path and os.path.isfile(bundle_path):
            artifact = artifact_manager.create_artifact(
                source_id=source_id,
                operation_id=operation_id,
                file_path=bundle_path,
                name="Conditioner output bundle",
                artifact_type="application/zip",
                metadata=payload,
            )

            artifact_id = str(getattr(artifact, "id", artifact) if artifact else "")
            self.artifact_id = artifact_id
            self.artifact_payload["artifact_id"] = artifact_id

            self.logger.info(
                "Registered Conditioner file artifact with ArtifactManager: "
                "artifact_id=%s source_id=%s operation_id=%s file_path=%s",
                artifact_id,
                source_id,
                operation_id,
                bundle_path,
            )

            return artifact_id

        files = payload.get("files") or []

        for file_record in files:
            if not isinstance(file_record, dict):
                continue

            file_path = str(file_record.get("path", "") or "").strip()

            if not file_path or not os.path.isfile(file_path):
                continue

            artifact = artifact_manager.create_artifact(
                source_id=source_id,
                operation_id=operation_id,
                file_path=file_path,
                name="Conditioner output file",
                artifact_type="application/octet-stream",
                metadata=payload,
            )

            artifact_id = str(getattr(artifact, "id", artifact) if artifact else "")
            self.artifact_id = artifact_id
            self.artifact_payload["artifact_id"] = artifact_id

            self.logger.info(
                "Registered Conditioner file artifact with ArtifactManager: "
                "artifact_id=%s source_id=%s operation_id=%s file_path=%s",
                artifact_id,
                source_id,
                operation_id,
                file_path,
            )

            return artifact_id

        self.logger.warning(
            "No Conditioner file output was available for artifact registration."
        )

        self.artifact_id = ""
        self.artifact_payload["artifact_id"] = ""
        return ""

    @staticmethod
    def _normalize_output_mode(output_mode: str) -> str:
        """
        Normalize Conditioner output modes.

        'Local Folder + Artifact' is intentionally collapsed to 'Artifact'
        because artifact output must be managed exclusively under the FISSURE
        artifact directory.
        """
        text = str(output_mode or "").strip()

        aliases = {
            "Local Folder + Artifact": "Artifact",
            "local_folder_artifact": "Artifact",
            "artifact": "Artifact",
            "local": "Local Folder",
            "local_folder": "Local Folder",
        }

        text = aliases.get(text, text)

        if text not in {"Local Folder", "Artifact"}:
            return "Local Folder"

        return text


    @staticmethod
    def _normalize_output_format(output_format: str) -> str:
        text = str(output_format or "").strip()
        normalized = text.lower().replace("_", " ").replace("-", " ")
        normalized = " ".join(normalized.split())

        if "sigmf" in normalized and ("zip" in normalized or "bundle" in normalized):
            return "SigMF Zip Bundle"

        if "raw" in normalized and ("zip" in normalized or "bundle" in normalized):
            return "Raw IQ Zip Bundle"

        if normalized in {"zip", "zip bundle", "bundle"}:
            return "Raw IQ Zip Bundle"

        if "sigmf" in normalized:
            return "SigMF Files"

        if "raw" in normalized or "iq" in normalized:
            return "Raw IQ Files"

        allowed = {
            "Raw IQ Files",
            "SigMF Files",
            "Raw IQ Zip Bundle",
            "SigMF Zip Bundle",
        }

        if text in allowed:
            return text

        return "Raw IQ Files"


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test

    run_test(OperationMain, {}, {})