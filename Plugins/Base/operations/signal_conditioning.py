#!/usr/bin/env python3
"""
Signal Conditioning Operation

Hardware-source TSI Conditioner operation.

Dashboard Frequencies source:
    - Uses frequency_plan rows from the Conditioner frequency table.
    - Treats max_files as max files per frequency row.
    - Treats dwell_s as dwell time per frequency row.

Tactical/direct action:
    - Can pass frequency_mhz and optional dwell_s.
    - The operation converts that into a one-row frequency_plan.

This operation intentionally writes both:
    signal_conditioning_artifact.json
    signal_conditioning_file_artifact.json

The second name keeps the current Dashboard Conditioner results poller compatible
with the file-source Conditioner action.
"""

import os
import sys
import time
import json
import shutil
import signal
import datetime
import hashlib
import asyncio
import zipfile
import logging
import inspect
from typing import Any, Callable, Dict, List, Optional


PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

try:
    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT, get_library_version
except ImportError:
    if FISSURE_REPO_ROOT not in sys.path:
        sys.path.insert(0, FISSURE_REPO_ROOT)
    if PLUGIN_ROOT not in sys.path:
        sys.path.insert(0, PLUGIN_ROOT)

    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT, get_library_version


def list_files(path: str) -> Dict[str, os.stat_result]:
    """
    Return {filename: os.stat_result} for regular files under path.
    """
    out: Dict[str, os.stat_result] = {}

    try:
        for filename in os.listdir(path):
            full_path = os.path.join(path, filename)
            if os.path.isfile(full_path):
                out[filename] = os.stat(full_path)
    except FileNotFoundError:
        return {}

    return out


def is_file_stable(
    prev: os.stat_result,
    cur: os.stat_result,
    settle_seconds: float,
) -> bool:
    """
    A file is stable when size/mtime are unchanged and the file has not been
    modified for settle_seconds.
    """
    return (
        prev.st_size == cur.st_size
        and prev.st_mtime == cur.st_mtime
        and (time.time() - cur.st_mtime) >= settle_seconds
    )


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    """
    Compute a SHA-256 checksum for a file.
    """
    digest = hashlib.sha256()

    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def sha512_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    """
    Compute a SHA-512 checksum for SigMF metadata.
    """
    digest = hashlib.sha512()

    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def conditioner_output_uses_sigmf(output_format: str) -> bool:
    """Return True when the selected Conditioner output should be SigMF."""
    text = str(output_format or "").strip().lower().replace("_", " ")
    return "sigmf" in text


def conditioner_output_uses_zip(output_format: str) -> bool:
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


def sigmf_datatype_for_data_type(data_type: str) -> str:
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


async def maybe_await(value: Any) -> Any:
    """
    Await coroutine-like values while allowing normal synchronous returns.
    """
    if inspect.isawaitable(value):
        return await value
    return value


async def invoke_callback(
    callback: Optional[Callable],
    *args: Any,
    timeout: float = 2.0,
    **kwargs: Any,
) -> Any:
    """
    Invoke a callback with a bounded await when possible.
    """
    if not callback:
        return None

    result = callback(*args, **kwargs)

    if inspect.isawaitable(result):
        return await asyncio.wait_for(result, timeout=timeout)

    return result


async def cancel_task(
    task: Optional[asyncio.Task],
    logger: logging.Logger,
    name: str,
) -> None:
    """
    Cancel and await a task cleanly.
    """
    if task is None or task.done():
        return

    task.cancel()

    try:
        await task
    except asyncio.CancelledError:
        pass
    except Exception:
        logger.exception("%s failed during cancellation", name)


async def wait_for_files_to_settle(
    paths: List[str],
    settle_seconds: float,
    max_wait: Optional[float],
    poll: float,
    logger: Optional[logging.Logger] = None,
    stop_check: Optional[Callable[[], bool]] = None,
) -> Dict[str, os.stat_result]:
    """
    Wait until all provided file paths are stable, or return best-effort stats
    when stop/max_wait ends the settle window.
    """
    start = time.time()
    last_stats: Dict[str, os.stat_result] = {}
    stable_since: Dict[str, Optional[float]] = {path: None for path in paths}
    done = set()

    while len(done) < len(paths):
        now = time.time()

        if stop_check and stop_check():
            if logger:
                logger.info("Stop requested during settle; exiting settle early.")
            break

        if max_wait is not None and (now - start) > max_wait:
            if logger:
                logger.warning("Settle max_wait exceeded; returning best-effort stats.")
            break

        for path in paths:
            if path in done:
                continue

            try:
                stat = os.stat(path)
            except FileNotFoundError:
                stable_since[path] = None
                continue

            prev = last_stats.get(path)

            if prev is not None and is_file_stable(prev, stat, settle_seconds):
                if stable_since[path] is None:
                    stable_since[path] = now

                if (now - stable_since[path]) >= settle_seconds:
                    done.add(path)
            else:
                stable_since[path] = None

            last_stats[path] = stat

        await asyncio.sleep(poll)

    return last_stats


class OperationMain(Operation):
    """
    Signal Conditioning Operation.

    Runs the normal_decay hardware-source GNU Radio helper for one or more
    frequency rows.
    """

    def __init__(
        self,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback=None,
        tak_cot_callback=None,
        status_callback=None,
        artifact_manager=None,
        source_id: Optional[str] = None,
        operation_id: str = "",
        source_type: str = "frequencies",
        category: str = "energy",
        method: str = "normal_decay",
        frequency_plan: Optional[List[Dict[str, Any]]] = None,
        frequency_mhz: Optional[float] = None,
        dwell_s: Any = 10.0,
        max_files: Any = 5,
        min_samples: Any = 4096,
        sample_rate: Any = "1e6",
        threshold: Any = "0.004",
        decay: Any = "0.0002",
        channel: str = "A:A",
        ip_address: str = "",
        serial: str = "False",
        antenna: str = "TX/RX",
        gain: Any = "60",
        output_directory: str = "",
        output_mode: str = "Local Folder",
        output_format: str = "Raw IQ Files",
        check_saturation: Any = False,
        saturation_check: str = "",
        prefix: str = "output_",
        data_type: str = "Complex Float 32",
        description: str = "Signal conditioning capture",
        emit_alert: Any = False,
        emit_tak: Any = False,
        **kwargs,
    ):
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            status_callback=status_callback,
            artifact_manager=artifact_manager,
        )

        self.source_id = source_id or node_uid or "sensor_node"
        self.source_type = str(source_type or "frequencies").strip().lower()
        self.category = str(category or "energy").strip()
        self.method = (
            str(method or "normal_decay")
            .strip()
            .lower()
            .replace(" ", "_")
            .replace("-", "_")
        )

        self.frequency_mhz = self._safe_float_or_none(frequency_mhz)
        self.dwell_s = max(0.1, self._safe_float(dwell_s, 10.0))
        self.max_files = max(1, self._safe_int(max_files, 5))
        self.min_samples = max(1, self._safe_int(min_samples, 4096))

        self.sample_rate = str(sample_rate)
        self.threshold = str(threshold)
        self.decay = str(decay)
        self.channel = str(channel or "A:A")
        self.ip_address = str(ip_address or "")
        self.serial = str(serial or "False")
        self.antenna = str(antenna or "TX/RX")
        self.gain = str(gain)

        self.output_directory = str(output_directory or "").strip()
        self.output_mode = str(output_mode or "Local Folder").strip()
        self.output_format = str(output_format or "Raw IQ Files").strip()
        self.check_saturation = self._safe_bool(check_saturation, False)
        saturation_check_text = str(saturation_check or "").strip().lower()
        if saturation_check_text in {"full", "yes", "true", "1", "on"}:
            self.check_saturation = True
        self.prefix = str(prefix or "output_")
        self.data_type = str(data_type or "Complex Float 32").strip()
        self.description = str(description or "Signal conditioning capture").strip()
        self.emit_alert = self._safe_bool(emit_alert, False)
        self.emit_tak = self._safe_bool(emit_tak, False)

        self.frequency_plan = self._normalize_frequency_plan(
            frequency_plan=frequency_plan,
            frequency_mhz=self.frequency_mhz,
            dwell_s=self.dwell_s,
        )

        self.artifact_id = ""
        self.artifact_payload: Dict[str, Any] = {}
        self.selected_files: List[str] = []
        self.file_records: List[Dict[str, Any]] = []
        self.stop_reasons: List[str] = []

        if operation_id:
            self.opid = str(operation_id)

    def _safe_bool(self, value: Any, default: bool = False) -> bool:
        if isinstance(value, bool):
            return value

        if value is None:
            return default

        if isinstance(value, (int, float)):
            return bool(value)

        text = str(value).strip().lower()

        if text in {"true", "1", "yes", "y", "on", "enabled"}:
            return True

        if text in {"false", "0", "no", "n", "off", "disabled"}:
            return False

        return default

    def _safe_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(float(value))
        except Exception:
            return int(default)

    def _safe_float(self, value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except Exception:
            return float(default)

    def _safe_float_or_none(self, value: Any) -> Optional[float]:
        try:
            if value is None:
                return None

            text = str(value).strip()
            if text == "":
                return None

            return float(text)
        except Exception:
            return None

    def _normalize_frequency_plan(
        self,
        frequency_plan: Optional[List[Dict[str, Any]]],
        frequency_mhz: Optional[Any],
        dwell_s: Any = 10.0,
    ) -> List[Dict[str, Any]]:
        """
        Prefer Dashboard frequency_plan rows. Fall back to frequency_mhz for
        Tactical/direct action usage.
        """
        plan: List[Dict[str, Any]] = []

        if isinstance(frequency_plan, list):
            for index, row in enumerate(frequency_plan):
                if not isinstance(row, dict):
                    continue

                try:
                    freq = float(row.get("frequency_mhz"))
                except Exception:
                    continue

                try:
                    dwell = float(row.get("dwell_s", dwell_s))
                except Exception:
                    dwell = 10.0

                plan.append(
                    {
                        "frequency_mhz": freq,
                        "dwell_s": max(0.1, dwell),
                        "row": row.get("row", index),
                        "power_db": row.get("power_db", ""),
                        "time": row.get("time", ""),
                    }
                )

        if not plan and frequency_mhz is not None:
            try:
                freq = float(frequency_mhz)
                dwell = float(dwell_s)

                plan.append(
                    {
                        "frequency_mhz": freq,
                        "dwell_s": max(0.1, dwell),
                        "row": 0,
                        "power_db": "",
                        "time": "",
                    }
                )
            except Exception:
                pass

        return plan

    async def _set_status(self, status: str) -> None:
        if not getattr(self, "status_callback", None):
            return

        try:
            await invoke_callback(self.status_callback, status, timeout=2.0)
        except Exception:
            self.logger.exception("status_callback failed")

    async def _publish_alert(
        self,
        payload: Dict[str, Any],
        enabled: bool = False,
    ) -> None:
        """
        Optionally publish a normal alert message.

        Disabled by default because Conditioner output is primarily consumed as
        artifact metadata by the Dashboard poller.
        """
        if not enabled:
            return

        if not getattr(self, "alert_callback", None):
            return

        try:
            file_count = int(payload.get("file_count", 0) or 0)
            frequency_mhz = payload.get("frequency_mhz", "")

            if frequency_mhz != "":
                message = (
                    f"Signal conditioning complete: "
                    f"{file_count} file(s), {frequency_mhz} MHz"
                )
            else:
                message = (
                    f"Signal conditioning complete: "
                    f"{file_count} file(s)"
                )

            await invoke_callback(
                self.alert_callback,
                self.node_uid,
                getattr(self, "opid", ""),
                message,
                self.logger,
                timeout=2.0,
            )

        except Exception:
            self.logger.exception("alert_callback failed")

    async def _publish_tak_cot(
        self,
        payload: Dict[str, Any],
        enabled: bool = False,
    ) -> None:
        """
        Optionally publish a TAK/CoT event.

        Disabled by default. This is not needed for Conditioner table
        population.
        """
        if not enabled:
            return

        if not getattr(self, "tak_cot_callback", None):
            return

        try:
            uid = (
                str(payload.get("uid", "") or "").strip()
                or f"conditioner-{getattr(self, 'opid', '')}"
            )

            file_count = int(payload.get("file_count", 0) or 0)
            frequency_mhz = payload.get("frequency_mhz", "")

            tak_msg = {
                "msg_type": "event",
                "uid": uid,
                "remarks": json.dumps(payload),
                "lat": True,
                "lon": True,
                "alt": True,
                "time": True,
                "tak_icon": "b-t-f-r",
                "opid": getattr(self, "opid", ""),
                "node_uid": self.node_uid,
                "alert_kind": "signal_conditioning_artifact",
                "alert_summary": (
                    f"Signal conditioning complete: {file_count} file(s)"
                ),
                "frequency_mhz": frequency_mhz,
                "file_count": file_count,
            }

            await invoke_callback(
                self.tak_cot_callback,
                tak_msg,
                timeout=2.0,
            )

        except Exception:
            self.logger.exception("tak_cot_callback failed")

    async def _create_artifact(self, payload: Dict[str, Any]) -> str:
        """
        Register hardware-source Conditioner output with the Sensor Node
        ArtifactManager.

        The SensorNode wraps ArtifactManager.create_artifact() and sends
        updateArtifact to HIPRFISR after creation. This is the canonical
        action-artifact reporting path used by other plugin operations.
        """
        self.artifact_payload = payload

        artifact_manager = getattr(self, "artifact_manager", None)

        if artifact_manager is None:
            self.logger.info(
                "No artifact_manager available; skipping artifact registration."
            )
            self.artifact_id = str(getattr(self, "opid", "") or "")
            self.artifact_payload["artifact_id"] = self.artifact_id
            return self.artifact_id

        operation_id = str(
            payload.get("operation_id", "")
            or getattr(self, "opid", "")
            or ""
        ).strip()

        source_id = str(
            payload.get("source_id", "")
            or self.source_id
            or self.node_uid
            or "sensor_node"
        ).strip()

        name = str(
            payload.get("name", "")
            or "Signal Conditioning IQ Capture"
        ).strip()

        bundle_path = str(payload.get("bundle_path", "") or "").strip()

        if bundle_path and os.path.isfile(bundle_path):
            artifact = artifact_manager.create_artifact(
                source_id=source_id,
                operation_id=operation_id,
                file_path=bundle_path,
                name=name,
                artifact_type="application/zip",
                metadata=payload,
            )

            artifact_id = str(getattr(artifact, "id", artifact) if artifact else "")
            self.artifact_id = artifact_id or operation_id
            self.artifact_payload["artifact_id"] = self.artifact_id

            self.logger.info(
                "Registered Conditioner artifact with ArtifactManager: "
                "artifact_id=%s source_id=%s operation_id=%s file_path=%s",
                self.artifact_id,
                source_id,
                operation_id,
                bundle_path,
            )

            return self.artifact_id

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
                name=name,
                artifact_type="application/octet-stream",
                metadata=payload,
            )

            artifact_id = str(getattr(artifact, "id", artifact) if artifact else "")
            self.artifact_id = artifact_id or operation_id
            self.artifact_payload["artifact_id"] = self.artifact_id

            self.logger.info(
                "Registered Conditioner artifact with ArtifactManager: "
                "artifact_id=%s source_id=%s operation_id=%s file_path=%s",
                self.artifact_id,
                source_id,
                operation_id,
                file_path,
            )

            return self.artifact_id

        self.logger.warning(
            "No Conditioner output file was available for artifact registration."
        )

        self.artifact_id = operation_id
        self.artifact_payload["artifact_id"] = self.artifact_id
        return self.artifact_id

    def _output_dir(self) -> str:
        """
        Returns the directory where Conditioner output files are written.

        Local Folder:
            use explicit output_directory.

        Artifact:
            ignore output_directory and always use managed artifact storage:
            FISSURE_ROOT/artifacts/<operation_id>/files.
        """
        output_mode = str(self.output_mode or "").strip()

        if output_mode == "Local Folder" and self.output_directory:
            return os.path.abspath(self.output_directory)

        return os.path.join(
            FISSURE_ROOT,
            "artifacts",
            str(getattr(self, "opid", "") or "signal_conditioning"),
            "files",
        )

    def _normal_decay_path(self) -> str:
        version = get_library_version() or "maint-3.10"

        candidates = [
            os.path.abspath(
                os.path.join(
                    PLUGIN_ROOT,
                    "flow_graphs",
                    "conditioner_flow_graphs",
                    version,
                    "hardware_source",
                    "b2x0",
                    "burst_tagger",
                    "normal_decay.py",
                )
            ),
            os.path.abspath(
                os.path.join(
                    PLUGIN_ROOT,
                    "flow_graphs",
                    "conditioner_flow_graphs",
                    "maint-3.8",
                    "hardware_source",
                    "b2x0",
                    "burst_tagger",
                    "normal_decay.py",
                )
            ),
            os.path.abspath(
                os.path.join(
                    PLUGIN_ROOT,
                    "flow_graphs",
                    "conditioner_flow_graphs",
                    "maint-3.10",
                    "hardware_source",
                    "b2x0",
                    "burst_tagger",
                    "normal_decay.py",
                )
            ),
            os.path.abspath(
                os.path.join(
                    PLUGIN_ROOT,
                    "scripts",
                    "promote_to_soi_lib",
                    "normal_decay.py",
                )
            ),
        ]

        checked: List[str] = []

        for path in candidates:
            if path in checked:
                continue

            checked.append(path)

            if os.path.isfile(path):
                self.logger.info("Using Conditioner hardware flow graph: %s", path)
                return path

        raise FileNotFoundError(
            "Conditioner hardware flow graph not found. Tried:\n"
            + "\n".join(checked)
        )

    def _build_command(
        self,
        python_path: str,
        flowgraph_path: str,
        frequency_mhz: float,
        max_files_for_frequency: int,
    ) -> List[str]:
        """
        Ask the flow graph for one extra burst. The newest file is the most
        likely partial tagged_file_sink output when the flow graph is stopped,
        so the operation keeps max_files_for_frequency valid files and drops
        the extra/newest candidate.
        """
        requested_bursts = max_files_for_frequency + 1

        return [
            python_path,
            "-u",
            flowgraph_path,
            "--sample-rate", str(self.sample_rate),
            "--threshold", str(self.threshold),
            "--decay", str(self.decay),
            "--max-bursts", str(requested_bursts),
            "--rx-freq", str(frequency_mhz),
            "--channel", str(self.channel),
            "--ip-address", str(self.ip_address),
            "--serial", str(self.serial),
            "--antenna", str(self.antenna),
            "--gain", str(self.gain),
        ]

    def _samples_from_size(self, size_bytes: int) -> int:
        data_type = str(self.data_type or "").strip()

        bytes_per_sample = {
            "Complex Float 64": 16,
            "Complex Float 32": 8,
            "Float/Float 32": 4,
            "Short/Int 16": 2,
            "Int/Int 32": 4,
            "Byte/Int 8": 1,
            "Complex Int 16": 4,
            "Complex Int 8": 2,
            "Complex Int 64": 16,
        }.get(data_type, 8)

        return int(size_bytes // max(1, bytes_per_sample))

    def _delete_file_quietly(self, path: str, reason: str = "") -> None:
        try:
            if os.path.isfile(path):
                os.remove(path)
                self.logger.info(
                    "Deleted Conditioner output file: %s reason=%s",
                    path,
                    reason,
                )
        except Exception:
            self.logger.exception(
                "Failed deleting Conditioner output file: %s",
                path,
            )

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

    def _conditioner_final_filename(
        self,
        frequency_mhz: float,
        frequency_index: int,
        file_index: int,
        extension: str,
    ) -> str:
        """
        Builds the final user-facing Conditioner output filename for
        hardware-source captures.
        """
        prefix = str(getattr(self, "prefix", "") or "").strip()
        prefix = self._safe_filename_component(prefix, default="output_")

        if prefix and not prefix.endswith("_"):
            prefix = f"{prefix}_"

        try:
            freq_text = f"{float(frequency_mhz):g}MHz"
        except Exception:
            freq_text = "unknownMHz"

        freq_text = self._safe_filename_component(
            freq_text,
            default="unknownMHz",
        )

        try:
            frequency_index = int(frequency_index)
        except Exception:
            frequency_index = 1

        try:
            file_index = int(file_index)
        except Exception:
            file_index = 1

        extension = str(extension or ".dat").strip()

        if not extension.startswith("."):
            extension = f".{extension}"

        return (
            f"{prefix}{freq_text}_"
            f"{frequency_index:02d}_{file_index:03d}{extension}"
        )

    def _rename_conditioner_capture(
        self,
        path: str,
        frequency_mhz: float,
        frequency_index: int,
        file_index: int,
        extension: str,
    ) -> str:
        """
        Rename a GNU Radio tagged_file_sink output into the Dashboard-selected
        Conditioner naming scheme.

        Applies to both Raw IQ and SigMF data outputs.
        """
        if not path:
            return path

        if not os.path.isfile(path):
            return path

        directory = os.path.dirname(path)

        final_name = self._conditioner_final_filename(
            frequency_mhz=frequency_mhz,
            frequency_index=frequency_index,
            file_index=file_index,
            extension=extension,
        )

        candidate = os.path.join(
            directory,
            final_name,
        )

        if os.path.abspath(candidate) == os.path.abspath(path):
            return path

        if os.path.exists(candidate):
            stem, ext = os.path.splitext(final_name)
            opid = self._safe_filename_component(
                getattr(self, "opid", "") or str(int(time.time())),
                default=str(int(time.time())),
            )

            candidate = os.path.join(
                directory,
                f"{stem}_{opid}{ext}",
            )

        os.replace(path, candidate)

        self.logger.info(
            "Renamed Conditioner output: %s -> %s",
            path,
            candidate,
        )

        return candidate

    def _sigmf_data_path_for_capture(
        self,
        path: str,
        frequency_mhz: float,
        frequency_index: int,
        file_index: int,
    ) -> str:
        """
        Rename a captured GNU Radio output file to the final SigMF data name.
        """
        return self._rename_conditioner_capture(
            path=path,
            frequency_mhz=frequency_mhz,
            frequency_index=frequency_index,
            file_index=file_index,
            extension=".sigmf-data",
        )

    def _write_sigmf_meta_for_record(
        self,
        record: Dict[str, Any],
        frequency_mhz: float,
        dwell_s: float,
        plan_row: Dict[str, Any],
        file_index: int,
    ) -> str:
        """
        Writes a SigMF sidecar for one captured Conditioner data file.
        """
        data_path = str(record.get("path", "") or "")

        if not data_path:
            return ""

        if data_path.endswith(".sigmf-data"):
            meta_path = data_path.replace(".sigmf-data", ".sigmf-meta")
        else:
            meta_path = data_path + ".sigmf-meta"

        checksum = ""
        try:
            checksum = sha512_file(data_path)
        except Exception:
            self.logger.exception("Failed to calculate SigMF sha512 for %s", data_path)

        capture = {
            "core:sample_start": 0,
            "core:datetime": datetime.datetime.utcnow().isoformat("T") + "Z",
            "core:frequency": float(frequency_mhz) * 1e6,
        }

        meta = {
            "global": {
                "core:datatype": sigmf_datatype_for_data_type(self.data_type),
                "core:sample_rate": float(self.sample_rate),
                "core:version": "1.0.0",
                "core:dataset": os.path.basename(data_path),
                "core:sha512": checksum,
                "core:description": (
                    f"FISSURE Conditioner hardware capture. "
                    f"category={self.category}, method={self.method}, "
                    f"source_type={self.source_type}"
                ),
            },
            "captures": [capture],
            "annotations": [],
            "fissure": {
                "operation_id": getattr(self, "opid", ""),
                "node_uid": self.node_uid,
                "source_id": self.source_id,
                "source_type": self.source_type,
                "category": self.category,
                "method": self.method,
                "data_type": self.data_type,
                "sample_rate": self.sample_rate,
                "frequency_mhz": frequency_mhz,
                "dwell_s": dwell_s,
                "frequency_row": plan_row.get("row", file_index - 1),
                "file_index": file_index,
            },
        }

        with open(meta_path, "w", encoding="utf-8") as handle:
            json.dump(meta, handle, indent=2, sort_keys=True)

        record["sigmf_meta_name"] = os.path.basename(meta_path)
        record["sigmf_meta_path"] = meta_path
        record["sigmf_meta_relative_path"] = os.path.relpath(meta_path, FISSURE_ROOT)

        return meta_path

    async def _terminate_flowgraph_process(
        self,
        proc: Optional[asyncio.subprocess.Process],
        reason: str = "",
    ) -> int:
        """
        Stop the GNU Radio helper and its process group.

        This is stronger than killing only the direct child and prevents B2x0
        handles from surviving until the Dashboard process exits.
        """
        if proc is None:
            return -1

        if proc.returncode is not None:
            return proc.returncode

        pid = proc.pid

        try:
            pgid = os.getpgid(pid)
        except Exception:
            pgid = None

        self.logger.info(
            "Stopping signal conditioning flow graph pid=%s pgid=%s reason=%s",
            pid,
            pgid,
            reason,
        )

        for sig, label, timeout_s in (
            (signal.SIGINT, "SIGINT", 4.0),
            (signal.SIGTERM, "SIGTERM", 3.0),
            (signal.SIGKILL, "SIGKILL", 3.0),
        ):
            if proc.returncode is not None:
                return proc.returncode

            try:
                if pgid is not None:
                    os.killpg(pgid, sig)
                else:
                    proc.send_signal(sig)

                await asyncio.wait_for(proc.wait(), timeout=timeout_s)
                return proc.returncode if proc.returncode is not None else 0

            except asyncio.TimeoutError:
                self.logger.warning(
                    "Flow graph did not exit after %s within %.1fs.",
                    label,
                    timeout_s,
                )

            except ProcessLookupError:
                try:
                    await proc.wait()
                except Exception:
                    pass
                return proc.returncode if proc.returncode is not None else 0

            except Exception:
                self.logger.exception("Failed sending %s to flow graph.", label)

        return proc.returncode if proc.returncode is not None else -1

    def _select_output_files(
        self,
        output_dir: str,
        new_items: List[tuple],
        max_files_for_frequency: int,
    ) -> List[str]:
        """
        Select up to max_files_for_frequency valid files.

        Rules:
            - Sort by mtime/name.
            - If extra files exist, delete the newest/extra files.
            - If the newest file is much smaller than the others, delete it as
              likely partial even when there is no extra file.
        """
        if not new_items:
            return []

        ordered = sorted(new_items, key=lambda kv: (kv[1].st_mtime, kv[0]))

        keep_items = ordered
        drop_items: List[tuple] = []

        if len(ordered) > max_files_for_frequency:
            keep_items = ordered[:max_files_for_frequency]
            drop_items.extend(ordered[max_files_for_frequency:])

        elif len(ordered) >= 2:
            previous_sizes = [stat.st_size for _, stat in ordered[:-1] if stat.st_size > 0]
            newest_name, newest_stat = ordered[-1]

            if previous_sizes:
                sorted_sizes = sorted(previous_sizes)
                median_size = sorted_sizes[len(sorted_sizes) // 2]

                if median_size > 0 and newest_stat.st_size < (0.25 * median_size):
                    keep_items = ordered[:-1]
                    drop_items.append((newest_name, newest_stat))

        for filename, _ in drop_items:
            self._delete_file_quietly(
                os.path.join(output_dir, filename),
                reason="partial_or_extra",
            )

        return [filename for filename, _ in keep_items[:max_files_for_frequency]]

    async def _capture_one_frequency(
        self,
        output_dir: str,
        flowgraph_path: str,
        python_path: str,
        plan_row: Dict[str, Any],
        index: int,
        total: int,
    ) -> List[Dict[str, Any]]:
        frequency_mhz = float(plan_row["frequency_mhz"])
        dwell_s = max(
            0.1,
            self._safe_float(
                plan_row.get("dwell_s", self.dwell_s),
                self.dwell_s,
            ),
        )
        max_files_for_frequency = self.max_files
        requested_files_for_frequency = max_files_for_frequency + 1

        before = list_files(output_dir)

        settle_poll = 0.10
        settle_seconds = 1.0
        settle_max_wait = 5.0

        await self._set_status(
            f"Running: {frequency_mhz:.6f} MHz ({index}/{total}), dwell {dwell_s:g}s"
        )

        cmd = self._build_command(
            python_path=python_path,
            flowgraph_path=flowgraph_path,
            frequency_mhz=frequency_mhz,
            max_files_for_frequency=max_files_for_frequency,
        )

        self.logger.info("Signal conditioning flow graph argv: %r", cmd)
        self.logger.info("Signal conditioning output directory: %s", output_dir)

        proc: Optional[asyncio.subprocess.Process] = None
        stderr_task: Optional[asyncio.Task] = None
        stderr_lines: List[str] = []
        stop_reason = "unknown"
        child_exited_early = False
        child_returncode = 0

        async def _drain_stderr() -> None:
            if proc is None or proc.stderr is None:
                return

            try:
                while True:
                    line = await proc.stderr.readline()
                    if not line:
                        break

                    text = line.decode(errors="ignore").rstrip()
                    if text:
                        stderr_lines.append(text)
                        self.logger.warning("normal_decay stderr: %s", text)

            except asyncio.CancelledError:
                raise

            except Exception:
                self.logger.exception("Failed while draining normal_decay stderr")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=output_dir,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            stderr_task = asyncio.create_task(_drain_stderr())

            start_time = time.time()
            known_files: Dict[str, os.stat_result] = {}
            cap_selected: Optional[List[str]] = None
            cap_last: Optional[str] = None
            cap_wait_started: Optional[float] = None

            while True:
                now = time.time()

                if getattr(self, "_stop", False):
                    stop_reason = "stop_requested"
                    self.logger.info("Stop requested; exiting frequency capture loop.")
                    break

                if proc.returncode is not None:
                    child_exited_early = True
                    child_returncode = proc.returncode
                    stop_reason = f"process_exited_{proc.returncode}"
                    self.logger.info(
                        "normal_decay exited with return code %s",
                        proc.returncode,
                    )
                    break

                current_all = list_files(output_dir)
                current = {
                    name: stat
                    for name, stat in current_all.items()
                    if name not in before
                }

                if len(current) >= requested_files_for_frequency:
                    if cap_selected is None:
                        ordered = sorted(
                            current.items(),
                            key=lambda kv: (kv[1].st_mtime, kv[0]),
                        )

                        cap_selected = [
                            filename
                            for filename, _ in ordered[:requested_files_for_frequency]
                        ]
                        cap_last = cap_selected[-1] if cap_selected else None
                        cap_wait_started = now

                    if cap_last is None or cap_last not in current:
                        cap_selected = None
                        cap_last = None
                        cap_wait_started = None
                        await asyncio.sleep(settle_poll)
                        continue

                    prev_last = known_files.get(cap_last)
                    last_stat = current[cap_last]

                    if prev_last is not None and is_file_stable(
                        prev_last,
                        last_stat,
                        settle_seconds,
                    ):
                        stop_reason = "max_files_for_frequency_reached"
                        break

                    if (
                        cap_wait_started is not None
                        and (now - cap_wait_started) > settle_max_wait
                    ):
                        stop_reason = "max_files_settle_timeout"
                        break

                if (now - start_time) >= dwell_s:
                    stop_reason = "dwell_complete"
                    break

                for filename, stat in current.items():
                    known_files[filename] = stat

                await asyncio.sleep(settle_poll)

        finally:
            if proc is not None and proc.returncode is None:
                child_returncode = await self._terminate_flowgraph_process(
                    proc,
                    reason=stop_reason,
                )
            elif proc is not None:
                child_returncode = proc.returncode

            await cancel_task(stderr_task, self.logger, "stderr drain task")

            # Give UHD/libusb a moment to release the B2x0 before the next
            # frequency row or next Dashboard/Tactical run tries to claim it.
            await asyncio.sleep(1.0)

        self.stop_reasons.append(
            f"{frequency_mhz:g} MHz: {stop_reason}"
        )

        if getattr(self, "_stop", False):
            return []

        if child_exited_early and child_returncode not in (0, None):
            stderr_tail = "\n".join(stderr_lines[-12:])
            raise RuntimeError(
                "Conditioner hardware flow graph exited with return code "
                f"{child_returncode} at {frequency_mhz:g} MHz.\n"
                f"{stderr_tail}"
            )

        after = list_files(output_dir)
        new_items = [
            (name, stat)
            for name, stat in after.items()
            if name not in before
        ]

        if not new_items:
            self.logger.info("No files captured at %s MHz", frequency_mhz)
            return []

        selected = self._select_output_files(
            output_dir=output_dir,
            new_items=new_items,
            max_files_for_frequency=max_files_for_frequency,
        )

        selected_paths = [
            os.path.join(output_dir, filename)
            for filename in selected
        ]

        final_stats = await wait_for_files_to_settle(
            selected_paths,
            settle_seconds=settle_seconds,
            max_wait=settle_max_wait,
            poll=settle_poll,
            logger=self.logger,
            stop_check=lambda: getattr(self, "_stop", False),
        )

        records: List[Dict[str, Any]] = []
        uses_sigmf = conditioner_output_uses_sigmf(self.output_format)
        data_extension = ".sigmf-data" if uses_sigmf else ".dat"

        for selected_index, filename in enumerate(selected, start=1):
            full_path = os.path.join(output_dir, filename)
            stat = final_stats.get(full_path)

            if stat is None:
                try:
                    stat = os.stat(full_path)
                except FileNotFoundError:
                    self.logger.warning(
                        "Captured file missing unexpectedly: %s",
                        full_path,
                    )
                    continue

            samples = self._samples_from_size(stat.st_size)

            if samples < self.min_samples:
                self.logger.warning(
                    "Dropping tiny Conditioner output file: %s size=%s samples=%s min_samples=%s",
                    full_path,
                    stat.st_size,
                    samples,
                    self.min_samples,
                )
                self._delete_file_quietly(full_path, reason="below_min_samples")
                continue

            try:
                if uses_sigmf:
                    full_path = self._sigmf_data_path_for_capture(
                        path=full_path,
                        frequency_mhz=frequency_mhz,
                        frequency_index=index,
                        file_index=selected_index,
                    )
                else:
                    full_path = self._rename_conditioner_capture(
                        path=full_path,
                        frequency_mhz=frequency_mhz,
                        frequency_index=index,
                        file_index=selected_index,
                        extension=data_extension,
                    )

                filename = os.path.basename(full_path)
                stat = os.stat(full_path)
                samples = self._samples_from_size(stat.st_size)

            except Exception:
                self.logger.exception(
                    "Failed renaming Conditioner output file: %s",
                    full_path,
                )
                continue

            checksum = ""
            try:
                checksum = sha256_file(full_path)
            except Exception:
                self.logger.exception(
                    "Failed to checksum artifact file: %s",
                    full_path,
                )

            record = {
                "name": filename,
                "path": full_path,
                "relative_path": os.path.relpath(full_path, FISSURE_ROOT),
                "size": stat.st_size,
                "samples": samples,
                "mtime": stat.st_mtime,
                "sha256": checksum,
                "frequency_mhz": frequency_mhz,
                "dwell_s": dwell_s,
                "frequency_row": plan_row.get("row", index - 1),
                "power_db": plan_row.get("power_db", ""),
                "time": plan_row.get("time", ""),
                "sample_rate": self.sample_rate,
                "format": self.data_type,
                "data_type": self.data_type,
                "file_type": "sigmf-data" if uses_sigmf else "iq",
                "sigmf": bool(uses_sigmf),
                "source": f"{frequency_mhz:g} MHz",
            }

            if uses_sigmf:
                self._write_sigmf_meta_for_record(
                    record=record,
                    frequency_mhz=frequency_mhz,
                    dwell_s=dwell_s,
                    plan_row=plan_row,
                    file_index=len(records) + 1,
                )

            records.append(record)

        return records

    def _metadata_name(self) -> str:
        operation_id = str(getattr(self, "opid", "") or "conditioner").strip()
        return f"conditioner_{operation_id}.json"

    def _zip_bundle_name(self) -> str:
        operation_id = str(getattr(self, "opid", "") or "conditioner").strip()
        return f"conditioner_{operation_id}.zip"

    def _create_zip_bundle(
        self,
        output_dir: str,
        files: List[Dict[str, Any]],
        metadata_path: str,
    ) -> str:
        """
        Builds a Conditioner zip bundle containing output data files, SigMF
        sidecars when present, and operation metadata.
        """
        zip_name = self._zip_bundle_name()
        zip_path = os.path.join(output_dir, zip_name)

        if os.path.exists(zip_path):
            os.remove(zip_path)

        with zipfile.ZipFile(
            zip_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as zip_handle:
            for row in files:
                path = str(row.get("path", "") or "")
                name = str(row.get("name", "") or "")

                if path and name and os.path.isfile(path):
                    zip_handle.write(
                        path,
                        arcname=os.path.join("files", name),
                    )

                sigmf_meta_path = str(row.get("sigmf_meta_path", "") or "")
                sigmf_meta_name = str(row.get("sigmf_meta_name", "") or "")

                if (
                    sigmf_meta_path
                    and sigmf_meta_name
                    and os.path.isfile(sigmf_meta_path)
                ):
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

    def _build_artifact_payload(
        self,
        files: List[Dict[str, Any]],
        output_dir: str,
    ) -> Dict[str, Any]:
        first_frequency = ""

        if self.frequency_plan:
            first_frequency = self.frequency_plan[0].get("frequency_mhz", "")

        uses_sigmf = conditioner_output_uses_sigmf(self.output_format)
        uses_zip = conditioner_output_uses_zip(self.output_format)

        if uses_sigmf and uses_zip:
            artifact_format = "sigmf_zip_bundle"
        elif uses_sigmf:
            artifact_format = "sigmf_files"
        elif uses_zip:
            artifact_format = "raw_iq_zip_bundle"
        else:
            artifact_format = "burst_iq_files"

        return {
            "kind": "artifact",
            "event_type": "signal_conditioning_artifact",
            "node_uid": self.node_uid,
            "source_id": self.source_id or self.node_uid or "sensor_node",
            "operation_id": getattr(self, "opid", ""),
            "artifact_id": getattr(self, "opid", ""),
            "artifact_type": "iq_capture",
            "artifact_format": artifact_format,
            "name": "Signal Conditioning IQ Capture",
            "description": self.description,
            "source_type": self.source_type,
            "category": self.category,
            "method": self.method,
            "frequency_mhz": first_frequency,
            "frequency_plan": self.frequency_plan,
            "sample_rate": self.sample_rate,
            "data_type": self.data_type,
            "output_dir": output_dir,
            "files_dir": output_dir,
            "output_mode": self.output_mode,
            "output_format": self.output_format,
            "check_saturation": bool(self.check_saturation),
            "saturation_check": "full" if self.check_saturation else "none",
            "prefix": self.prefix,
            "file_count": len(files),
            "sigmf_enabled": uses_sigmf,
            "zip_enabled": uses_zip,
            "files": files,
            "stop_reasons": self.stop_reasons,
            "created_at": datetime.datetime.utcnow().isoformat("T") + "Z",
        }

    async def run(self) -> None:
        output_dir = self._output_dir()
        os.makedirs(output_dir, exist_ok=True)

        try:
            if self.method != "normal_decay":
                raise ValueError(
                    f"Unsupported signal_conditioning method: {self.method}"
                )

            if not self.frequency_plan:
                raise ValueError(
                    "Missing required parameter: frequency_plan or frequency_mhz"
                )

            flowgraph_path = self._normal_decay_path()
            python_path = (
                shutil.which("python3")
                or shutil.which("python")
                or sys.executable
            )

            self.file_records = []

            total = len(self.frequency_plan)

            for index, plan_row in enumerate(self.frequency_plan, start=1):
                if getattr(self, "_stop", False):
                    self.logger.info("Stop requested before next frequency row.")
                    break

                records = await self._capture_one_frequency(
                    output_dir=output_dir,
                    flowgraph_path=flowgraph_path,
                    python_path=python_path,
                    plan_row=plan_row,
                    index=index,
                    total=total,
                )

                self.file_records.extend(records)

            if getattr(self, "_stop", False):
                self.logger.info("Stop requested; skipping metadata publish.")
                return

            if self.check_saturation and self.file_records:
                await self._set_status("Checking Conditioner output saturation")
                saturation_stats = apply_saturation_check_to_records(
                    self.file_records,
                    self.data_type,
                    logger=self.logger,
                )
                self.logger.info(
                    "Conditioner saturation check complete: checked=%s saturated=%s errors=%s",
                    saturation_stats.get("checked", 0),
                    saturation_stats.get("saturated", 0),
                    saturation_stats.get("errors", 0),
                )

            artifact_payload = self._build_artifact_payload(
                files=self.file_records,
                output_dir=output_dir,
            )

            metadata_paths = [
                os.path.join(output_dir, "signal_conditioning_artifact.json"),
                os.path.join(output_dir, "signal_conditioning_file_artifact.json"),
            ]

            operation_metadata_path = os.path.join(
                output_dir,
                self._metadata_name(),
            )

            artifact_payload["metadata_name"] = os.path.basename(operation_metadata_path)
            artifact_payload["metadata_path"] = operation_metadata_path

            all_metadata_paths = [operation_metadata_path] + metadata_paths

            # Write metadata once before building the zip so the bundle contains
            # a useful operation metadata file. It is rewritten below after
            # artifact registration fills in artifact_id.
            for metadata_path in all_metadata_paths:
                try:
                    with open(metadata_path, "w", encoding="utf-8") as handle:
                        json.dump(
                            artifact_payload,
                            handle,
                            indent=2,
                            sort_keys=True,
                        )

                    self.logger.info(
                        "Wrote signal conditioning artifact metadata: %s",
                        metadata_path,
                    )

                except Exception:
                    self.logger.exception(
                        "Failed to write signal conditioning artifact metadata: %s",
                        metadata_path,
                    )

            if conditioner_output_uses_zip(self.output_format):
                zip_path = self._create_zip_bundle(
                    output_dir=output_dir,
                    files=self.file_records,
                    metadata_path=operation_metadata_path,
                )

                artifact_payload["bundle_path"] = zip_path
                artifact_payload["bundle_name"] = os.path.basename(zip_path)
                artifact_payload["bundle_size"] = os.path.getsize(zip_path)
                artifact_payload["bundle_relative_path"] = os.path.relpath(
                    zip_path,
                    FISSURE_ROOT,
                )

                self.logger.info(
                    "Built signal conditioning zip bundle: %s",
                    zip_path,
                )

            artifact_id = await self._create_artifact(artifact_payload)
            artifact_payload["artifact_id"] = artifact_id
            self.artifact_payload = artifact_payload

            # Rewrite final metadata after artifact registration. Rebuild the zip
            # once more so the bundled metadata includes artifact_id.
            for metadata_path in all_metadata_paths:
                try:
                    with open(metadata_path, "w", encoding="utf-8") as handle:
                        json.dump(
                            artifact_payload,
                            handle,
                            indent=2,
                            sort_keys=True,
                        )
                except Exception:
                    self.logger.exception(
                        "Failed to rewrite signal conditioning artifact metadata: %s",
                        metadata_path,
                    )

            if conditioner_output_uses_zip(self.output_format):
                zip_path = self._create_zip_bundle(
                    output_dir=output_dir,
                    files=self.file_records,
                    metadata_path=operation_metadata_path,
                )
                artifact_payload["bundle_path"] = zip_path
                artifact_payload["bundle_name"] = os.path.basename(zip_path)
                artifact_payload["bundle_size"] = os.path.getsize(zip_path)
                artifact_payload["bundle_relative_path"] = os.path.relpath(
                    zip_path,
                    FISSURE_ROOT,
                )

                for metadata_path in all_metadata_paths:
                    try:
                        with open(metadata_path, "w", encoding="utf-8") as handle:
                            json.dump(
                                artifact_payload,
                                handle,
                                indent=2,
                                sort_keys=True,
                            )
                    except Exception:
                        self.logger.exception(
                            "Failed to rewrite final signal conditioning artifact metadata: %s",
                            metadata_path,
                        )

            await self._publish_alert(
                artifact_payload,
                enabled=self.emit_alert,
            )
            await self._publish_tak_cot(
                artifact_payload,
                enabled=self.emit_tak,
            )

            self.logger.info(
                "Signal conditioning capture complete: artifact_id=%s file_count=%s",
                artifact_id,
                artifact_payload.get("file_count", 0),
            )

        finally:
            await self._set_status("Idle")


if __name__ == "__main__":
    async def _main():
        logging.basicConfig(level=logging.INFO)

        op = OperationMain(
            node_uid="test-node",
            logger=logging.getLogger("signal_conditioning_test"),
            frequency_mhz=915.0,
        )
        await op.run()

    asyncio.run(_main())