#! /usr/bin/env python3
"""LFM Beacon Detection

Runs the generated LFM beacon RTL-SDR GNU Radio flow graph as a subprocess,
parses TSI lines from stdout, and emits detection/alert updates through the
operation callbacks.
"""

import asyncio
import inspect
import logging
import os
import shutil
import sys
import time
from typing import Any, Callable, Dict, Optional, Union


PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))

FLOW_GRAPH_BASE_DIR = os.path.join(
    PLUGIN_ROOT,
    "flow_graphs",
    "lfm_beacon_detection_flow_graphs",
)

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

try:
    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT, get_library_version  # noqa: F401 - FISSURE_ROOT retained for compatibility
except ImportError:
    if FISSURE_REPO_ROOT not in sys.path:
        sys.path.insert(0, FISSURE_REPO_ROOT)
    if PLUGIN_ROOT not in sys.path:
        sys.path.insert(0, PLUGIN_ROOT)

    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT, get_library_version  # noqa: F401 - FISSURE_ROOT retained for compatibility


CALLBACK_TIMEOUT_S = 2.0


class OperationMain(Operation):
    """LFM Beacon Detection."""

    def __init__(
        self,
        freq_mhz: float = 433.0,
        min_detection_interval_s: float = 1.0,
        description: str = "LFM beacon detection",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        detection_callback: Union[Callable, None] = None,
        status_callback: Union[Callable, None] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            detection_callback=detection_callback,
            status_callback=status_callback,
        )

        self.parameters: Dict[str, Any] = parameters or {}
        self.freq_mhz = float(freq_mhz)
        self.min_detection_interval_s = float(min_detection_interval_s)
        self.description = description or "LFM beacon detection"
        self.source_id = str(self.parameters.get("source_id") or node_uid or "sensor_node")
        self.emit_alerts = bool(self.parameters.get("emit_alerts", True))

        self.resource_args = {
            "freq_mhz": self.freq_mhz,
        }

        self.logger.info(
            "lfm_beacon_detection init params: "
            f"freq_mhz={self.freq_mhz}, "
            f"min_detection_interval_s={self.min_detection_interval_s}, "
            f"description={self.description}"
        )

    @staticmethod
    def get_resources(freq_mhz: float = 433.0) -> Dict[str, Any]:
        return {}

    def _resolve_flow_graph_path(self) -> str:
        version = get_library_version() or "maint-3.10"

        script_path = os.path.join(
            FLOW_GRAPH_BASE_DIR,
            version,
            "lfm_beacon_rtlsdr.py",
        )

        if not os.path.isfile(script_path):
            raise FileNotFoundError(f"LFM beacon flowgraph not found: {script_path}")

        return script_path

    def _should_stop(self) -> bool:
        if getattr(self, "_stop", False):
            return True

        ev = getattr(self, "stop_event", None)
        if ev is not None:
            try:
                return bool(ev.is_set())
            except Exception:
                pass

        return False

    async def _maybe_await(self, result: Any) -> Any:
        if inspect.isawaitable(result):
            return await result

        return result

    async def _call_with_timeout(self, callback: Callable, *args, **kwargs) -> Any:
        return await asyncio.wait_for(
            self._maybe_await(callback(*args, **kwargs)),
            timeout=CALLBACK_TIMEOUT_S,
        )

    async def _set_status(self, text: str) -> None:
        if not getattr(self, "status_callback", None):
            return

        try:
            await self._call_with_timeout(self.status_callback, text)
        except Exception:
            self.logger.exception("status_callback failed")

    def _apply_parameters_from_runner(self) -> None:
        params = getattr(self, "parameters", {}) or {}
        if not isinstance(params, dict):
            return

        try:
            self.freq_mhz = float(
                params.get(
                    "freq_mhz",
                    params.get("frequency_mhz", self.freq_mhz),
                )
            )
        except Exception:
            self.logger.warning(
                "Invalid freq_mhz/frequency_mhz parameter; using %.6f",
                self.freq_mhz,
            )

        try:
            self.min_detection_interval_s = float(
                params.get(
                    "min_detection_interval_s",
                    params.get("emit_every_s", self.min_detection_interval_s),
                )
            )
        except Exception:
            self.logger.warning(
                "Invalid min_detection_interval_s/emit_every_s parameter; using %.3f",
                self.min_detection_interval_s,
            )

        self.description = (
            str(params.get("description", self.description)).strip()
            or "LFM beacon detection"
        )
        self.source_id = str(
            params.get("source_id") or getattr(self, "node_uid", "") or "sensor_node"
        )
        self.emit_alerts = bool(params.get("emit_alerts", self.emit_alerts))

    async def _drain_stderr(self, process: asyncio.subprocess.Process) -> None:
        if not process.stderr:
            return

        try:
            while True:
                line = await process.stderr.readline()
                if not line:
                    break

                text = line.decode(errors="ignore").rstrip()
                if text:
                    self.logger.debug("LFM beacon flowgraph stderr: %s", text)

        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("Error while draining LFM beacon flowgraph stderr")

    async def _terminate_process(self, process: Optional[asyncio.subprocess.Process]) -> None:
        if process is None:
            return

        if process.returncode is not None:
            return

        self.logger.info("Terminating LFM beacon flowgraph process...")

        try:
            process.terminate()
        except ProcessLookupError:
            return
        except Exception:
            self.logger.exception("Failed to terminate LFM beacon flowgraph process")

        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            self.logger.warning("LFM beacon flowgraph did not terminate, killing...")

            try:
                process.kill()
            except ProcessLookupError:
                return

            await process.wait()

    def _build_detection_payload(
        self,
        *,
        label: str,
        freq_hz: float,
        metric: float,
        det_time: float,
    ) -> Dict[str, Any]:
        timestamp = float(det_time if det_time > 0 else time.time())

        return {
            "kind": "detection",
            "event_type": "detection",
            "detection_kind": "lfm_beacon_detection",
            "node_uid": str(getattr(self, "node_uid", "") or ""),
            "source_id": self.source_id,
            "description": self.description,
            "label": label,
            "frequency_hz": int(freq_hz),
            "frequency_mhz": float(freq_hz) / 1e6,
            "power_dbm": float(metric),
            "metric": float(metric),
            "timestamp": timestamp,
            "detector": "lfm_beacon_detection",
            "opid": self.opid,
            "operation_id": self.opid,
            "flowgraph": "lfm_beacon_rtlsdr",
            "device": "RTL-SDR",
            "configured_frequency_mhz": float(self.freq_mhz),
        }

    async def _emit_detection(self, detection: Dict[str, Any]) -> None:
        if not self.detection_callback:
            self.logger.warning("lfm_beacon_detection has no detection_callback")
            return

        try:
            await self._call_with_timeout(self.detection_callback, detection)
        except Exception:
            self.logger.exception("detection_callback failed for lfm_beacon_detection")

    async def _emit_alert(self, detection: Dict[str, Any]) -> None:
        if not self.emit_alerts or not self.alert_callback:
            return

        text = (
            f"{self.description} @ {float(detection['frequency_mhz']):.3f} MHz, "
            f"metric {float(detection['metric']):.2f}"
        )

        alert_payload = {
            "kind": "alert",
            "event_type": "alert",
            "alert_kind": "lfm_beacon_detection",
            "node_uid": str(getattr(self, "node_uid", "") or ""),
            "source_id": self.source_id,
            "operation_id": self.opid,
            "opid": self.opid,
            "description": self.description,
            "message": text,
            "detection": detection,
            "timestamp": float(detection.get("timestamp") or time.time()),
        }

        try:
            try:
                await self._call_with_timeout(self.alert_callback, alert_payload)
            except TypeError:
                await self._call_with_timeout(
                    self.alert_callback,
                    self.node_uid,
                    self.opid,
                    text,
                    self.logger,
                )
        except Exception:
            self.logger.exception("alert_callback failed for lfm_beacon_detection")

    async def run(self) -> None:
        """Run the LFM Beacon Detection Operation."""

        self._apply_parameters_from_runner()

        alert_interval = float(self.min_detection_interval_s)
        last_alert_time = 0.0
        configured_freq_hz = self.freq_mhz * 1_000_000.0

        try:
            script_path = self._resolve_flow_graph_path()
        except FileNotFoundError:
            self.logger.exception("LFM beacon flowgraph path resolution failed")
            raise

        flow_graph_dir = os.path.dirname(script_path)

        python_path = shutil.which("python3") or sys.executable

        cmd = [
            python_path,
            script_path,
            "--rx-freq-default",
            str(configured_freq_hz),
        ]

        self.logger.info("Using LFM beacon flowgraph: %s", script_path)
        self.logger.info("Starting LFM beacon flowgraph: %s", " ".join(cmd))

        await self._set_status(f"Running: LFM beacon @ {self.freq_mhz:.3f} MHz")

        process: Optional[asyncio.subprocess.Process] = None
        stderr_task: Optional[asyncio.Task] = None

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=flow_graph_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stderr_task = asyncio.create_task(self._drain_stderr(process))

            if process.stdout is None:
                raise RuntimeError("LFM beacon flowgraph stdout pipe was not created")

            while not self._should_stop():
                try:
                    line_bytes = await asyncio.wait_for(
                        process.stdout.readline(),
                        timeout=0.25,
                    )
                except asyncio.TimeoutError:
                    if process.returncode is not None:
                        break
                    continue

                if not line_bytes:
                    self.logger.info("LFM beacon flowgraph exited (EOF on stdout).")
                    break

                line = line_bytes.strip()
                if not line:
                    continue

                text = line.decode(errors="ignore")
                if not text.startswith("TSI:"):
                    continue

                parts = text.split("/")
                if len(parts) < 5:
                    self.logger.warning("Unexpected TSI format: %s", text)
                    continue

                _, label, freq_str, metric_str, tstamp_str = parts[:5]

                try:
                    freq_hz = float(freq_str)
                    metric = float(metric_str)
                    det_time = float(tstamp_str)
                except ValueError:
                    self.logger.warning("Could not parse TSI line: %s", text)
                    continue

                now = time.time()
                if now - last_alert_time < alert_interval:
                    continue

                last_alert_time = now

                detection = self._build_detection_payload(
                    label=label,
                    freq_hz=freq_hz,
                    metric=metric,
                    det_time=det_time if det_time > 0 else now,
                )

                await self._emit_detection(detection)
                await self._emit_alert(detection)

        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("LFM beacon detection operation error")
        finally:
            await self._terminate_process(process)

            if stderr_task is not None:
                stderr_task.cancel()

                try:
                    await stderr_task
                except asyncio.CancelledError:
                    pass
                except Exception:
                    self.logger.exception("stderr task cleanup failed")

            await self._set_status("Idle")
            self.logger.info("LFM beacon detection operation stopped cleanly.")


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test

    run_test(OperationMain, {}, {})