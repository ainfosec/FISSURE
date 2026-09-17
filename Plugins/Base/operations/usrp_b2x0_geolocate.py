#! /usr/bin/env python3
"""USRP B2x0 Geolocate

Hub-side multilateration geolocation using the fixed threshold B2x0 detector
as a subprocess, mirroring the working LFM beacon geolocate pattern.
"""

import asyncio
import inspect
import logging
import os
import shutil
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Union

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))
FLOW_GRAPH_DIR = os.path.join(
    PLUGIN_ROOT,
    "flow_graphs",
    "fixed_detection_flow_graphs",
)

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT, FLOW_GRAPH_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

try:
    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT, get_library_version
    from fissure.utils.common import haversine_m
except ImportError:
    if FISSURE_REPO_ROOT not in sys.path:
        sys.path.insert(0, FISSURE_REPO_ROOT)
    if PLUGIN_ROOT not in sys.path:
        sys.path.insert(0, PLUGIN_ROOT)
    if FLOW_GRAPH_DIR not in sys.path:
        sys.path.insert(0, FLOW_GRAPH_DIR)

    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT, get_library_version
    from fissure.utils.common import haversine_m


class OperationMain(Operation):
    def __init__(
        self,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        detection_callback: Union[Callable, None] = None,
        status_callback: Union[Callable, None] = None,
        target_callback: Union[Callable, None] = None,
        position_callback: Union[Callable, None] = None,
        artifact_manager=None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            detection_callback=detection_callback,
            status_callback=status_callback,
            target_callback=target_callback,
            position_callback=position_callback,
            artifact_manager=artifact_manager,
        )

        self.parameters: Dict[str, Any] = parameters or {}

        self.target_id: str = ""
        self.frequency_mhz: float = 2412.0
        self.min_detection_interval_s: float = 1.0
        self.description: str = "USRP B2x0 geolocation"
        self.sample_rate: float = 1e6
        self.gain_db: float = 65.0
        self.threshold_db: float = -60.0
        self.channel: str = "A:A"
        self.antenna: str = "TX/RX"
        self.hardware_serial_argument: str = "False"

        self.source_id: str = str(node_uid or "sensor_node")
        self.emit_alerts: bool = False

        # Keep network/Hub traffic bounded while still allowing repeated RSSI
        # samples at one receiver position for robust per-position aggregation.
        self.measurement_spacing_m: float = 8.0
        self.stationary_reemit_s: float = 5.0

        self._last_emit_time: float = 0.0
        self._last_spatial_emit_position: Optional[tuple] = None
        self._last_no_position_log_time: float = 0.0

    # ------------------------------------------------------------------
    # Compatibility/callback helpers
    # ------------------------------------------------------------------
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

    async def _call_callback(self, callback: Optional[Callable], *args, timeout: float = 2.0, **kwargs) -> Any:
        if callback is None:
            return None
        try:
            return await asyncio.wait_for(self._maybe_await(callback(*args, **kwargs)), timeout=timeout)
        except asyncio.TimeoutError:
            self.logger.warning("Callback timed out: %s", getattr(callback, "__name__", repr(callback)))
        except Exception:
            self.logger.exception("Callback failed: %s", getattr(callback, "__name__", repr(callback)))
        return None

    async def _set_status(self, text: str) -> None:
        await self._call_callback(getattr(self, "status_callback", None), text)

    async def _drain_stderr(self, stream: Optional[asyncio.StreamReader], name: str) -> None:
        if stream is None:
            return
        try:
            while True:
                line = await stream.readline()
                if not line:
                    break
                text = line.decode(errors="ignore").rstrip()
                if text:
                    self.logger.debug("%s stderr: %s", name, text)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("Failed draining %s stderr", name)

    async def _stop_process(self, process: Optional[asyncio.subprocess.Process], name: str) -> None:
        if process is None:
            return
        if process.returncode is None:
            self.logger.info("Terminating %s process...", name)
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self.logger.warning("%s did not terminate, killing...", name)
                process.kill()
                await process.wait()

    async def _cancel_task(self, task: Optional[asyncio.Task], name: str) -> None:
        if task is None or task.done():
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:
            self.logger.exception("%s task failed during cancellation", name)

    # ------------------------------------------------------------------
    # Parameter/position helpers
    # ------------------------------------------------------------------
    def _apply_parameters_from_runner(self) -> None:
        p = getattr(self, "parameters", None)
        self.logger.info("_apply_parameters_from_runner self.parameters=%r type=%s", p, type(p))

        if not isinstance(p, dict):
            return

        self.target_id = str(p.get("target_id", self.target_id)).strip()

        try:
            self.frequency_mhz = float(p.get("frequency_mhz", p.get("freq_mhz", self.frequency_mhz)))
        except Exception:
            self.frequency_mhz = 2412.0

        try:
            self.min_detection_interval_s = float(
                p.get("min_detection_interval_s", p.get("emit_every_s", self.min_detection_interval_s))
            )
        except Exception:
            self.min_detection_interval_s = 1.0

        self.description = str(p.get("description", self.description)).strip() or "USRP B2x0 geolocation"

        try:
            self.sample_rate = float(p.get("sample_rate", self.sample_rate))
        except Exception:
            self.sample_rate = 1e6
        try:
            self.gain_db = float(p.get("gain_db", p.get("gain", self.gain_db)))
        except Exception:
            self.gain_db = 65.0
        try:
            self.threshold_db = float(p.get("threshold_db", p.get("threshold", self.threshold_db)))
        except Exception:
            self.threshold_db = -60.0

        self.channel = str(p.get("channel", self.channel) or "A:A")
        self.antenna = str(p.get("antenna", self.antenna) or "TX/RX")
        self.hardware_serial_argument = str(
            p.get("hardware_serial_argument", self.hardware_serial_argument) or "False"
        ).strip()

        self.source_id = str(p.get("source_id", self.source_id) or self.node_uid or "sensor_node")
        self.emit_alerts = bool(p.get("emit_alerts", self.emit_alerts))

        try:
            self.measurement_spacing_m = max(
                0.0,
                float(p.get("measurement_spacing_m", self.measurement_spacing_m)),
            )
        except Exception:
            self.measurement_spacing_m = 8.0

        try:
            self.stationary_reemit_s = max(
                self.min_detection_interval_s,
                float(p.get("stationary_reemit_s", self.stationary_reemit_s)),
            )
        except Exception:
            self.stationary_reemit_s = max(self.min_detection_interval_s, 5.0)

    def _snapshot_position(self) -> Dict[str, Any]:
        try:
            position = self.position_callback()
        except Exception as exc:
            self.logger.warning("Position callback failed: %s", exc)
            return {"valid": False, "source": ""}

        if not isinstance(position, dict) or not position.get("valid", False):
            return {
                "valid": False,
                "source": (
                    str(position.get("source") or "")
                    if isinstance(position, dict)
                    else ""
                ),
            }

        lat = position.get("latitude")
        lon = position.get("longitude")
        alt = position.get("altitude")
        if lat is None or lon is None:
            return {
                "valid": False,
                "source": str(position.get("source") or ""),
            }

        return {
            "valid": True,
            "source": str(position.get("source") or ""),
            "latitude": float(lat),
            "longitude": float(lon),
            "altitude": float(alt or 0.0),
        }


    def _position_emit_decision(
        self,
        *,
        lat: float,
        lon: float,
        now: float,
    ) -> tuple:
        """Return (should_emit, reason, distance_from_spatial_anchor_m)."""
        anchor = self._last_spatial_emit_position
        if anchor is None:
            return True, "first_position", None

        try:
            distance_m = haversine_m(anchor[0], anchor[1], lat, lon)
        except Exception:
            distance_m = None

        if (
            distance_m is not None
            and distance_m >= self.measurement_spacing_m
        ):
            return True, "moved", float(distance_m)

        if (now - self._last_emit_time) >= self.stationary_reemit_s:
            return True, "stationary_refresh", distance_m

        return False, "too_close", distance_m


    # ------------------------------------------------------------------
    # Emission helpers
    # ------------------------------------------------------------------
    def _make_detection_payload(
        self,
        *,
        frequency_hz: float,
        metric_db: float,
        det_time: float,
        lat: Optional[float],
        lon: Optional[float],
        alt: Optional[float],
    ) -> Dict[str, Any]:
        detection = {
            "kind": "detection",
            "event_type": "detection",
            "detection_kind": "usrp_b2x0_geolocate",
            "target_id": self.target_id,
            "node_uid": str(self.node_uid),
            "source_id": self.source_id,
            "frequency_hz": int(frequency_hz),
            "frequency_mhz": float(frequency_hz) / 1e6,
            "power_dbm": float(metric_db),
            "metric": float(metric_db),
            "metric_db": float(metric_db),
            "metric_units": "log_power_fft_db",
            "timestamp": float(det_time),
            "detector": "usrp_b2x0_geolocate",
            "opid": self.opid,
            "operation_id": self.opid,
            "flowgraph": "fixed_threshold_b2x0",
            "device": "USRP B2x0",
            "configured_frequency_mhz": self.frequency_mhz,
            "description": self.description,
        }
        if lat is not None:
            detection["latitude"] = float(lat)
        if lon is not None:
            detection["longitude"] = float(lon)
        if alt is not None:
            detection["altitude"] = float(alt)
        return detection

    async def _emit_detection(
        self,
        *,
        frequency_hz: float,
        metric_db: float,
        det_time: float,
        lat: Optional[float],
        lon: Optional[float],
        alt: Optional[float],
    ) -> None:
        detection = self._make_detection_payload(
            frequency_hz=frequency_hz,
            metric_db=metric_db,
            det_time=det_time,
            lat=lat,
            lon=lon,
            alt=alt,
        )

        if self.detection_callback:
            await self._call_callback(self.detection_callback, detection)
        else:
            self.logger.warning("usrp_b2x0_geolocate has no detection_callback")

        if self.emit_alerts and self.alert_callback:
            alert_payload = {
                **detection,
                "kind": "alert",
                "event_type": "alert",
                "alert_kind": "usrp_b2x0_geolocate",
                "message": f"USRP B2x0 detection for {self.target_id} @ {frequency_hz / 1e6:.3f} MHz",
            }
            await self._call_callback(self.alert_callback, alert_payload)

    def _resolve_flowgraph_script(self) -> str:
        version = get_library_version() or "maint-3.10"
        script_path = os.path.join(
            FLOW_GRAPH_DIR,
            version,
            "b2x0",
            "headless",
            "fixed_threshold_b2x0.py",
        )
        if not os.path.isfile(script_path):
            raise FileNotFoundError(f"fixed_threshold_b2x0.py not found: {script_path}")
        return script_path

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    async def run(self) -> None:
        self._apply_parameters_from_runner()

        stderr_task: Optional[asyncio.Task] = None
        process: Optional[asyncio.subprocess.Process] = None

        try:
            if not self.target_id:
                raise RuntimeError("usrp_b2x0_geolocate requires target_id from hub geolocation start")

            await self._set_status(f"Geolocating target {self.target_id} with USRP B2x0")

            configured_freq_hz = self.frequency_mhz * 1000000.0
            script_path = self._resolve_flowgraph_script()
            python_path = shutil.which("python3") or sys.executable

            cmd: List[str] = [
                python_path,
                "-u",
                script_path,
                "--rx-freq-default", str(configured_freq_hz),
                "--sample-rate-default", str(self.sample_rate),
                "--gain-default", str(self.gain_db),
                "--threshold-default", str(self.threshold_db),
                "--channel-default", self.channel,
                "--antenna-default", self.antenna,
                "--min-interval", str(self.min_detection_interval_s),
            ]
            if self.hardware_serial_argument and self.hardware_serial_argument.lower() != "false":
                cmd.extend(["--serial", self.hardware_serial_argument])

            self.logger.info("Starting USRP B2x0 fixed-threshold geolocate flowgraph: %s", " ".join(cmd))

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=os.path.dirname(script_path),
            )
            stderr_task = asyncio.create_task(
                self._drain_stderr(process.stderr, "USRP B2x0 fixed-threshold flowgraph")
            )

            if process.stdout is None:
                raise RuntimeError("Flowgraph stdout pipe was not created")

            while not self._should_stop():
                try:
                    line_bytes = await asyncio.wait_for(process.stdout.readline(), timeout=0.25)
                except asyncio.TimeoutError:
                    continue

                if not line_bytes:
                    self.logger.info("USRP B2x0 fixed-threshold flowgraph exited (EOF on stdout).")
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
                    frequency_hz = float(freq_str)
                    metric = float(metric_str)
                    det_time = float(tstamp_str)
                except ValueError:
                    self.logger.warning("Could not parse TSI line: %s", text)
                    continue

                now = time.time()
                if (now - self._last_emit_time) < self.min_detection_interval_s:
                    continue

                position = self._snapshot_position()
                if not position.get("valid"):
                    if (now - self._last_no_position_log_time) >= 10.0:
                        self.logger.info(
                            "USRP B2x0 geolocation is receiving RF detections but waiting "
                            "for a valid Sensor Node position."
                        )
                        self._last_no_position_log_time = now
                    continue

                lat = float(position.get("latitude"))
                lon = float(position.get("longitude"))
                alt = float(position.get("altitude") or 0.0)

                should_emit, emit_reason, distance_m = self._position_emit_decision(
                    lat=lat,
                    lon=lon,
                    now=now,
                )
                if not should_emit:
                    continue

                if emit_reason in {"first_position", "moved"}:
                    self._last_spatial_emit_position = (lat, lon)
                self._last_emit_time = now

                self.logger.info(
                    "USRP B2x0 measurement for %s: label=%s, freq_mhz=%.6f, "
                    "metric=%.2f, lat=%.7f, lon=%.7f, reason=%s, spacing_m=%s",
                    self.target_id,
                    label,
                    frequency_hz / 1e6,
                    metric,
                    lat,
                    lon,
                    emit_reason,
                    f"{distance_m:.1f}" if distance_m is not None else "-",
                )

                emit_time = det_time if det_time > 0 else now
                await self._emit_detection(
                    frequency_hz=frequency_hz,
                    metric_db=metric,
                    det_time=emit_time,
                    lat=lat,
                    lon=lon,
                    alt=alt,
                )

                await self._set_status(
                    f"Tracking {self.target_id} @ {frequency_hz / 1e6:.3f} MHz"
                )

        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.exception("USRP B2x0 geolocate operation error: %s", e)
        finally:
            await self._stop_process(process, "USRP B2x0 fixed-threshold flowgraph")
            await self._cancel_task(stderr_task, "stderr drain")
            await self._set_status("Idle")
            self.logger.info("USRP B2x0 geolocate operation stopped cleanly.")


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})