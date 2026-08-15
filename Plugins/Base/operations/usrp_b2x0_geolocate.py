#! /usr/bin/env python3
"""USRP B2x0 Geolocate

Hub-side multilateration geolocation using the fixed threshold B2x0 detector
as a subprocess, mirroring the working LFM beacon geolocate pattern.
"""

import asyncio
import inspect
import json
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
    from fissure.utils import FISSURE_ROOT
except ImportError:
    if FISSURE_REPO_ROOT not in sys.path:
        sys.path.insert(0, FISSURE_REPO_ROOT)
    if PLUGIN_ROOT not in sys.path:
        sys.path.insert(0, PLUGIN_ROOT)
    if FLOW_GRAPH_DIR not in sys.path:
        sys.path.insert(0, FLOW_GRAPH_DIR)

    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT


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
            artifact_manager=artifact_manager,
        )

        self.parameters: Dict[str, Any] = parameters or {}

        self.target_id: str = ""
        self.frequency_mhz: float = 2412.0
        self.min_detection_interval_s: float = 1.0
        self.description: str = "USRP B2x0 geolocation"

        self.gpsd_host: str = "127.0.0.1"
        self.gpsd_port: int = 2947
        self.gps_refresh_interval: float = 1.0

        self.source_id: str = str(node_uid or "sensor_node")
        self.emit_alerts: bool = False

        self._gps_stop = asyncio.Event()
        self._current_position: Dict[str, Any] = {"lat": None, "lon": None, "alt": 0.0}
        self._last_emit_time: float = 0.0

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
    # Parameter/GPS helpers
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
        self.gpsd_host = str(p.get("gpsd_host", self.gpsd_host))
        self.gpsd_port = int(p.get("gpsd_port", self.gpsd_port))
        self.gps_refresh_interval = float(p.get("gps_refresh_interval", self.gps_refresh_interval))

        self.source_id = str(p.get("source_id", self.source_id) or self.node_uid or "sensor_node")
        self.emit_alerts = bool(p.get("emit_alerts", self.emit_alerts))

    async def _gps_loop(self) -> None:
        self.logger.info("Starting GPS loop (GPSD)")
        buf = ""

        while (not self._should_stop()) and (not self._gps_stop.is_set()):
            writer = None
            try:
                reader, writer = await asyncio.open_connection(self.gpsd_host, self.gpsd_port)
                writer.write(b'?WATCH={"enable":true,"json":true}\n')
                await writer.drain()

                while (not self._should_stop()) and (not self._gps_stop.is_set()):
                    data = await reader.read(4096)
                    if not data:
                        await asyncio.sleep(0.5)
                        continue

                    buf += data.decode(errors="ignore")

                    while "\n" in buf:
                        if self._should_stop() or self._gps_stop.is_set():
                            break

                        line, buf = buf.split("\n", 1)
                        if not line.strip():
                            continue

                        try:
                            msg = json.loads(line)
                        except Exception:
                            continue

                        if msg.get("class") == "TPV" and msg.get("mode", 0) >= 2:
                            lat = msg.get("lat")
                            lon = msg.get("lon")
                            alt = msg.get("altMSL") or msg.get("altHAE") or msg.get("alt") or 0.0

                            if lat is not None and lon is not None:
                                self._current_position.update({
                                    "lat": float(lat),
                                    "lon": float(lon),
                                    "alt": float(alt or 0.0),
                                })

            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.logger.warning("GPS error: %s", e)
                await asyncio.sleep(2.0)
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

        self.logger.info("GPS loop exited")

    # ------------------------------------------------------------------
    # Emission helpers
    # ------------------------------------------------------------------
    def _make_detection_payload(
        self,
        *,
        frequency_hz: float,
        metric_db: float,
        det_time: float,
        lat: float,
        lon: float,
        alt: float,
    ) -> Dict[str, Any]:
        return {
            "kind": "detection",
            "event_type": "detection",
            "detection_kind": "usrp_b2x0_geolocate",
            "target_id": self.target_id,
            "node_uid": str(self.node_uid),
            "source_id": self.source_id,
            "frequency_hz": int(frequency_hz),
            "frequency_mhz": float(frequency_hz) / 1e6,
            "power_dbm": float(metric_db),
            "metric_db": float(metric_db),
            "timestamp": float(det_time),
            "detector": "usrp_b2x0_geolocate",
            "opid": self.opid,
            "operation_id": self.opid,
            "flowgraph": "fixed_threshold_b2x0",
            "device": "USRP B2x0",
            "configured_frequency_mhz": self.frequency_mhz,
            "description": self.description,
            "lat": float(lat),
            "lon": float(lon),
            "alt": float(alt or 0.0),
        }

    async def _emit_detection(
        self,
        *,
        frequency_hz: float,
        metric_db: float,
        det_time: float,
        lat: float,
        lon: float,
        alt: float,
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
        script_path = os.path.join(FLOW_GRAPH_DIR, "fixed_threshold_b2x0.py")
        if not os.path.isfile(script_path):
            raise FileNotFoundError(f"fixed_threshold_b2x0.py not found: {script_path}")
        return script_path

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------
    async def run(self) -> None:
        self._apply_parameters_from_runner()

        gps_task: Optional[asyncio.Task] = None
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
                script_path,
                "--rx-freq-default", str(configured_freq_hz),
            ]

            self.logger.info("Starting USRP B2x0 fixed-threshold geolocate flowgraph: %s", " ".join(cmd))

            gps_task = asyncio.create_task(self._gps_loop())

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=FLOW_GRAPH_DIR,
            )
            stderr_task = asyncio.create_task(
                self._drain_stderr(process.stderr, "USRP B2x0 fixed-threshold flowgraph")
            )

            if process.stdout is None:
                raise RuntimeError("Flowgraph stdout pipe was not created")

            while not self._should_stop():
                lat = self._current_position.get("lat")
                lon = self._current_position.get("lon")
                alt = self._current_position.get("alt", 0.0)
                if lat is None or lon is None:
                    await asyncio.sleep(0.25)
                    continue

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
                self._last_emit_time = now

                self.logger.info(
                    "USRP B2x0 measurement for %s: label=%s, freq_mhz=%.6f, metric=%.2f, lat=%s, lon=%s",
                    self.target_id,
                    label,
                    frequency_hz / 1e6,
                    metric,
                    lat,
                    lon,
                )

                emit_time = det_time if det_time > 0 else now
                await self._emit_detection(
                    frequency_hz=frequency_hz,
                    metric_db=metric,
                    det_time=emit_time,
                    lat=float(lat),
                    lon=float(lon),
                    alt=float(alt or 0.0),
                )

                await self._set_status(f"Tracking {self.target_id} @ {frequency_hz / 1e6:.3f} MHz")

        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.exception("USRP B2x0 geolocate operation error: %s", e)
        finally:
            self._gps_stop.set()
            await self._cancel_task(gps_task, "GPS")
            await self._stop_process(process, "USRP B2x0 fixed-threshold flowgraph")
            await self._cancel_task(stderr_task, "stderr drain")
            await self._set_status("Idle")
            self.logger.info("USRP B2x0 geolocate operation stopped cleanly.")


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})