#! /usr/bin/env python3
"""LFM Beacon Geolocate"""

import asyncio
import contextlib
import json
import logging
import os
import sys
import time
from typing import Any, Callable, Dict, Optional, Union


PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))

FLOW_GRAPH_BASE_DIR = os.path.join(
    PLUGIN_ROOT,
    "flow_graphs",
    "lfm_beacon_detection_flow_graphs",
)

for path in (FISSURE_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from fissure.utils.plugins.operations import Operation
from fissure.utils import get_library_version


class OperationMain(Operation):
    """LFM beacon geolocation using hub-side multilateration for one selected target."""

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
        self.freq_mhz: float = 433.0
        self.min_detection_interval_s: float = 1.0
        self.description: str = "LFM beacon geolocation"

        self.gpsd_host: str = "127.0.0.1"
        self.gpsd_port: int = 2947
        self.gps_refresh_interval: float = 1.0

        self._gps_stop = asyncio.Event()
        self._current_position = {"lat": None, "lon": None, "alt": 0.0}
        self._last_emit_time: float = 0.0

    def _apply_parameters_from_runner(self) -> None:
        p = getattr(self, "parameters", None)
        self.logger.info(f"_apply_parameters_from_runner self.parameters={p!r} type={type(p)}")

        if not isinstance(p, dict):
            return

        self.target_id = str(p.get("target_id", self.target_id)).strip()

        try:
            self.freq_mhz = float(p.get("freq_mhz", self.freq_mhz))
        except Exception:
            self.freq_mhz = 433.0

        try:
            self.min_detection_interval_s = float(
                p.get("min_detection_interval_s", self.min_detection_interval_s)
            )
        except Exception:
            self.min_detection_interval_s = 1.0

        self.description = (
            str(p.get("description", self.description)).strip()
            or "LFM beacon geolocation"
        )
        self.gpsd_host = str(p.get("gpsd_host", self.gpsd_host))

        try:
            self.gpsd_port = int(p.get("gpsd_port", self.gpsd_port))
        except Exception:
            self.gpsd_port = 2947

        try:
            self.gps_refresh_interval = float(
                p.get("gps_refresh_interval", self.gps_refresh_interval)
            )
        except Exception:
            self.gps_refresh_interval = 1.0

        self.resource_args = {"freq_mhz": self.freq_mhz}

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
            raise FileNotFoundError(f"LFM beacon flow graph not found: {script_path}")

        return script_path

    async def _gps_loop(self) -> None:
        self.logger.info("Starting GPS loop: GPSD")
        buf = ""

        while not self._stop and not self._gps_stop.is_set():
            writer = None

            try:
                reader, writer = await asyncio.open_connection(
                    self.gpsd_host,
                    self.gpsd_port,
                )
                writer.write(b'?WATCH={"enable":true,"json":true}\n')
                await writer.drain()

                while not self._stop and not self._gps_stop.is_set():
                    try:
                        data = await asyncio.wait_for(
                            reader.read(4096),
                            timeout=max(0.25, self.gps_refresh_interval),
                        )
                    except asyncio.TimeoutError:
                        continue

                    if not data:
                        await asyncio.sleep(0.5)
                        continue

                    buf += data.decode(errors="ignore")

                    while "\n" in buf:
                        if self._stop or self._gps_stop.is_set():
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
                            alt = msg.get("altMSL") or msg.get("altHAE") or 0.0

                            if lat is not None and lon is not None:
                                self._current_position.update(
                                    {
                                        "lat": float(lat),
                                        "lon": float(lon),
                                        "alt": float(alt),
                                    }
                                )

            except asyncio.CancelledError:
                raise

            except Exception as e:
                self.logger.warning(f"GPS error: {e}")
                await asyncio.sleep(2.0)

            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

        self.logger.info("GPS loop stopped.")

    async def _emit_detection(
        self,
        *,
        label: str,
        frequency_hz: float,
        metric_db: float,
        det_time: float,
        lat: Union[float, None],
        lon: Union[float, None],
        alt: Union[float, None],
    ) -> None:
        ts = time.time()
        cb_timeout_s = 2.0

        detection = {
            "kind": "detection",
            "event_type": "detection",
            "detection_kind": "lfm_beacon_geolocate",
            "target_id": self.target_id,
            "node_uid": str(self.node_uid),
            "source_id": str(self.node_uid),
            "description": self.description,
            "label": label,
            "frequency_hz": int(frequency_hz),
            "frequency_mhz": float(frequency_hz) / 1e6,
            "power_dbm": float(metric_db),
            "timestamp": int(ts),
            "flowgraph_timestamp": float(det_time),
            "detector": "lfm_beacon_geolocate",
            "opid": self.opid,
            "flowgraph": "lfm_beacon_rtlsdr",
            "device": "RTL-SDR",
            "configured_frequency_mhz": self.freq_mhz,
            "latitude": lat,
            "longitude": lon,
            "altitude": alt,
        }

        if self.detection_callback:
            try:
                await asyncio.wait_for(self.detection_callback(detection), timeout=cb_timeout_s)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception("detection_callback failed")
        else:
            self.logger.warning("lfm_beacon_geolocate has no detection_callback")

        if self.alert_callback:
            try:
                await asyncio.wait_for(
                    self.alert_callback(
                        self.node_uid,
                        self.opid,
                        (
                            f"{self.description} {self.target_id} "
                            f"@ {frequency_hz / 1e6:.3f} MHz, metric {metric_db:.2f}"
                        ),
                        self.logger,
                    ),
                    timeout=cb_timeout_s,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception("alert_callback failed")

    async def run(self) -> None:
        self._apply_parameters_from_runner()

        if not self.target_id:
            raise RuntimeError("lfm_beacon_geolocate requires target_id from hub geolocation start")

        if self.status_callback:
            await self.status_callback(f"Geolocating LFM beacon {self.target_id}")

        configured_freq_hz = self.freq_mhz * 1_000_000.0

        script_path = self._resolve_flow_graph_path()
        flow_graph_dir = os.path.dirname(script_path)

        cmd = [
            sys.executable,
            "-u",
            script_path,
            "--rx-freq-default",
            str(configured_freq_hz),
        ]

        self.logger.info(f"Using LFM beacon flow graph: {script_path}")
        self.logger.info(f"Starting LFM beacon flow graph: {' '.join(cmd)}")

        gps_task = asyncio.create_task(self._gps_loop())

        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=flow_graph_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def _log_stderr() -> None:
            if process.stderr is None:
                return

            while True:
                line = await process.stderr.readline()
                if not line:
                    break

                text = line.decode(errors="ignore").strip()
                if text:
                    self.logger.warning(f"lfm_beacon_geolocate stderr: {text}")

        stderr_task = asyncio.create_task(_log_stderr())

        try:
            if process.stdout is None:
                raise RuntimeError("LFM beacon flow graph stdout pipe was not created")

            while not self._stop:
                try:
                    line_bytes = await asyncio.wait_for(
                        process.stdout.readline(),
                        timeout=0.25,
                    )
                except asyncio.TimeoutError:
                    continue

                if not line_bytes:
                    self.logger.info("LFM beacon flow graph exited: EOF on stdout.")
                    break

                text = line_bytes.decode(errors="ignore").strip()
                if not text:
                    continue

                self.logger.debug(f"lfm_beacon_geolocate stdout: {text}")

                if "TSI:" not in text:
                    continue

                text = text[text.index("TSI:") :]

                parts = text.split("/")
                if len(parts) < 5:
                    self.logger.warning(f"Unexpected TSI format: {text}")
                    continue

                _, label, freq_str, metric_str, tstamp_str = parts[:5]

                try:
                    frequency_hz = float(freq_str)
                    metric = float(metric_str)
                    det_time = float(tstamp_str)
                except ValueError:
                    self.logger.warning(f"Could not parse TSI line: {text}")
                    continue

                now = time.time()
                if (now - self._last_emit_time) < self.min_detection_interval_s:
                    continue

                self._last_emit_time = now

                lat = self._current_position.get("lat")
                lon = self._current_position.get("lon")
                alt = self._current_position.get("alt")

                if lat is None or lon is None:
                    self.logger.debug(
                        "LFM beacon measurement received before GPS fix; emitting detection without node position."
                    )

                self.logger.info(
                    f"LFM beacon measurement for {self.target_id}: "
                    f"label={label}, freq_mhz={frequency_hz / 1e6:.6f}, "
                    f"metric={metric:.2f}, lat={lat}, lon={lon}"
                )

                await self._emit_detection(
                    label=label,
                    frequency_hz=frequency_hz,
                    metric_db=metric,
                    det_time=det_time if det_time > 0 else now,
                    lat=lat,
                    lon=lon,
                    alt=alt,
                )

                if self.status_callback:
                    await self.status_callback(
                        f"Tracking LFM beacon {self.target_id} @ {frequency_hz / 1e6:.3f} MHz"
                    )

        except asyncio.CancelledError:
            raise

        except Exception as e:
            self.logger.exception(f"LFM beacon geolocate operation error: {e}")
            raise

        finally:
            self._gps_stop.set()

            if gps_task and not gps_task.done():
                gps_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await gps_task

            if stderr_task and not stderr_task.done():
                stderr_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await stderr_task

            if process.returncode is None:
                self.logger.info("Terminating LFM beacon flow graph process...")
                process.terminate()

                try:
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    self.logger.warning("LFM beacon flow graph did not terminate, killing...")
                    process.kill()
                    await process.wait()

            if self.status_callback:
                try:
                    await self.status_callback("Idle")
                except Exception:
                    self.logger.exception("status_callback failed while setting Idle")

            self.logger.info("LFM beacon geolocate operation stopped cleanly.")


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test

    run_test(OperationMain, {}, {})