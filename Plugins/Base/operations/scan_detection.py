#! /usr/bin/env python3
"""B2x0 scan/sweep detection using fixed_threshold_b2x0 in-process."""

import asyncio
import importlib.util
import json
import logging
import os
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Union


PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))

FLOW_GRAPH_BASE_DIR = os.path.join(
    PLUGIN_ROOT,
    "flow_graphs",
    "fixed_detection_flow_graphs",
)

for path in (FISSURE_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from fissure.utils.plugins.operations import Operation
from fissure.utils import get_library_version

from gnuradio import gr
import pmt


class DetectionSink(gr.basic_block):
    """Receives GNU Radio messages and forwards each payload string to a callback."""

    def __init__(
        self,
        callback: Callable[[str], None],
        logger: Union[logging.Logger, None] = None,
    ):
        gr.basic_block.__init__(
            self,
            name="scan_detection_sink",
            in_sig=None,
            out_sig=None,
        )

        self._callback = callback
        self._logger = logger or logging.getLogger(__name__)

        self.message_port_register_in(pmt.intern("in"))
        self.set_msg_handler(pmt.intern("in"), self._handle_msg)

    def _handle_msg(self, msg):
        try:
            if pmt.is_symbol(msg):
                text = pmt.symbol_to_string(msg)
            else:
                text = pmt.write_string(msg)

            if self._callback:
                self._callback(text)

        except Exception as e:
            self._logger.error(f"[SCAN] DetectionSink error: {e}")


class OperationMain(Operation):
    """Scan/sweep detection across preset or custom frequency bands."""

    BAND_PLANS = {
        "315 MHz ISM": [
            {
                "start_mhz": 300.0,
                "end_mhz": 330.0,
                "step_mhz": 1.0,
            },
        ],
        "433 MHz ISM": [
            {
                "start_mhz": 420.0,
                "end_mhz": 450.0,
                "step_mhz": 1.0,
            },
        ],
        "868 MHz ISM": [
            {
                "start_mhz": 860.0,
                "end_mhz": 880.0,
                "step_mhz": 1.0,
            },
        ],
        "902-928 MHz ISM": [
            {
                "start_mhz": 902.0,
                "end_mhz": 928.0,
                "step_mhz": 1.0,
            },
        ],
        "2.4 GHz Wi-Fi": [
            {
                "start_mhz": 2400.0,
                "end_mhz": 2500.0,
                "step_mhz": 5.0,
            },
        ],
        "Common RF Sweep": [
            {
                "start_mhz": 300.0,
                "end_mhz": 330.0,
                "step_mhz": 1.0,
            },
            {
                "start_mhz": 420.0,
                "end_mhz": 450.0,
                "step_mhz": 1.0,
            },
            {
                "start_mhz": 860.0,
                "end_mhz": 880.0,
                "step_mhz": 1.0,
            },
            {
                "start_mhz": 902.0,
                "end_mhz": 928.0,
                "step_mhz": 1.0,
            },
            {
                "start_mhz": 2400.0,
                "end_mhz": 2500.0,
                "step_mhz": 5.0,
            },
        ],
    }

    def __init__(
        self,
        band_plan: str = "902-928 MHz ISM",
        custom_start_mhz: Union[str, float] = 2400.0,
        custom_end_mhz: Union[str, float] = 2500.0,
        custom_step_mhz: Union[str, float] = 5.0,
        dwell_s: Union[str, float] = 3.0,
        alert_interval_s: Union[str, float] = 3.0,
        threshold: Union[str, float] = -60.0,
        sample_rate: Union[str, float] = 1000000.0,
        gain: Union[str, float] = 65.0,
        channel: str = "A:A",
        antenna: str = "TX/RX",
        run_mode: str = "headless",
        retune_settle_s: Union[str, float] = 0.25,
        bands_json: str = "",
        blacklist_json: str = "",
        description: str = "Sweep scan detection",
        source_id: str = "",
        dev: str = "",
        serial: str = "",
        hardware_serial: str = "",
        hardware_type: str = "",
        hardware_uid: str = "",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        status_callback: Union[Callable, None] = None,
        **kwargs,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            status_callback=status_callback,
        )

        self.band_plan = str(band_plan or "902-928 MHz ISM").strip()
        self.custom_start_mhz = self._float(custom_start_mhz, 2400.0)
        self.custom_end_mhz = self._float(custom_end_mhz, 2500.0)
        self.custom_step_mhz = max(0.001, self._float(custom_step_mhz, 5.0))

        self.dwell_s = max(0.1, self._float(dwell_s, 3.0))
        self.alert_interval_s = max(0.0, self._float(alert_interval_s, 3.0))
        self.threshold = self._float(threshold, -60.0)
        self.sample_rate = max(1.0, self._float(sample_rate, 1000000.0))
        self.gain = self._float(gain, 65.0)
        self.channel = str(channel or "A:A").strip()
        self.antenna = str(antenna or "TX/RX").strip()

        self.run_mode = str(run_mode or "headless").strip().lower()
        if self.run_mode not in {"headless", "gui"}:
            self.run_mode = "headless"

        self.retune_settle_s = max(0.0, self._float(retune_settle_s, 0.25))
        self.bands_json = str(bands_json or "").strip()
        self.blacklist_json = str(blacklist_json or "").strip()
        self.description = description or "Sweep scan detection"
        self.source_id = source_id or node_uid or "sensor_node"

        self.dev = str(dev or serial or hardware_serial or "").strip()
        self.hardware_type = str(hardware_type or "").strip()
        self.hardware_uid = str(hardware_uid or "").strip()

        self.extra_parameters = kwargs or {}

        self.resource_args = {
            "dev": self.dev,
            "hardware_type": self.hardware_type,
            "hardware_uid": self.hardware_uid,
        }

        self.bands = self._resolve_bands()
        self.blacklist = self._resolve_blacklist()
        self.scan_frequencies_hz = self._build_scan_frequencies_hz(
            self.bands,
            self.blacklist,
        )

        self.logger.info(
            "scan_detection init params: "
            f"band_plan={self.band_plan}, "
            f"bands={self.bands}, "
            f"blacklist={self.blacklist}, "
            f"scan_points={len(self.scan_frequencies_hz)}, "
            f"dwell_s={self.dwell_s}, "
            f"alert_interval_s={self.alert_interval_s}, "
            f"threshold={self.threshold}, "
            f"sample_rate={self.sample_rate}, "
            f"gain={self.gain}, "
            f"channel={self.channel}, "
            f"antenna={self.antenna}, "
            f"run_mode={self.run_mode}, "
            f"retune_settle_s={self.retune_settle_s}, "
            f"description={self.description}, "
            f"dev={self.dev}, "
            f"hardware_type={self.hardware_type}, "
            f"hardware_uid={self.hardware_uid}"
        )

    @staticmethod
    def get_resources(dev: str = "", **kwargs) -> Dict[str, Any]:
        return {
            "usrp": {
                "type": "sdr",
                "model": "USRP B2x0",
                "serial": dev,
                "description": "USRP B2x0",
                "required": True,
            }
        }

    async def run(self) -> None:
        """Run scan/sweep detection."""
        try:
            await self._run_scan_detection()

        except asyncio.CancelledError:
            self.logger.info("scan_detection cancelled")
            raise

        except Exception:
            self.logger.exception("scan_detection failed")
            raise

        finally:
            if self.status_callback:
                try:
                    await self.status_callback("Idle")
                except Exception:
                    self.logger.exception(
                        "scan_detection status_callback failed while setting Idle"
                    )

    async def _run_scan_detection(self) -> None:
        if not self.scan_frequencies_hz:
            self.logger.warning("[SCAN] No scan frequencies resolved. Exiting.")
            return

        script_path = self._resolve_flow_graph_path()
        flow_graph_dir = os.path.dirname(script_path)

        self.logger.info(f"[SCAN] Using flow graph: {script_path}")

        fixed_threshold_cls = self._load_flow_graph_class(
            script_path,
            "fixed_threshold_b2x0",
        )

        self.logger.info("[SCAN] Creating fixed_threshold_b2x0 in-process.")
        tb = fixed_threshold_cls()

        self._configure_flow_graph(tb)

        loop = asyncio.get_running_loop()
        detections: asyncio.Queue[str] = asyncio.Queue()

        def enqueue_detection(text: str):
            loop.call_soon_threadsafe(detections.put_nowait, text)

        sink = DetectionSink(enqueue_detection, logger=self.logger)

        self._connect_detection_sink(tb, sink)

        last_alert_by_freq: Dict[float, float] = {}
        scan_index = 0

        try:
            tb.start()
            self.logger.info("[SCAN] Flow graph started.")

            while not self._stop:
                freq_hz = self.scan_frequencies_hz[scan_index]
                scan_index = (scan_index + 1) % len(self.scan_frequencies_hz)

                freq_mhz = freq_hz / 1e6
                retune_time = time.time()

                try:
                    self._retune_flow_graph(tb, freq_hz)
                except Exception:
                    self.logger.exception(
                        f"[SCAN] Retune failed @ {freq_mhz:.3f} MHz"
                    )
                    await asyncio.sleep(self.dwell_s)
                    continue

                self.logger.info(f"[SCAN] Retuned to {freq_mhz:.3f} MHz")

                if self.status_callback:
                    try:
                        await self.status_callback(
                            f"Running: Scan tuned {freq_mhz:.3f} MHz"
                        )
                    except Exception:
                        self.logger.exception(
                            "[SCAN] status_callback failed during retune"
                        )

                dwell_end = retune_time + self.dwell_s
                detections_seen = 0

                while time.time() < dwell_end and not self._stop:
                    try:
                        text = await asyncio.wait_for(
                            detections.get(),
                            timeout=0.05,
                        )
                    except asyncio.TimeoutError:
                        continue

                    if time.time() - retune_time < self.retune_settle_s:
                        continue

                    parsed = self._parse_tsi_detection(text)
                    if parsed is None:
                        continue

                    det_freq_hz = parsed["frequency_hz"]
                    det_rssi_dbm = parsed["power_dbm"]
                    flowgraph_timestamp = parsed["flowgraph_timestamp"]
                    label = parsed["label"]

                    detections_seen += 1

                    last = last_alert_by_freq.get(freq_hz, 0.0)
                    now = time.time()

                    if now - last < self.alert_interval_s:
                        continue

                    last_alert_by_freq[freq_hz] = now

                    await self._emit_detection(
                        label=label,
                        det_freq_hz=det_freq_hz,
                        det_rssi_dbm=det_rssi_dbm,
                        flowgraph_timestamp=flowgraph_timestamp,
                        scan_frequency_hz=freq_hz,
                        retune_time=retune_time,
                    )

                self.logger.info(
                    f"[SCAN] Completed dwell @ {freq_mhz:.3f} MHz, "
                    f"detections_seen={detections_seen}"
                )

        finally:
            self.logger.info("[SCAN] Stopping flow graph...")

            try:
                tb.stop()
            except Exception:
                self.logger.exception("[SCAN] tb.stop failed")

            try:
                tb.wait()
            except Exception:
                self.logger.exception("[SCAN] tb.wait failed")

            self.logger.info("[SCAN] Stopped.")

    def _resolve_flow_graph_path(self) -> str:
        version = get_library_version() or "maint-3.10"

        script_path = os.path.join(
            FLOW_GRAPH_BASE_DIR,
            version,
            "b2x0",
            self.run_mode,
            "fixed_threshold_b2x0.py",
        )

        if not os.path.isfile(script_path):
            raise FileNotFoundError(
                f"Scan detection flow graph not found: {script_path}"
            )

        return script_path

    def _load_flow_graph_class(self, script_path: str, class_name: str):
        flow_graph_dir = os.path.dirname(script_path)

        if flow_graph_dir not in sys.path:
            sys.path.insert(0, flow_graph_dir)

        module_name = f"_fissure_scan_{class_name}_{abs(hash(script_path))}"

        spec = importlib.util.spec_from_file_location(
            module_name,
            script_path,
        )

        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load flow graph module: {script_path}")

        module = importlib.util.module_from_spec(spec)

        old_cwd = os.getcwd()
        try:
            os.chdir(flow_graph_dir)
            spec.loader.exec_module(module)
        finally:
            os.chdir(old_cwd)

        flow_graph_class = getattr(module, class_name, None)

        if flow_graph_class is None:
            raise ImportError(
                f"Flow graph class {class_name!r} not found in {script_path}"
            )

        return flow_graph_class

    def _configure_flow_graph(self, tb) -> None:
        setter_calls = [
            ("sample_rate", self.sample_rate),
            ("threshold", self.threshold),
            ("gain", self.gain),
            ("channel", self.channel),
            ("antenna", self.antenna),
        ]

        for name, value in setter_calls:
            self._call_possible_setters(
                tb,
                name,
                value,
                required=False,
            )

    def _retune_flow_graph(self, tb, freq_hz: float) -> None:
        self._call_possible_setters(
            tb,
            "rx_freq",
            freq_hz,
            required=True,
        )

    def _call_possible_setters(
        self,
        tb,
        field_name: str,
        value: Any,
        required: bool = False,
    ) -> bool:
        setter_names = [
            f"set_{field_name}",
            f"set_{field_name}_default",
        ]

        # Common generated GRC aliases from your fixed detector scripts.
        if field_name == "sample_rate":
            setter_names.extend(
                [
                    "set_sample_rate_default",
                    "set_samp_rate",
                    "set_samp_rate_default",
                ]
            )

        elif field_name == "threshold":
            setter_names.extend(
                [
                    "set_threshold_default",
                ]
            )

        elif field_name == "gain":
            setter_names.extend(
                [
                    "set_gain_default",
                    "set_rx_gain",
                    "set_rx_gain_default",
                ]
            )

        elif field_name == "channel":
            setter_names.extend(
                [
                    "set_channel_default",
                    "set_rx_channel",
                    "set_rx_channel_default",
                ]
            )

        elif field_name == "antenna":
            setter_names.extend(
                [
                    "set_antenna_default",
                    "set_rx_antenna",
                    "set_rx_antenna_default",
                ]
            )

        elif field_name == "rx_freq":
            setter_names.extend(
                [
                    "set_rx_freq_default",
                    "set_freq",
                    "set_frequency",
                    "set_center_freq",
                ]
            )

        tried = []

        for setter_name in dict.fromkeys(setter_names):
            setter = getattr(tb, setter_name, None)
            if not callable(setter):
                continue

            tried.append(setter_name)

            try:
                setter(value)
                self.logger.debug(
                    f"[SCAN] Called {setter_name}({value!r})"
                )
                return True
            except Exception:
                self.logger.exception(
                    f"[SCAN] {setter_name}({value!r}) failed"
                )

        if required:
            raise AttributeError(
                f"Required flow graph setter not found/usable for "
                f"{field_name!r}. Tried: {tried or setter_names}"
            )

        self.logger.debug(
            f"[SCAN] Optional setter not found/usable for "
            f"{field_name!r}. Tried: {tried or setter_names}"
        )

        return False

    def _connect_detection_sink(self, tb, sink: DetectionSink) -> None:
        source_blocks = [
            getattr(tb, "epy_block_0", None),
            getattr(tb, "fixed_threshold_b2x0_epy_block_0", None),
        ]

        ports = [
            "detected_signals",
            "out",
        ]

        for source_block in source_blocks:
            if source_block is None:
                continue

            for port in ports:
                try:
                    tb.msg_connect((source_block, port), (sink, "in"))
                    self.logger.info(
                        f"[SCAN] Connected detection sink from {source_block}.{port}"
                    )
                    return
                except Exception:
                    continue

        raise RuntimeError(
            "Could not connect scan detection sink to flow graph message port."
        )

    def _parse_tsi_detection(self, text: str) -> Optional[Dict[str, Any]]:
        if not text:
            return None

        if "TSI:" not in text:
            return None

        text = text[text.index("TSI:") :]

        if not text.startswith("TSI:/Signal Found"):
            return None

        parts = text.split("/")
        if len(parts) < 5:
            self.logger.warning(f"[SCAN] Unexpected TSI format: {text}")
            return None

        _, label, freq_str, rssi_str, tstamp_str = parts[:5]

        try:
            freq_hz = float(freq_str)
            rssi_dbm = float(rssi_str)
            flowgraph_timestamp = float(tstamp_str)
        except ValueError:
            self.logger.warning(f"[SCAN] Could not parse TSI line: {text}")
            return None

        return {
            "label": label,
            "frequency_hz": freq_hz,
            "power_dbm": rssi_dbm,
            "flowgraph_timestamp": flowgraph_timestamp,
        }

    async def _emit_detection(
        self,
        *,
        label: str,
        det_freq_hz: float,
        det_rssi_dbm: float,
        flowgraph_timestamp: float,
        scan_frequency_hz: float,
        retune_time: float,
    ) -> None:
        ts = time.time()
        cb_timeout_s = 2.0

        scan_freq_mhz = round(scan_frequency_hz / 1e6, 3)

        detection = {
            "kind": "detection",
            "event_type": "detection",
            "node_uid": self.node_uid,
            "source_id": self.source_id,
            "description": self.description,
            "label": label,
            "frequency_hz": int(det_freq_hz),
            "frequency_mhz": float(det_freq_hz) / 1e6,
            "power_dbm": float(det_rssi_dbm),
            "timestamp": int(ts),
            "flowgraph_timestamp": float(flowgraph_timestamp),
            "detector": "scan_detection",
            "opid": self.opid,
            "flowgraph": "fixed_threshold_b2x0",
            "device": "USRP B2x0",
            "scan_frequency_hz": int(scan_frequency_hz),
            "scan_frequency_mhz": scan_freq_mhz,
            "retune_age_s": round(ts - retune_time, 3),
            "band_plan": self.band_plan,
        }

        self.logger.info(
            f"[SCAN] Detection @ {det_freq_hz / 1e6:.3f} MHz, "
            f"RSSI={det_rssi_dbm:.1f} dBm, "
            f"scan_freq={scan_freq_mhz:.3f} MHz, "
            f"opid={self.opid}"
        )

        if self.tak_cot_callback:
            try:
                await asyncio.wait_for(
                    self.tak_cot_callback(
                        {
                            "msg_type": "event",
                            "uid": f"scan-detection-{self.node_uid}-{int(ts)}",
                            "lat": True,
                            "lon": True,
                            "alt": True,
                            "time": True,
                            "data": detection,
                            "opid": self.opid,
                            "tak_icon": "r-x-fissure-detection",
                        }
                    ),
                    timeout=cb_timeout_s,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception("[SCAN] tak_cot_callback failed")
        else:
            self.logger.warning("[SCAN] No tak_cot_callback configured")

        if self.alert_callback:
            try:
                await asyncio.wait_for(
                    self.alert_callback(
                        self.node_uid,
                        self.opid,
                        (
                            f"{self.description} @ "
                            f"{det_freq_hz / 1e6:.3f} MHz, "
                            f"RSSI {det_rssi_dbm:.1f} dBm"
                        ),
                        self.logger,
                    ),
                    timeout=cb_timeout_s,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception("[SCAN] alert_callback failed")
        else:
            self.logger.warning("[SCAN] No alert_callback configured")

    def _resolve_bands(self) -> List[Dict[str, float]]:
        if self.bands_json:
            parsed = self._parse_json_list(
                self.bands_json,
                "bands_json",
            )
            bands = self._normalize_bands(parsed)
            if bands:
                return bands

        if self.band_plan == "Custom Single Band":
            return self._normalize_bands(
                [
                    {
                        "start_mhz": self.custom_start_mhz,
                        "end_mhz": self.custom_end_mhz,
                        "step_mhz": self.custom_step_mhz,
                        "dwell_s": self.dwell_s,
                    }
                ]
            )

        plan_bands = self.BAND_PLANS.get(self.band_plan)

        if not plan_bands:
            self.logger.warning(
                f"[SCAN] Unknown band_plan={self.band_plan!r}; "
                "falling back to 902-928 MHz ISM."
            )
            plan_bands = self.BAND_PLANS["902-928 MHz ISM"]

        bands = []

        for band in plan_bands:
            entry = dict(band)
            entry.setdefault("dwell_s", self.dwell_s)
            bands.append(entry)

        return self._normalize_bands(bands)

    def _resolve_blacklist(self) -> List[Dict[str, float]]:
        if not self.blacklist_json:
            return []

        parsed = self._parse_json_list(
            self.blacklist_json,
            "blacklist_json",
        )

        return self._normalize_blacklist(parsed)

    def _parse_json_list(self, text: str, label: str) -> List[Dict[str, Any]]:
        try:
            parsed = json.loads(text)
        except Exception:
            self.logger.exception(f"[SCAN] Could not parse {label}")
            return []

        if not isinstance(parsed, list):
            self.logger.warning(f"[SCAN] {label} must be a JSON list")
            return []

        return parsed

    def _normalize_bands(
        self,
        bands: List[Dict[str, Any]],
    ) -> List[Dict[str, float]]:
        normalized = []

        for band in bands:
            if not isinstance(band, dict):
                continue

            start_mhz = self._float(
                band.get("start_mhz", band.get("start", band.get("low_mhz"))),
                None,
            )
            end_mhz = self._float(
                band.get("end_mhz", band.get("end", band.get("high_mhz"))),
                None,
            )
            step_mhz = self._float(
                band.get("step_mhz", band.get("step", self.custom_step_mhz)),
                self.custom_step_mhz,
            )
            dwell_s = self._float(
                band.get("dwell_s", self.dwell_s),
                self.dwell_s,
            )

            if start_mhz is None or end_mhz is None:
                continue

            if end_mhz < start_mhz:
                start_mhz, end_mhz = end_mhz, start_mhz

            step_mhz = max(0.001, step_mhz)
            dwell_s = max(0.1, dwell_s)

            normalized.append(
                {
                    "start_mhz": float(start_mhz),
                    "end_mhz": float(end_mhz),
                    "step_mhz": float(step_mhz),
                    "dwell_s": float(dwell_s),
                }
            )

        return normalized

    def _normalize_blacklist(
        self,
        blacklist: List[Dict[str, Any]],
    ) -> List[Dict[str, float]]:
        normalized = []

        for entry in blacklist:
            if not isinstance(entry, dict):
                continue

            start_mhz = self._float(
                entry.get("start_mhz", entry.get("start", entry.get("low_mhz"))),
                None,
            )
            end_mhz = self._float(
                entry.get("end_mhz", entry.get("end", entry.get("high_mhz"))),
                None,
            )

            if start_mhz is None or end_mhz is None:
                continue

            if end_mhz < start_mhz:
                start_mhz, end_mhz = end_mhz, start_mhz

            normalized.append(
                {
                    "start_mhz": float(start_mhz),
                    "end_mhz": float(end_mhz),
                }
            )

        return normalized

    def _build_scan_frequencies_hz(
        self,
        bands: List[Dict[str, float]],
        blacklist: List[Dict[str, float]],
    ) -> List[float]:
        freqs_mhz = []

        for band in bands:
            start_mhz = float(band["start_mhz"])
            end_mhz = float(band["end_mhz"])
            step_mhz = max(0.001, float(band["step_mhz"]))

            current_mhz = start_mhz

            # Include the end point with a small tolerance.
            while current_mhz <= end_mhz + (step_mhz * 0.001):
                rounded_mhz = round(current_mhz, 6)

                if not self._frequency_is_blacklisted(
                    rounded_mhz,
                    blacklist,
                ):
                    freqs_mhz.append(rounded_mhz)

                current_mhz += step_mhz

        unique_sorted_mhz = sorted(set(freqs_mhz))

        return [freq_mhz * 1_000_000.0 for freq_mhz in unique_sorted_mhz]

    def _frequency_is_blacklisted(
        self,
        freq_mhz: float,
        blacklist: List[Dict[str, float]],
    ) -> bool:
        for entry in blacklist:
            if (
                float(entry["start_mhz"])
                <= freq_mhz
                <= float(entry["end_mhz"])
            ):
                return True

        return False

    @staticmethod
    def _float(value, default: Optional[float]) -> Optional[float]:
        try:
            return float(value)
        except Exception:
            if default is None:
                return None
            return float(default)


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test

    run_test(OperationMain, {}, {})