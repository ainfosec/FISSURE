#! /usr/bin/env python3
"""b205_geo_target.py

B205 RSSI/power geolocation target operation.

This operation:
- Tracks one or more RF frequencies with a B205/B2xx UHD receiver.
- Reads GPSD position updates for this sensor node.
- Computes relative RSSI/power measurements from received IQ.
- Uses the fissure_geo helper library for path-loss multilateration.
- Emits target updates suitable for the Tactical tab / TAK target workflow.

Parameters are read from ``self.parameters`` when provided.
"""

import asyncio
import inspect
import json
import logging
import math
import os
import sys
import tempfile
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Union

import numpy as np

# -----------------------------------------------------------------------------
# Plugin/repo bootstrap
# -----------------------------------------------------------------------------

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))
OPERATIONS_DIR = os.path.dirname(__file__)

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT, OPERATIONS_DIR):
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
    if OPERATIONS_DIR not in sys.path:
        sys.path.insert(0, OPERATIONS_DIR)

    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT

from fissure_geo import PathLossModel, MultilaterationEstimator
from fissure_geo import estimate_ce_from_samples


# -----------------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------------

def _json_default(value: Any) -> Any:
    """JSON serializer for numpy scalars and other simple non-JSON values."""
    if isinstance(value, np.generic):
        return value.item()
    return str(value)


class OperationMain(Operation):
    def __init__(
        self,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        status_callback: Union[Callable, None] = None,
        target_callback: Union[Callable, None] = None,
        artifact_manager=None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            status_callback=status_callback,
            target_callback=target_callback,
            artifact_manager=artifact_manager,
        )

        self._gps_stop = asyncio.Event()
        self._current_position: Dict[str, Any] = {"lat": None, "lon": None, "alt": 0.0}

        self.gpsd_host = "127.0.0.1"
        self.gpsd_port = 2947
        self.gps_refresh_interval = 3.0
        self.opid = str(getattr(self, "opid", "") or uuid.uuid4())

    # ------------------------------------------------------------------
    # Compatibility/callback helpers
    # ------------------------------------------------------------------
    def _should_stop(self) -> bool:
        if getattr(self, "_stop", False):
            return True
        ev = getattr(self, "stop_event", None)
        if ev is not None:
            try:
                return ev.is_set()
            except Exception:
                pass
        return False

    async def _maybe_await(self, result: Any) -> Any:
        if inspect.isawaitable(result):
            return await result
        return result

    async def _call_callback(self, name: str, callback: Optional[Callable], *args: Any, **kwargs: Any) -> Any:
        if not callback:
            return None
        try:
            return await asyncio.wait_for(self._maybe_await(callback(*args, **kwargs)), timeout=2.0)
        except TypeError:
            # Some operation runners wire callbacks as callback(dict) rather than kwargs.
            if kwargs and not args:
                try:
                    return await asyncio.wait_for(self._maybe_await(callback(kwargs)), timeout=2.0)
                except Exception:
                    self.logger.exception("%s failed", name)
                    return None
            self.logger.exception("%s failed", name)
            return None
        except asyncio.TimeoutError:
            self.logger.warning("%s timed out", name)
            return None
        except Exception:
            self.logger.exception("%s failed", name)
            return None

    async def _set_status(self, text: str) -> None:
        await self._call_callback("status_callback", getattr(self, "status_callback", None), text)

    async def _emit_target_update(self, **kwargs: Any) -> None:
        await self._call_callback("target_callback", getattr(self, "target_callback", None), **kwargs)

    async def _emit_tak_cot(self, payload: Dict[str, Any]) -> None:
        await self._call_callback("tak_cot_callback", getattr(self, "tak_cot_callback", None), payload)

    async def _emit_alert(self, payload: Dict[str, Any]) -> None:
        await self._call_callback("alert_callback", getattr(self, "alert_callback", None), payload)

    def _now_iso(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _source_id(self, params: Dict[str, Any]) -> str:
        return str(params.get("source_id") or self.node_uid or "sensor_node")

    def _parse_freqs_hz(self, params: Dict[str, Any]) -> List[float]:
        freqs: List[float] = []
        if isinstance(params.get("freqs_hz"), (list, tuple)):
            freqs.extend([float(x) for x in params["freqs_hz"]])
        if isinstance(params.get("freqs_mhz"), (list, tuple)):
            freqs.extend([float(x) * 1e6 for x in params["freqs_mhz"]])
        if "freq_hz" in params:
            freqs.append(float(params["freq_hz"]))
        if "frequency_mhz" in params:
            freqs.append(float(params["frequency_mhz"]) * 1e6)
        if not freqs:
            # Safe test default so RX still starts if the caller forgot frequency.
            freqs = [915e6]
        return sorted({float(f) for f in freqs})

    # ------------------------------------------------------------------
    # GPSD loop
    # ------------------------------------------------------------------
    async def _gps_loop(self) -> None:
        self.logger.info("Starting GPS loop (GPSD)")
        last = 0.0
        buf = ""

        while (not self._should_stop()) and (not self._gps_stop.is_set()):
            writer = None
            try:
                reader, writer = await asyncio.open_connection(self.gpsd_host, self.gpsd_port)
                writer.write(b'?WATCH={"enable":true,"json":true}\n')
                await writer.drain()

                while (not self._should_stop()) and (not self._gps_stop.is_set()):
                    data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
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
                                self._current_position.update(
                                    {"lat": float(lat), "lon": float(lon), "alt": float(alt or 0.0)}
                                )
                                now = time.time()
                                if (now - last) >= float(self.gps_refresh_interval):
                                    last = now

            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.logger.warning("GPS error: %s", exc)
                await asyncio.sleep(2.0)
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

        self.logger.info("GPS loop exited")

    async def _gps_fallback_check(self, fallback_position: Optional[Dict[str, Any]]) -> None:
        if not fallback_position:
            return
        await asyncio.sleep(1.0)
        if self._current_position.get("lat") is None:
            self.logger.warning("GPS unavailable. Using fallback coordinates.")
            self._current_position.update(
                {
                    "lat": float(fallback_position.get("lat", 40.712776)),
                    "lon": float(fallback_position.get("lon", -74.005974)),
                    "alt": float(fallback_position.get("alt", 10.5)),
                }
            )

    # ------------------------------------------------------------------
    # UHD/geolocation helpers
    # ------------------------------------------------------------------
    def _power_dbfs(self, iq: np.ndarray) -> float:
        p = float(np.mean(np.abs(iq) ** 2))
        p = max(p, 1e-12)
        return 10.0 * math.log10(p)

    def _detect_peak_offset_hz(
        self,
        iq: np.ndarray,
        sample_rate: float,
        *,
        fft_size: int = 4096,
        peak_snr_db: float = 10.0,
        max_offset_hz: Optional[float] = None,
    ) -> Optional[float]:
        if iq.size < 64:
            return None

        sr = float(sample_rate)
        if sr <= 0:
            return None

        n = min(int(fft_size), int(iq.size))
        if n < 256:
            n = int(iq.size)

        x = np.asarray(iq[:n], dtype=np.complex64)
        w = np.hanning(n).astype(np.float32)
        spec = np.fft.fftshift(np.fft.fft(x * w))
        pwr = (spec.real * spec.real) + (spec.imag * spec.imag)

        noise = max(float(np.median(pwr)), 1e-12)
        peak_idx = int(np.argmax(pwr))
        peak = max(float(pwr[peak_idx]), 1e-12)

        snr_db = 10.0 * math.log10(peak / noise)
        if snr_db < float(peak_snr_db):
            return None

        freqs = np.fft.fftshift(np.fft.fftfreq(n, d=1.0 / sr))
        offset = float(freqs[peak_idx])

        if max_offset_hz is None:
            max_offset_hz = 0.49 * sr
        max_off = float(abs(max_offset_hz))
        if max_off > 0:
            offset = float(np.clip(offset, -max_off, max_off))

        return offset

    def _uhd_open(self, uhd_args: str, rate: float, gain: float, antenna: str):
        try:
            import uhd  # type: ignore
        except Exception:
            try:
                import pyuhd as uhd  # type: ignore
            except Exception as exc:
                raise RuntimeError(
                    "UHD python bindings not found (uhd/pyuhd). Install python UHD bindings or adapt to SoapySDR."
                ) from exc

        usrp = uhd.usrp.MultiUSRP(uhd_args)
        usrp.set_rx_rate(rate, 0)
        usrp.set_rx_gain(gain, 0)
        usrp.set_rx_antenna(antenna, 0)

        stream_args = uhd.usrp.StreamArgs("fc32", "sc16")
        streamer = usrp.get_rx_stream(stream_args)
        metadata = uhd.types.RXMetadata()

        cmd = uhd.types.StreamCMD(uhd.types.StreamMode.start_cont)
        cmd.stream_now = True
        streamer.issue_stream_cmd(cmd)

        return uhd, usrp, streamer, metadata

    def _stable_target_id_for_freq(self, freq_hz: float) -> str:
        return f"emitter-{int(freq_hz)}"

    def _write_local_evidence(
        self,
        *,
        operation_id: str,
        target_id: str,
        freq_hz: float,
        snapshot: Dict[str, Any],
    ) -> str:
        if self.artifact_manager:
            _, evidence_dir = self.artifact_manager.create_operation_dir(operation_id)
        else:
            evidence_dir = os.path.join(FISSURE_ROOT, "artifacts", operation_id, "files")
            os.makedirs(evidence_dir, exist_ok=True)
        path = os.path.join(evidence_dir, "b205_geo_evidence.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(snapshot, handle, indent=2, default=_json_default)
        return evidence_dir

    def _make_artifact(
        self,
        *,
        source_id: str,
        operation_id: str,
        target_id: str,
        freq_hz: float,
        snapshot: Dict[str, Any],
    ) -> str:
        evidence_dir = tempfile.mkdtemp(prefix="b205_geo_")
        with open(os.path.join(evidence_dir, "evidence.json"), "w", encoding="utf-8") as handle:
            json.dump(snapshot, handle, indent=2, default=_json_default)

        if not self.artifact_manager:
            self._write_local_evidence(
                operation_id=operation_id,
                target_id=target_id,
                freq_hz=freq_hz,
                snapshot=snapshot,
            )
            return operation_id

        try:
            artifact = self.artifact_manager.create_zip_artifact_from_folder(
                source_id=source_id,
                operation_id=operation_id,
                folder=evidence_dir,
                name=f"B205 Geo evidence @ {freq_hz / 1e6:.3f} MHz",
                metadata={
                    "kind": "artifact",
                    "event_type": "target_evidence",
                    "role": "target_evidence_b205_geo",
                    "node_uid": self.node_uid,
                    "source_id": source_id,
                    "target_id": target_id,
                    "frequency_hz": float(freq_hz),
                    "frequency_mhz": float(freq_hz / 1e6),
                    "operation_id": operation_id,
                },
                arc_prefix=f"target_{operation_id}",
            )
            return str(getattr(artifact, "id", artifact) if artifact else "")
        except Exception as exc:
            self.logger.exception("Failed creating artifact: %s", exc)
            self._write_local_evidence(
                operation_id=operation_id,
                target_id=target_id,
                freq_hz=freq_hz,
                snapshot=snapshot,
            )
            return operation_id

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------
    async def run(self) -> None:
        params: Dict[str, Any] = getattr(self, "parameters", {}) or {}
        source_id = self._source_id(params)

        gps_task: Optional[asyncio.Task] = None
        fallback_task: Optional[asyncio.Task] = None
        uhd = None
        streamer = None
        stream_cmd_issued = False

        try:
            if not self.target_callback:
                raise RuntimeError("b205_geo_target requires target_callback to be wired")

            self.gpsd_host = str(params.get("gpsd_host", self.gpsd_host))
            self.gpsd_port = int(params.get("gpsd_port", self.gpsd_port))
            self.gps_refresh_interval = float(params.get("gps_refresh_interval", self.gps_refresh_interval))

            uhd_args = str(params.get("uhd_args", "type=b200"))
            rate = float(params.get("sample_rate", 1e6))
            gain = float(params.get("gain_db", 60.0))
            antenna = str(params.get("antenna", "TX/RX"))
            n_samp = int(params.get("n_samp", 131072))
            rf_interval_s = float(params.get("rf_interval_s", 0.0))

            meas_every_s = float(params.get("meas_every_s", 0.20))
            ce_every_s = float(params.get("ce_every_s", 6.0))
            ce_max_samples = int(params.get("ce_max_samples", 30))
            dwell_s = float(params.get("dwell_s", 1.5))
            detect_frequency = bool(params.get("detect_frequency", True))
            fft_size = int(params.get("fft_size", 8192))
            peak_snr_db = float(params.get("peak_snr_db", 15.0))
            max_offset_hz_param = params.get("max_offset_hz", 200e3)
            max_offset_hz = float(max_offset_hz_param) if max_offset_hz_param is not None else None

            pathloss_n = float(params.get("pathloss_n", 2.4))
            p0_db = float(params.get("p0_db", -20.0))
            auto_cal = bool(params.get("auto_calibrate", True))
            d_ref_m = float(params.get("d_ref_m", 30.0))
            cal_min_samples = int(params.get("cal_min_samples", 20))
            max_samples = int(params.get("max_samples", 80))
            smooth_alpha = float(params.get("smooth_alpha", 0.35))

            emit_every_s = float(params.get("emit_every_s", 1.0))
            ce_m_default = float(params.get("ce_m", 75.0))
            ce_confidence = float(params.get("ce_confidence", 0.90))
            display_label_prefix = str(params.get("display_label_prefix", "Emitter"))
            source_soi_id = str(params.get("source_soi_id", "") or "")
            emit_tak_cot = bool(params.get("emit_tak_cot", False))
            emit_alerts = bool(params.get("emit_alerts", False))

            fallback_position = params.get("fallback_position")
            if fallback_position is None and bool(params.get("use_gps_fallback", True)):
                fallback_position = {"lat": 40.712776, "lon": -74.005974, "alt": 10.5}

            freqs_hz = self._parse_freqs_hz(params)
            await self._set_status(f"Running: B205 Geo ({len(freqs_hz)} freqs)")

            if not self.artifact_manager:
                self.logger.warning("artifact_manager not provided; using operation_id as local artifact_id fallback")

            gps_task = asyncio.create_task(self._gps_loop())
            fallback_task = asyncio.create_task(self._gps_fallback_check(fallback_position))

            uhd, usrp, streamer, md = self._uhd_open(uhd_args, rate, gain, antenna)
            stream_cmd_issued = True
            buf = np.empty(n_samp, dtype=np.complex64)

            per_freq: Dict[float, Dict[str, Any]] = {}
            for freq_hz in freqs_hz:
                model = PathLossModel(n=pathloss_n, p0_db=p0_db)
                est = MultilaterationEstimator(smooth_alpha=smooth_alpha, max_samples=max_samples)
                operation_id = str(uuid.uuid4())
                per_freq[freq_hz] = {
                    "model": model,
                    "est": est,
                    "target_id": self._stable_target_id_for_freq(freq_hz),
                    "last_emit": 0.0,
                    "last_meas": 0.0,
                    "last_ce": 0.0,
                    "ce_cached": float(ce_m_default),
                    "detected_freq_hz": None,
                    "last_freq_det": 0.0,
                    "artifact_id": "",
                    "operation_id": operation_id,
                }

            while not self._should_stop():
                for freq_hz in freqs_hz:
                    if self._should_stop():
                        break

                    try:
                        usrp.set_rx_freq(uhd.types.TuneRequest(float(freq_hz)), 0)
                    except Exception as exc:
                        self.logger.warning("Tune failed for %.3f Hz: %s", freq_hz, exc)
                        await asyncio.sleep(0.1)
                        continue

                    t0 = time.time()
                    while not self._should_stop() and (time.time() - t0) < dwell_s:
                        n = int(streamer.recv(buf, md, timeout=1.0) or 0)
                        if n <= 0:
                            try:
                                if md.error_code != uhd.types.RXMetadataErrorCode.none:
                                    self.logger.warning("RXMetadata error: %s", md.strerror())
                            except Exception:
                                pass
                            await asyncio.sleep(0.01)
                            continue

                        lat = self._current_position.get("lat")
                        lon = self._current_position.get("lon")
                        alt = self._current_position.get("alt", 0.0)

                        st = per_freq[freq_hz]
                        model: PathLossModel = st["model"]
                        est: MultilaterationEstimator = st["est"]
                        now = time.time()

                        if (lat is not None) and (lon is not None) and ((now - st["last_meas"]) >= meas_every_s):
                            p_dbfs = self._power_dbfs(buf[:n])

                            if detect_frequency and ((now - st["last_freq_det"]) >= max(0.2, meas_every_s)):
                                try:
                                    offset = self._detect_peak_offset_hz(
                                        buf[:n],
                                        rate,
                                        fft_size=fft_size,
                                        peak_snr_db=peak_snr_db,
                                        max_offset_hz=max_offset_hz,
                                    )
                                    if offset is not None:
                                        st["detected_freq_hz"] = float(freq_hz + offset)
                                except Exception:
                                    self.logger.exception("Frequency detection failed")
                                finally:
                                    st["last_freq_det"] = now

                            est.add_measurement(
                                lat=float(lat),
                                lon=float(lon),
                                rssi_db=float(p_dbfs),
                                t=now,
                                model=model,
                                auto_calibrate=auto_cal,
                                d_ref_m=d_ref_m,
                                cal_min_samples=cal_min_samples,
                            )
                            st["last_meas"] = now

                        if est.ready and (lat is not None) and (lon is not None) and ((now - st["last_emit"]) >= emit_every_s):
                            out_latlon = est.estimate_latlon(model)
                            if out_latlon is None:
                                await asyncio.sleep(0)
                                continue

                            est_lat, est_lon = out_latlon

                            if (now - st["last_ce"]) >= ce_every_s:
                                try:
                                    samples_ref = getattr(est, "_samples", None)
                                    if samples_ref is None:
                                        samples_ref = est.samples
                                    ce_calc = estimate_ce_from_samples(
                                        samples_ref[-ce_max_samples:],
                                        model,
                                        confidence=ce_confidence,
                                    )
                                    if ce_calc is not None:
                                        st["ce_cached"] = float(ce_calc)
                                except Exception:
                                    self.logger.exception("CE calculation failed")
                                finally:
                                    st["last_ce"] = now

                            ce_m = float(st.get("ce_cached", ce_m_default)) if st.get("ce_cached") is not None else float(ce_m_default)
                            detected_freq_hz = float(st.get("detected_freq_hz") or freq_hz)
                            now_iso = self._now_iso()
                            target_id = st["target_id"]
                            operation_id = st["operation_id"]
                            display_label = f"{display_label_prefix} @ {detected_freq_hz / 1e6:.3f} MHz"

                            samples_ref = getattr(est, "_samples", None)
                            if samples_ref is None:
                                samples_ref = est.samples
                            recent = samples_ref[-min(50, len(samples_ref)) :]

                            classification = {
                                "display_label": display_label,
                                "candidates": [
                                    {"source": "radio", "label": "B205", "frequency_hz": detected_freq_hz},
                                    {"source": "model", "label": "RSSI multilateration", "confidence": 0.6},
                                ],
                            }

                            location = {
                                "lat": float(est_lat),
                                "lon": float(est_lon),
                                "hae_m": float(alt or 0.0),
                                "ce_m": float(ce_m),
                                "detected_frequency_hz": detected_freq_hz,
                                "timestamp": now_iso,
                                "source": "b205_geo_target",
                            }

                            snapshot = {
                                "kind": "target",
                                "event_type": "b205_geo_update",
                                "node_uid": self.node_uid,
                                "source_id": source_id,
                                "target_id": target_id,
                                "source_soi_id": source_soi_id,
                                "operation_id": operation_id,
                                "frequency_hz": detected_freq_hz,
                                "frequency_mhz": float(detected_freq_hz / 1e6),
                                "created_time": now_iso,
                                "classification": classification,
                                "location": location,
                                "model": {
                                    "n": float(model.n),
                                    "p0_db": float(model.p0_db),
                                    "auto_calibrate": auto_cal,
                                    "d_ref_m": d_ref_m,
                                    "ce_confidence": float(ce_confidence),
                                },
                                "estimate": {
                                    "lat": float(est_lat),
                                    "lon": float(est_lon),
                                    "ce_m": float(ce_m),
                                },
                                "samples": [
                                    {"lat": s.lat, "lon": s.lon, "rssi_db": s.rssi_db, "t": s.t}
                                    for s in recent
                                ],
                            }

                            artifact_id = st["artifact_id"]
                            if not artifact_id:
                                artifact_id = self._make_artifact(
                                    source_id=source_id,
                                    operation_id=operation_id,
                                    target_id=target_id,
                                    freq_hz=detected_freq_hz,
                                    snapshot=snapshot,
                                )
                                st["artifact_id"] = artifact_id
                            snapshot["artifact_id"] = artifact_id

                            target_payload = {
                                "kind": "target",
                                "event_type": "b205_geo_update",
                                "node_uid": self.node_uid,
                                "source_id": source_id,
                                "target_id": target_id,
                                "source_soi_id": source_soi_id,
                                "frequency_mhz": float(detected_freq_hz / 1e6),
                                "frequency_hz": detected_freq_hz,
                                "state": "tracking",
                                "artifact_id": artifact_id,
                                "classification": classification,
                                "location": location,
                                "history_entry": {
                                    "event": "b205_geo_update",
                                    "artifact_id": artifact_id,
                                    "operation_id": operation_id,
                                    "frequency_hz": detected_freq_hz,
                                },
                                "summary": {
                                    "stage": "tracking",
                                    "stage_order": 20,
                                    "frequency_hz": detected_freq_hz,
                                    "samples": len(samples_ref),
                                    "p0_db": float(model.p0_db),
                                    "n": float(model.n),
                                    "ce_m": float(ce_m),
                                    "detected_frequency_hz": detected_freq_hz,
                                },
                                "lat": float(est_lat),
                                "lon": float(est_lon),
                                "alt": float(alt or 0.0),
                                "observation_time": True,
                            }

                            await self._emit_target_update(**target_payload)

                            if emit_tak_cot:
                                await self._emit_tak_cot(dict(target_payload))

                            if emit_alerts:
                                alert_payload = {
                                    "kind": "alert",
                                    "event_type": "b205_geo_target",
                                    "node_uid": self.node_uid,
                                    "source_id": source_id,
                                    "target_id": target_id,
                                    "artifact_id": artifact_id,
                                    "message": display_label,
                                    "frequency_hz": detected_freq_hz,
                                    "lat": float(est_lat),
                                    "lon": float(est_lon),
                                    "alt": float(alt or 0.0),
                                    "timestamp": now_iso,
                                }
                                await self._emit_alert(alert_payload)

                            st["last_emit"] = now

                        await asyncio.sleep(0) if rf_interval_s <= 0 else await asyncio.sleep(rf_interval_s)

                await asyncio.sleep(0.01)

        finally:
            self._gps_stop.set()

            if fallback_task is not None:
                fallback_task.cancel()
                try:
                    await fallback_task
                except asyncio.CancelledError:
                    pass
                except Exception:
                    self.logger.exception("GPS fallback task cleanup failed")

            if gps_task is not None:
                gps_task.cancel()
                try:
                    await gps_task
                except asyncio.CancelledError:
                    pass
                except Exception:
                    self.logger.exception("GPS task cleanup failed")

            if stream_cmd_issued and uhd is not None and streamer is not None:
                try:
                    cmd = uhd.types.StreamCMD(uhd.types.StreamMode.stop_cont)
                    cmd.stream_now = True
                    streamer.issue_stream_cmd(cmd)
                except Exception:
                    self.logger.exception("Failed to stop UHD stream")

            await self._set_status("Idle")
            self.logger.info("B205 Geo operation stopped/complete.")


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test

    run_test(OperationMain, {}, {})