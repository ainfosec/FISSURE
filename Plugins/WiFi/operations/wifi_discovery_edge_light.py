#!/usr/bin/env python3
"""
FISSURE – Dual-Band Passive Wi-Fi Discovery / Edge Geolocation (Light/Rural)
----------------------------------------------------------------------------
This version is intended for lighter-volume environments.

Behavior:
- Creates targets for discovered Wi-Fi APs after a minimum sample count
- Does NOT create artifacts
- Sends one alert per newly created Wi-Fi target via alert_callback
- Does NOT send separate TAK alert pins
"""

import os
import sys
import csv
import glob
import time
import math
import json
import asyncio
import subprocess
import signal
import logging
import inspect
import shutil
from dataclasses import dataclass
from typing import Dict, Tuple, Optional, List, Any, Callable, Union

import numpy as np

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))
SCRIPTS_DIR = os.path.join(PLUGIN_ROOT, "scripts")
WIFI_LIB_DIR = os.path.join(SCRIPTS_DIR, "wifi_lib")
RESOURCES_DIR = os.path.join(PLUGIN_ROOT, "resources")

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT, SCRIPTS_DIR, WIFI_LIB_DIR):
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

    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT


MON_SUFFIX_DEFAULT = "mon"
DEFAULT_LOG_DIR = os.path.join(FISSURE_ROOT, "logs", "plugins", "WiFi")
CALLBACK_TIMEOUT_S = 2.0


@dataclass
class Sample:
    lat: float
    lon: float
    rssi: float


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
        parameters: Optional[Dict[str, Any]] = None,
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
        self.parameters: Dict[str, Any] = parameters or {}
        self.source_id: str = str(node_uid or "").strip() or "sensor_node"

        self.wifi_interface: str = "wlx00c0caa744fc"
        self.mon_suffix: str = MON_SUFFIX_DEFAULT

        self.airo_prefix: str = "/tmp/airodump"
        self.airo_csv_glob: str = self.airo_prefix + "-*.csv"

        self.gpsd_host: str = "127.0.0.1"
        self.gpsd_port: int = 2947
        self.gps_refresh_interval: float = 3.0
        self.wifi_refresh_interval: float = 0.5

        self.smooth_alpha: float = 0.3
        self.calibration_period: float = 3.0

        self.p_tx_ref: float = -45.0
        self.n_min: float = 2.2
        self.n_max: float = 3.8
        self.lna_gain_min: float = 0.0
        self.lna_gain_max: float = 30.0
        self.rssi_ref_target: float = -60.0
        self.calibration_smooth: float = 0.4
        self.lna_gain_db: float = 20.0

        self.log_dir: str = DEFAULT_LOG_DIR
        os.makedirs(self.log_dir, exist_ok=True)
        self.gain_store: str = os.path.join(self.log_dir, "lna_gain_store.json")

        self.ce_min_m: float = 10.0
        self.ce_max_m: float = 250.0
        self.ce_smooth_alpha: float = 0.35

        self.min_samples_before_target: int = 3
        self.alert_on_new_target: bool = True

        self._gps_stop = asyncio.Event()
        self._current_position = {"lat": None, "lon": None, "alt": 0.0}

        self._airodump_proc: Optional[asyncio.subprocess.Process] = None
        self._airodump_iface_in_use: Optional[str] = None

        self._ap_db: Dict[str, Dict[str, Any]] = {}
        self._last_cal = 0.0

    def _apply_parameters_from_runner(self) -> None:
        p = getattr(self, "parameters", None)
        self.logger.info(f"_apply_parameters_from_runner self.parameters={p!r} type={type(p)}")

        if not isinstance(p, dict):
            return

        self.wifi_interface = str(p.get("wifi_interface", self.wifi_interface) or self.wifi_interface)
        self.mon_suffix = str(p.get("mon_suffix", self.mon_suffix) or self.mon_suffix)
        self.source_id = str(p.get("source_id", self.source_id) or self.source_id or self.node_uid or "sensor_node")

        self.airo_prefix = p.get("airo_prefix", self.airo_prefix)
        self.airo_csv_glob = self.airo_prefix + "-*.csv"

        self.gpsd_host = p.get("gpsd_host", self.gpsd_host)
        self.gpsd_port = int(p.get("gpsd_port", self.gpsd_port))
        self.gps_refresh_interval = float(p.get("gps_refresh_interval", self.gps_refresh_interval))
        self.wifi_refresh_interval = float(p.get("wifi_refresh_interval", self.wifi_refresh_interval))

        self.smooth_alpha = float(p.get("smooth_alpha", self.smooth_alpha))
        self.calibration_period = float(p.get("calibration_period", self.calibration_period))

        self.p_tx_ref = float(p.get("p_tx_ref", self.p_tx_ref))
        self.n_min = float(p.get("n_min", self.n_min))
        self.n_max = float(p.get("n_max", self.n_max))
        self.lna_gain_min = float(p.get("lna_gain_min", self.lna_gain_min))
        self.lna_gain_max = float(p.get("lna_gain_max", self.lna_gain_max))
        self.rssi_ref_target = float(p.get("rssi_ref_target", self.rssi_ref_target))
        self.calibration_smooth = float(p.get("calibration_smooth", self.calibration_smooth))
        self.lna_gain_db = float(p.get("lna_gain_db", self.lna_gain_db))

        self.log_dir = p.get("log_dir", self.log_dir)
        os.makedirs(self.log_dir, exist_ok=True)
        self.gain_store = p.get("gain_store", os.path.join(self.log_dir, "lna_gain_store.json"))

        self.ce_min_m = float(p.get("ce_min_m", self.ce_min_m))
        self.ce_max_m = float(p.get("ce_max_m", self.ce_max_m))
        self.ce_smooth_alpha = float(p.get("ce_smooth_alpha", self.ce_smooth_alpha))

        self.min_samples_before_target = int(p.get("min_samples_before_target", self.min_samples_before_target))
        self.alert_on_new_target = self._as_bool(p.get("alert_on_new_target", self.alert_on_new_target), self.alert_on_new_target)

        self.resource_args = {"wifi_interface": self.wifi_interface}

    @staticmethod
    def get_resources(dev: str = "") -> Dict[str, Any]:
        return {
            "usrp": {
                "type": "Alfa",
                "model": "",
                "serial": dev,
                "description": "Alfa Card",
                "required": True,
            }
        }

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

    @staticmethod
    def _as_bool(value: Any, default: bool = False) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)

        text = str(value).strip().lower()
        if text in {"1", "true", "t", "yes", "y", "on"}:
            return True
        if text in {"0", "false", "f", "no", "n", "off"}:
            return False
        return default

    async def _maybe_await(self, result):
        if inspect.isawaitable(result):
            return await result
        return result

    async def _call_callback(self, callback: Callable, *args, timeout: float = CALLBACK_TIMEOUT_S, **kwargs):
        result = callback(*args, **kwargs)
        if inspect.isawaitable(result):
            return await asyncio.wait_for(result, timeout=timeout)
        return result

    async def _emit_status(self, message: str) -> None:
        if not self.status_callback:
            return
        try:
            await self._call_callback(self.status_callback, message)
        except Exception:
            self.logger.exception("status_callback failed")

    async def _emit_target_patch(
        self,
        target_id: str,
        patch: dict,
        history_entry: Optional[dict] = None,
        artifact_id: str = "",
    ) -> None:
        cb = self.target_callback
        if not cb:
            return

        history = history_entry or {}
        history.setdefault("node_uid", self.node_uid)
        history.setdefault("source_id", self.source_id)
        history.setdefault("kind", "target")
        history.setdefault("event_type", "target")

        try:
            await self._call_callback(
                cb,
                target_id=target_id,
                patch=patch,
                history_entry=history,
                artifact_id=artifact_id or "",
                node_uid=self.node_uid,
                source_id=self.source_id,
                kind="target",
                event_type="target",
            )
            return
        except TypeError as e:
            self.logger.warning(f"target_callback keyword call failed: {e}")
        except Exception as e:
            self.logger.warning(f"target_callback keyword emit failed: {e}")

        try:
            await self._call_callback(
                cb,
                {
                    "target_id": target_id,
                    "patch": patch,
                    "history_entry": history,
                    "artifact_id": artifact_id or "",
                    "node_uid": self.node_uid,
                    "source_id": self.source_id,
                    "kind": "target",
                    "event_type": "target",
                },
            )
        except Exception as e:
            self.logger.error(f"target_callback patch emit failed: {e}")
            raise

    async def _emit_alert(
        self,
        message: str,
        uid: str = "",
        alert_kind: str = "wifi_discovery_edge_light",
        alert_summary: str = "",
        lat: Optional[float] = None,
        lon: Optional[float] = None,
        alt: Optional[float] = None,
        remarks_extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not self.alert_callback:
            return

        alert_payload = {
            "uid": uid or f"wifi-alert-{int(time.time() * 1000)}",
            "alert_kind": alert_kind,
            "alert_summary": alert_summary or message,
            "message": message,
            "node_uid": self.node_uid,
            "source_id": self.source_id,
            "operation_id": self.opid,
            "opid": self.opid,
            "plot_pin": False,
        }

        if lat is not None:
            alert_payload["lat"] = float(lat)
        if lon is not None:
            alert_payload["lon"] = float(lon)
        if alt is not None:
            alert_payload["alt"] = float(alt)
        if remarks_extra:
            alert_payload.update(remarks_extra)

        try:
            await self._call_callback(self.alert_callback, alert_payload)
        except Exception as e:
            self.logger.warning(f"alert_callback failed: {e}")

    def _load_gain(self) -> None:
        try:
            if os.path.exists(self.gain_store):
                with open(self.gain_store, "r") as f:
                    data = json.load(f)
                if self.wifi_interface in data:
                    self.lna_gain_db = float(data[self.wifi_interface])
                    self.logger.info(f"Loaded LNA gain {self.lna_gain_db:.1f} dB")
        except Exception as e:
            self.logger.warning(f"Gain load failed: {e}")

    def _save_gain(self) -> None:
        try:
            data = {}
            if os.path.exists(self.gain_store):
                with open(self.gain_store, "r") as f:
                    data = json.load(f)

            data[self.wifi_interface] = round(self.lna_gain_db, 2)
            with open(self.gain_store, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Gain save failed: {e}")

    @staticmethod
    def _latlon_to_xy(lat, lon, lat0, lon0) -> Tuple[float, float]:
        R = 6371000.0
        lat_r, lon_r, lat0_r, lon0_r = map(math.radians, [lat, lon, lat0, lon0])
        x = (lon_r - lon0_r) * math.cos((lat_r + lat0_r) / 2) * R
        y = (lat_r - lat0_r) * R
        return x, y

    @staticmethod
    def _xy_to_latlon(x, y, lat0, lon0) -> Tuple[float, float]:
        R = 6371000.0
        lat0_r, lon0_r = math.radians(lat0), math.radians(lon0)
        lat_r = y / R + lat0_r
        lon_r = x / (R * math.cos((lat_r + lat0_r) / 2)) + lon0_r
        return math.degrees(lat_r), math.degrees(lon_r)

    def _distance_m(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        x, y = self._latlon_to_xy(lat2, lon2, lat1, lon1)
        return float(math.hypot(x, y))

    def _compute_ce_le(self, samples: List[Sample], est_lat: float, est_lon: float) -> Tuple[float, float]:
        n_s = len(samples)
        if n_s < 3:
            return float(self.ce_max_m), float(self.ce_max_m)

        d_geo = np.array([self._distance_m(est_lat, est_lon, s.lat, s.lon) for s in samples], dtype=float)
        med = float(np.median(d_geo))
        mad = float(np.median(np.abs(d_geo - med)))
        sigma_geo = 1.4826 * mad

        n = self._adaptive_n(samples)
        d_model = np.array([self._estimate_distance(s.rssi, n) for s in samples], dtype=float)
        resid = d_geo - d_model
        rms_resid = float(np.sqrt(np.mean(resid * resid)))

        base = max(sigma_geo * 2.0, rms_resid)
        shrink = math.sqrt(max(1.0, n_s / 3.0))
        ce = base / shrink
        ce = float(np.clip(ce, self.ce_min_m, self.ce_max_m))
        le = float(np.clip(ce * 1.2, self.ce_min_m, self.ce_max_m))
        return ce, le

    def _adaptive_n(self, samples: List[Sample]) -> float:
        if len(samples) < 3:
            return 3.0

        lat0, lon0 = samples[0].lat, samples[0].lon
        dists = []
        rssis = []

        for s in samples:
            x, y = self._latlon_to_xy(s.lat, s.lon, lat0, lon0)
            dists.append(math.hypot(x, y) + 1e-6)
            rssis.append(s.rssi - self.lna_gain_db)

        try:
            coeff = np.polyfit(np.log10(dists), (self.p_tx_ref - np.array(rssis)) / 10.0, 1)
            n = float(coeff[0])
        except Exception:
            n = 3.0

        return float(np.clip(n, self.n_min, self.n_max))

    def _estimate_distance(self, rssi: float, n: float) -> float:
        adj = rssi - self.lna_gain_db
        d = 10 ** ((self.p_tx_ref - adj) / (10 * n))
        return float(np.clip(d, 1.0, 150.0))

    def _multilaterate(self, samples: List[Sample]) -> Tuple[float, float]:
        if len(samples) < 3:
            return samples[-1].lat, samples[-1].lon

        n = self._adaptive_n(samples)
        lat0 = float(np.mean([s.lat for s in samples]))
        lon0 = float(np.mean([s.lon for s in samples]))

        xs, ys, rs, rssis = [], [], [], []
        for s in samples:
            x, y = self._latlon_to_xy(s.lat, s.lon, lat0, lon0)
            xs.append(x)
            ys.append(y)
            rs.append(self._estimate_distance(s.rssi, n))
            rssis.append(s.rssi)

        xs = np.array(xs)
        ys = np.array(ys)
        rs = np.array(rs)
        rssis = np.array(rssis)

        med = np.median(rssis)
        mask = np.abs(rssis - med) < 8
        if not np.any(mask):
            mask = np.argsort(rssis)[-3:]

        xs, ys, rs = xs[mask], ys[mask], rs[mask]

        w = 1 / np.clip(rs, 1, 1e9) ** 2
        x = float(np.average(xs, weights=w))
        y = float(np.average(ys, weights=w))

        for _ in range(15):
            d = np.hypot(x - xs, y - ys) + 1e-9
            J = np.column_stack(((x - xs) / d, (y - ys) / d))
            r = d - rs
            W = np.diag(w)

            try:
                delta, *_ = np.linalg.lstsq(J.T @ W @ J, -J.T @ W @ r, rcond=None)
            except np.linalg.LinAlgError:
                break

            x += float(delta[0])
            y += float(delta[1])

            if float(np.linalg.norm(delta)) < 0.5:
                break

        est_lat, est_lon = self._xy_to_latlon(x, y, lat0, lon0)

        d_est = math.hypot(x, y)
        if d_est > 200:
            scale = 200.0 / d_est
            est_lat, est_lon = self._xy_to_latlon(x * scale, y * scale, lat0, lon0)

        return est_lat, est_lon

    def _iface(self, cmd: List[str]) -> None:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _restore_managed(self) -> None:
        try:
            self._iface(["sudo", "ip", "link", "set", self.wifi_interface, "down"])
            self._iface(["sudo", "iw", "dev", self.wifi_interface, "set", "type", "managed"])
            self._iface(["sudo", "ip", "link", "set", self.wifi_interface, "up"])
            self.logger.info(f"Restored {self.wifi_interface} to managed mode")
        except Exception as e:
            self.logger.warning(f"Restore failed: {e}")

    def _kill_existing_airodump(self) -> None:
        patterns = [
            f"airodump-ng.*--write {self.airo_prefix}",
            f"airodump-ng.* {self.wifi_interface}{self.mon_suffix}",
            f"airodump-ng.* {self.wifi_interface}",
        ]
        for pat in patterns:
            try:
                subprocess.run(
                    ["sudo", "pkill", "-f", pat],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except Exception:
                pass

    async def _start_airodump(self) -> Tuple[Optional[asyncio.subprocess.Process], Optional[str]]:
        mon = self.wifi_interface + self.mon_suffix

        self._kill_existing_airodump()

        self._iface(["sudo", "ip", "link", "set", mon, "down"])
        self._iface(["sudo", "iw", "dev", mon, "del"])

        use: Optional[str] = None
        add = subprocess.run(
            ["sudo", "iw", "dev", self.wifi_interface, "interface", "add", mon, "type", "monitor"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

        if add.returncode == 0:
            self._iface(["sudo", "ip", "link", "set", mon, "up"])
            use = mon
            self.logger.info(f"Created monitor interface: {mon}")
        else:
            err = (add.stderr or "").strip()
            self.logger.warning(f"Monitor sub-iface create failed: {err}")
            self.logger.info(f"Fallback: switching {self.wifi_interface} to monitor mode")
            self._iface(["sudo", "ip", "link", "set", self.wifi_interface, "down"])
            subprocess.run(
                ["sudo", "iw", "dev", self.wifi_interface, "set", "type", "monitor"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            self._iface(["sudo", "ip", "link", "set", self.wifi_interface, "up"])
            use = self.wifi_interface

        airodump_bin = shutil.which("airodump-ng") or "airodump-ng"

        cmd = [
            "sudo", "-n",
            airodump_bin,
            "--berlin", "1",
            "--write-interval", "1",
            "--band", "abg",
            "--output-format", "csv",
            "--write", self.airo_prefix,
            use,
        ]

        self.logger.info(f"Launching airodump-ng on {use} (dual-band)")
        self.logger.info(f"Command: {' '.join(cmd)}")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )

        await asyncio.sleep(2.0)
        if proc.returncode is not None:
            err_b = b""
            try:
                err_b = await asyncio.wait_for(proc.stderr.read(), timeout=0.5)
            except Exception:
                pass

            self.logger.error(
                f"airodump-ng failed to start (rc={proc.returncode}). "
                f"stderr={err_b.decode(errors='ignore')}"
            )
            return None, None

        return proc, use

    def _latest_csv_path(self) -> Optional[str]:
        files = glob.glob(self.airo_csv_glob)
        return max(files, key=os.path.getmtime) if files else None

    def _read_airodump_rows_once(self) -> List[Tuple[str, str, int]]:
        csv_path = self._latest_csv_path()
        if not csv_path:
            return []

        try:
            with open(csv_path, errors="ignore", newline="") as f:
                rows = [r for r in csv.reader(f) if len(r) > 1]
        except Exception:
            return []

        idx = None
        for i, r in enumerate(rows):
            if r and r[0].strip().upper() == "BSSID":
                idx = i
                break
        if idx is None:
            return []

        out = []
        for r in rows[idx + 1:]:
            if not r or all(c.strip() == "" for c in r):
                break

            try:
                bssid = r[0].strip()
                rssi = int(float(r[8].strip()))
                ssid = r[13].strip(" ,\t\r\n") if len(r) > 13 else ""
                if (not ssid) or (ssid.lower() in ("<hidden>", "broadcast", "unknown")):
                    ssid = f"HIDDEN_{bssid[-5:].replace(':', '')}"
                out.append((ssid, bssid, rssi))
            except Exception:
                continue

        return out

    def _auto_calibrate_gain(self) -> None:
        rssis = []
        for ap in self._ap_db.values():
            for s in ap["samples"]:
                rssis.append(s.rssi)

        if len(rssis) < 10:
            return

        med = float(np.median(rssis))
        delta = self.rssi_ref_target - med
        self.lna_gain_db = float(
            np.clip(
                self.lna_gain_db + self.calibration_smooth * delta,
                self.lna_gain_min,
                self.lna_gain_max,
            )
        )
        self.logger.info(f"Auto-cal: median RSSI={med:.1f} -> LNA_GAIN_DB={self.lna_gain_db:.1f} dB")
        self._save_gain()

    async def _gps_loop(self) -> None:
        self.logger.info("Starting GPS loop (GPSD)")
        last = 0.0
        buf = ""

        while (not self._should_stop()) and (not self._gps_stop.is_set()):
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
                            alt = msg.get("altMSL") or msg.get("altHAE") or 0.0

                            if lat and lon:
                                self._current_position.update({"lat": lat, "lon": lon, "alt": alt})

                                now = time.time()
                                if (now - last) >= self.gps_refresh_interval:
                                    if self.tak_cot_callback:
                                        await self._call_callback(
                                            self.tak_cot_callback,
                                            {
                                                "msg_type": "event",
                                                "uid": "DF-DRONE",
                                                "type": "a-f-A",
                                                "point": {
                                                    "lat": float(lat),
                                                    "lon": float(lon),
                                                    "hae": float(alt),
                                                    "ce": 10.0,
                                                    "le": 10.0,
                                                },
                                                "data": {
                                                    "callsign": "DF-DRONE",
                                                    "type": "a-f-A",
                                                    "lat": float(lat),
                                                    "lon": float(lon),
                                                    "hae": float(alt),
                                                    "ce": 10.0,
                                                    "le": 10.0,
                                                    "remark": "Drone Position",
                                                },
                                                "opid": self.opid,
                                                "kind": "node",
                                                "event_type": "position",
                                                "node_uid": self.node_uid,
                                                "source_id": self.source_id,
                                            }
                                        )
                                    last = now

                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

            except Exception as e:
                self.logger.warning(f"GPS error: {e}")
                await asyncio.sleep(2.0)

    async def run(self):
        if not self.target_callback:
            raise RuntimeError("wifi_discovery_edge requires target_callback to be wired")

        self.logger.info("Starting Wi-Fi discovery / edge geolocation operation")
        self._apply_parameters_from_runner()
        self._load_gain()

        await self._emit_status("Running: Wi-Fi discovery")

        gps_task = asyncio.create_task(self._gps_loop())

        self._airodump_proc, self._airodump_iface_in_use = await self._start_airodump()
        if not self._airodump_proc:
            self._gps_stop.set()
            try:
                await gps_task
            except Exception:
                pass
            await self._emit_status("Idle")
            return

        self._last_cal = time.time()

        try:
            while not self._should_stop():
                lat = self._current_position.get("lat")
                lon = self._current_position.get("lon")
                alt = self._current_position.get("alt")

                if not lat or not lon:
                    await asyncio.sleep(self.wifi_refresh_interval)
                    continue

                rows = await self._to_thread_compat(self._read_airodump_rows_once)
                if not rows:
                    await asyncio.sleep(self.wifi_refresh_interval)
                    continue

                now = time.time()

                for ssid, bssid, rssi in rows:
                    ap_key = bssid.lower().strip()

                    ap = self._ap_db.setdefault(
                        ap_key,
                        {
                            "bssid": bssid,
                            "ssid": ssid,
                            "samples": [],
                            "est_lat": float(lat),
                            "est_lon": float(lon),
                            "frequency_mhz": None,
                            "band": "",
                            "channel": None,
                            "encryption": "",
                            "target_created": False,
                            "alert_sent": False,
                            "first_seen_time": now,
                            "last_seen_time": now,
                        },
                    )

                    ap["ssid"] = ssid
                    ap["bssid"] = bssid
                    ap["last_seen_time"] = now

                    if "target_id" not in ap:
                        raw = (ap.get("bssid") or ssid or "unknown").replace(":", "").replace(" ", "_")
                        ap["target_id"] = f"wifiap-{raw}"

                    ap["samples"].append(Sample(float(lat), float(lon), float(rssi)))
                    ap["samples"] = ap["samples"][-80:]

                    if len(ap["samples"]) < self.min_samples_before_target:
                        continue

                    est_lat, est_lon = self._multilaterate(ap["samples"])
                    ap["est_lat"] = self.smooth_alpha * est_lat + (1 - self.smooth_alpha) * ap["est_lat"]
                    ap["est_lon"] = self.smooth_alpha * est_lon + (1 - self.smooth_alpha) * ap["est_lon"]

                    ce_m, le_m = self._compute_ce_le(ap["samples"], ap["est_lat"], ap["est_lon"])
                    prev_ce = float(ap.get("ce_m", self.ce_max_m))
                    prev_le = float(ap.get("le_m", self.ce_max_m))
                    ap["ce_m"] = (1 - self.ce_smooth_alpha) * prev_ce + self.ce_smooth_alpha * ce_m
                    ap["le_m"] = (1 - self.ce_smooth_alpha) * prev_le + self.ce_smooth_alpha * le_m

                    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

                    freq_mhz = ap.get("frequency_mhz")
                    band = ap.get("band", "")
                    if not band and freq_mhz is not None:
                        try:
                            f = float(freq_mhz)
                            if 2400.0 <= f < 2500.0:
                                band = "2.4GHz"
                            elif 4900.0 <= f < 5900.0:
                                band = "5GHz"
                            elif 5925.0 <= f < 7125.0:
                                band = "6GHz"
                        except Exception:
                            band = ""

                    classification = {
                        "display_label": "Wi-Fi AP",
                        "candidates": [
                            {"source": "database", "label": "Wi-Fi AP"},
                            {"source": "model", "label": "802.11 Access Point", "confidence": 0.95},
                        ],
                    }

                    location = {
                        "lat": float(ap.get("est_lat", lat)),
                        "lon": float(ap.get("est_lon", lon)),
                        "hae_m": float(alt or 0.0),
                        "ce_m": float(ap.get("ce_m", ce_m)),
                        "timestamp": now_iso,
                        "source": "wifi_discovery_edge_light",
                    }

                    wifi_block = {
                        "ssid": ap.get("ssid", ssid),
                        "bssid": bssid,
                        "channel": ap.get("channel"),
                        "band": band,
                        "rssi_dbm": int(rssi),
                        "encryption": ap.get("encryption", ""),
                        "last_observation_time": now_iso,
                    }

                    patch = {
                        "kind": "target",
                        "event_type": "target",
                        "target_id": ap["target_id"],
                        "node_uid": self.node_uid,
                        "source_id": self.source_id,
                        "source_soi_id": "",
                        "frequency_mhz": float(freq_mhz) if freq_mhz is not None else None,
                        "classification": classification,
                        "location": location,
                        "state": "tracking",
                        "geolocate": {
                            "status": "idle",
                            "mode": "",
                            "plugin": "",
                            "action": "",
                            "node_uids": [],
                            "error": "",
                            "updated_time": "",
                        },
                        "wifi": wifi_block,
                    }

                    await self._emit_target_patch(
                        target_id=ap["target_id"],
                        patch=patch,
                        history_entry={
                            "event": "wifi_ap_update",
                            "kind": "target",
                            "event_type": "target",
                            "node_uid": self.node_uid,
                            "source_id": self.source_id,
                            "bssid": bssid,
                        },
                        artifact_id="",
                    )

                    if not ap["target_created"]:
                        ap["target_created"] = True
                        self.logger.info(
                            f"Created Wi-Fi target {ap['target_id']} for BSSID {bssid} SSID {ssid!r}"
                        )

                    if self.alert_on_new_target and not ap["alert_sent"]:
                        ap["alert_sent"] = True

                        alert_message = (
                            f"New Wi-Fi target discovered: SSID={ssid or '<hidden>'}, "
                            f"BSSID={bssid}, RSSI={int(rssi)} dBm"
                        )

                        await self._emit_alert(
                            message=alert_message,
                            uid=f"wifi-alert-{ap['target_id']}",
                            alert_kind="wifi_discovery_edge_light",
                            alert_summary=f"Wi-Fi target discovered: {ssid or '<hidden>'}",
                            lat=float(ap.get("est_lat", lat)),
                            lon=float(ap.get("est_lon", lon)),
                            alt=float(alt or 0.0),
                            remarks_extra={
                                "target_id": ap["target_id"],
                                "ssid": ssid or "<hidden>",
                                "bssid": bssid,
                                "rssi_dbm": int(rssi),
                            },
                        )

                await self._emit_status("Running: Scanning Wi-Fi APs")

                if (now - self._last_cal) > self.calibration_period:
                    self._auto_calibrate_gain()
                    self._last_cal = now

                await asyncio.sleep(self.wifi_refresh_interval)

        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.exception(f"Wi-Fi discovery operation error: {e}")
        finally:
            self._gps_stop.set()
            try:
                await asyncio.wait_for(gps_task, timeout=3.0)
            except Exception:
                pass

            try:
                if self._airodump_proc and self._airodump_proc.returncode is None:
                    try:
                        os.killpg(self._airodump_proc.pid, signal.SIGTERM)
                    except Exception:
                        self._airodump_proc.terminate()

                    try:
                        await asyncio.wait_for(self._airodump_proc.wait(), timeout=3.0)
                    except asyncio.TimeoutError:
                        try:
                            os.killpg(self._airodump_proc.pid, signal.SIGKILL)
                        except Exception:
                            self._airodump_proc.kill()
            except Exception:
                pass

            try:
                await self._to_thread_compat(self._restore_managed)
            except Exception:
                pass

            await self._emit_status("Idle")

            self.logger.info("Wi-Fi discovery / edge geolocation operation stopped cleanly.")

    async def _to_thread_compat(self, func, *args, **kwargs):
        if hasattr(asyncio, "to_thread"):
            return await asyncio.to_thread(func, *args, **kwargs)

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})