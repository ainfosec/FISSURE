#!/usr/bin/env python3
"""FISSURE - Wi-Fi Geolocate All Visible APs

Sparse-environment bulk geolocation. Discovers visible APs, creates or reuses
canonical Wi-Fi Targets, and emits reduced target-associated RSSI observations.
HIPRFISR owns geometry, multilateration, and the authoritative Target solution.
"""

import asyncio
import csv
import glob
import json
import logging
import os
import shutil
import statistics
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))
SCRIPTS_DIR = os.path.join(PLUGIN_ROOT, "scripts")
WIFI_LIB_DIR = os.path.join(SCRIPTS_DIR, "wifi_lib")
for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT, SCRIPTS_DIR, WIFI_LIB_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

from fissure.utils.plugins.operations import Operation


MON_SUFFIX_DEFAULT = "mon"
CALLBACK_TIMEOUT_S = 2.0


def _to_bool(value: Any, default: bool = False) -> bool:
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


def _normalize_bssid(bssid: str) -> str:
    return (bssid or "").replace(":", "").replace("-", "").strip().lower()


def _channel_info(channel: Optional[int]) -> Tuple[str, Optional[float]]:
    if channel is None:
        return "", None
    if 1 <= channel <= 14:
        return "2.4GHz", 2484.0 if channel == 14 else 2412.0 + 5.0 * (channel - 1)
    if 30 <= channel <= 177:
        return "5GHz", 5000.0 + 5.0 * channel
    if 1 <= channel <= 233:
        return "6GHz", 5950.0 + 5.0 * channel
    return "", None


class OperationMain(Operation):
    def __init__(self, node_uid: str = "", logger: logging.Logger = logging.getLogger(__name__), alert_callback=None, tak_cot_callback=None, detection_callback=None, status_callback=None, target_callback=None, artifact_manager=None, parameters: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(node_uid=node_uid, logger=logger, alert_callback=alert_callback, tak_cot_callback=tak_cot_callback, detection_callback=detection_callback, status_callback=status_callback, target_callback=target_callback, artifact_manager=artifact_manager)
        self.parameters = parameters or {}
        self.source_id = str(node_uid or "").strip() or "sensor_node"
        self.wifi_interface = "wlx00c0caa744fc"
        self.mon_suffix = MON_SUFFIX_DEFAULT
        self.airo_prefix = "/tmp/airodump"
        self.airo_csv_glob = self.airo_prefix + "-*.csv"
        self.gpsd_host = "127.0.0.1"
        self.gpsd_port = 2947
        self.meas_every_s = 0.5
        self.emit_every_s = 1.0
        self.aggregation_window_s = 3.0
        self.max_targets = 25
        self.auto_create_targets = True
        self.target_bssids: Dict[str, str] = {}
        self._gps_stop = asyncio.Event()
        self._current_position = {"lat": None, "lon": None, "alt": 0.0}
        self._airodump_proc = None
        self._airodump_iface_in_use = None
        self._announced_targets: Set[str] = set()
        self._last_emit_by_bssid: Dict[str, float] = {}
        self._samples_by_bssid: Dict[str, List[Tuple[float, float]]] = {}
        self._limit_logged = False

    def _apply_parameters_from_runner(self) -> None:
        p = self.parameters if isinstance(self.parameters, dict) else {}
        self.source_id = str(p.get("source_id") or p.get("node_uid") or self.node_uid or "sensor_node").strip()
        self.wifi_interface = str(p.get("wifi_interface", self.wifi_interface) or self.wifi_interface)
        self.mon_suffix = str(p.get("mon_suffix", self.mon_suffix) or self.mon_suffix)
        self.airo_prefix = str(p.get("airo_prefix", self.airo_prefix) or self.airo_prefix)
        self.airo_csv_glob = self.airo_prefix + "-*.csv"
        self.gpsd_host = str(p.get("gpsd_host", self.gpsd_host) or self.gpsd_host)
        self.gpsd_port = int(p.get("gpsd_port", self.gpsd_port))
        self.meas_every_s = max(0.2, float(p.get("meas_every_s", p.get("wifi_refresh_interval", self.meas_every_s))))
        self.emit_every_s = max(0.2, float(p.get("emit_every_s", p.get("min_detection_interval_s", self.emit_every_s))))
        self.aggregation_window_s = max(self.emit_every_s, float(p.get("aggregation_window_s", self.aggregation_window_s)))
        self.max_targets = max(0, int(float(p.get("max_targets", self.max_targets))))

        target_bssids = p.get("target_bssids", {})
        if isinstance(target_bssids, str):
            try:
                target_bssids = json.loads(target_bssids)
            except Exception:
                target_bssids = {}

        self.target_bssids = {}
        if isinstance(target_bssids, dict):
            for bssid, target_id in target_bssids.items():
                bssid_norm = _normalize_bssid(str(bssid))
                target_id = str(target_id or "").strip()
                if bssid_norm and target_id:
                    self.target_bssids[bssid_norm] = target_id

        default_auto_create = not bool(self.target_bssids)
        self.auto_create_targets = _to_bool(p.get("auto_create_targets"), default=default_auto_create)
        if self.target_bssids:
            self.auto_create_targets = False

        self.resource_args = {"wifi_interface": self.wifi_interface}

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

    async def _call(self, callback: Callable, *args, **kwargs):
        result = callback(*args, **kwargs)
        if asyncio.iscoroutine(result) or isinstance(result, asyncio.Future):
            return await asyncio.wait_for(result, timeout=CALLBACK_TIMEOUT_S)
        return result

    async def _set_status(self, status: str) -> None:
        if not self.status_callback:
            return
        try:
            await self._call(self.status_callback, status)
        except Exception:
            self.logger.exception("status_callback failed")

    @staticmethod
    def get_resources(dev: str = "") -> Dict[str, Any]:
        return {"usrp": {"type": "Alfa", "model": "", "serial": dev, "description": "Alfa Card", "required": True}}

    def _iface(self, cmd: List[str]) -> None:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    def _restore_managed(self) -> None:
        try:
            self._iface(["sudo", "ip", "link", "set", self.wifi_interface, "down"])
            self._iface(["sudo", "iw", "dev", self.wifi_interface, "set", "type", "managed"])
            self._iface(["sudo", "ip", "link", "set", self.wifi_interface, "up"])
        except Exception as exc:
            self.logger.warning(f"Restore failed: {exc}")

    def _kill_existing_airodump(self, signal_name: str = "TERM") -> None:
        signal_name = "KILL" if str(signal_name).upper() == "KILL" else "TERM"

        patterns = [
            f"airodump-ng.*--write {self.airo_prefix}",
            f"airodump-ng.* {self.wifi_interface}{self.mon_suffix}",
            f"airodump-ng.* {self.wifi_interface}",
        ]

        for pattern in patterns:
            try:
                result = subprocess.run(
                    [
                        "sudo",
                        "-n",
                        "pkill",
                        f"-{signal_name}",
                        "-f",
                        pattern,
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )

                stderr = (result.stderr or "").strip()

                if "password is required" in stderr.lower():
                    self.logger.warning(
                        "Passwordless sudo is not configured for pkill; "
                        "unable to stop privileged airodump-ng"
                    )
                    return

                if result.returncode == 0:
                    return

            except Exception as exc:
                self.logger.debug(
                    f"Unable to stop airodump-ng with pattern "
                    f"{pattern!r}: {exc}"
                )

    async def _start_airodump(self) -> Tuple[Optional[asyncio.subprocess.Process], Optional[str]]:
        airodump_path = shutil.which("airodump-ng")
        if not airodump_path:
            self.logger.error("airodump-ng not found in PATH")
            return None, None

        mon = self.wifi_interface + self.mon_suffix
        self._kill_existing_airodump()
        self._iface(["sudo", "ip", "link", "set", mon, "down"])
        self._iface(["sudo", "iw", "dev", mon, "del"])
        add = subprocess.run(["sudo", "iw", "dev", self.wifi_interface, "interface", "add", mon, "type", "monitor"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, check=False)
        if add.returncode == 0:
            self._iface(["sudo", "ip", "link", "set", mon, "up"])
            use = mon
        else:
            self.logger.warning(f"Monitor sub-interface create failed: {(add.stderr or '').strip()}")
            self._iface(["sudo", "ip", "link", "set", self.wifi_interface, "down"])
            self._iface(["sudo", "iw", "dev", self.wifi_interface, "set", "type", "monitor"])
            self._iface(["sudo", "ip", "link", "set", self.wifi_interface, "up"])
            use = self.wifi_interface

        cmd = ["sudo", "-n", airodump_path, "--berlin", "1", "--write-interval", "1", "--band", "abg", "--output-format", "csv", "--write", self.airo_prefix, use]
        self.logger.info(f"Command: {' '.join(cmd)}")
        proc = await asyncio.create_subprocess_exec(*cmd, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE, start_new_session=True, close_fds=True)
        await asyncio.sleep(2.0)
        if proc.returncode is not None:
            err = b""
            try:
                err = await asyncio.wait_for(proc.stderr.read(), timeout=0.5)
            except Exception:
                pass
            self.logger.error(f"airodump-ng failed to start rc={proc.returncode}: {err.decode(errors='ignore')}")
            return None, None
        return proc, use

    def _latest_csv_path(self) -> Optional[str]:
        files = glob.glob(self.airo_csv_glob)
        return max(files, key=os.path.getmtime) if files else None

    def _read_airodump_rows_once(self) -> List[Dict[str, Any]]:
        path = self._latest_csv_path()
        if not path:
            return []
        try:
            with open(path, errors="ignore", newline="") as f:
                rows = list(csv.reader(f))
        except Exception:
            return []

        idx = next((i for i, r in enumerate(rows) if r and r[0].strip().upper() == "BSSID"), None)
        if idx is None:
            return []

        out = []
        for r in rows[idx + 1:]:
            if not r or all(not c.strip() for c in r):
                break

            first = r[0].strip()
            if first.upper() == "STATION MAC":
                break
            if len(r) < 14:
                continue

            try:
                bssid = first
                bssid_norm = _normalize_bssid(bssid)
                if len(bssid_norm) != 12 or any(c not in "0123456789abcdef" for c in bssid_norm):
                    continue

                channel = int(float(r[3].strip())) if r[3].strip() else None
                if channel is not None and channel <= 0:
                    channel = None

                rssi = float(r[8].strip()) if r[8].strip() else None
                ssid = r[13].strip(" ,\t\r\n")
                if ssid.lower() in {"<hidden>", "broadcast", "unknown"}:
                    ssid = ""

                band, frequency_mhz = _channel_info(channel)
                out.append({
                    "ssid": ssid,
                    "bssid": bssid,
                    "bssid_norm": bssid_norm,
                    "channel": channel,
                    "band": band,
                    "frequency_mhz": frequency_mhz,
                    "rssi_dbm": rssi,
                    "encryption": r[5].strip(),
                })
            except Exception:
                continue
        return out

    async def _gps_loop(self) -> None:
        buf = ""
        while not self._should_stop() and not self._gps_stop.is_set():
            try:
                reader, writer = await asyncio.open_connection(self.gpsd_host, self.gpsd_port)
                writer.write(b'?WATCH={"enable":true,"json":true}\n')
                await writer.drain()
                while not self._should_stop() and not self._gps_stop.is_set():
                    data = await reader.read(4096)
                    if not data:
                        await asyncio.sleep(0.5)
                        continue
                    buf += data.decode(errors="ignore")
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        try:
                            msg = json.loads(line)
                        except Exception:
                            continue
                        if msg.get("class") == "TPV" and msg.get("mode", 0) >= 2:
                            lat, lon = msg.get("lat"), msg.get("lon")
                            alt = msg.get("altMSL") or msg.get("altHAE") or 0.0
                            if lat is not None and lon is not None:
                                self._current_position.update({"lat": float(lat), "lon": float(lon), "alt": float(alt)})
                writer.close()
                await writer.wait_closed()
            except Exception as exc:
                self.logger.warning(f"GPS error: {exc}")
                await asyncio.sleep(2.0)

    async def _stop_runtime(self, gps_task: Optional[asyncio.Task]) -> None:
        self._gps_stop.set()

        if gps_task:
            gps_task.cancel()
            try:
                await gps_task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass

        if self._airodump_proc and self._airodump_proc.returncode is None:
            self._kill_existing_airodump("TERM")

            try:
                await asyncio.wait_for(
                    self._airodump_proc.wait(),
                    timeout=1.5,
                )
            except asyncio.TimeoutError:
                self._kill_existing_airodump("KILL")

                try:
                    await asyncio.wait_for(
                        self._airodump_proc.wait(),
                        timeout=0.75,
                    )
                except asyncio.TimeoutError:
                    self.logger.warning(
                        "airodump-ng did not exit after SIGKILL"
                    )

        await self._to_thread_compat(self._restore_managed)

        # Direct discover-and-geolocate mode owns the Target lifecycle it
        # created. Search Similar mode is owned by HIPRFISR and must not be
        # independently cleared here.
        if (
            not self.target_bssids
            and self.target_callback
            and self._announced_targets
        ):
            updated_time = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(),
            )

            for target_id in sorted(self._announced_targets):
                try:
                    await self._call(
                        self.target_callback,
                        target_id=target_id,
                        patch={
                            "state": "detected",
                            "geolocate": {
                                "status": "idle",
                                "mode": "",
                                "plugin": "",
                                "action": "",
                                "node_uids": [],
                                "error": "",
                                "operation_id": "",
                                "updated_time": updated_time,
                                "previous_state": "",
                                "had_detections": False,
                            },
                        },
                        history_entry={
                            "event": "wifi_geolocate_all_stopped",
                            "source": "wifi_geolocate_all",
                            "operation_id": self.opid,
                        },
                        artifact_id="",
                    )
                except Exception as exc:
                    self.logger.warning(
                        f"Unable to clear geolocation state for "
                        f"target_id={target_id}: {exc}"
                    )

        await self._set_status("Idle")

    async def _to_thread_compat(self, func, *args, **kwargs):
        if hasattr(asyncio, "to_thread"):
            return await asyncio.to_thread(func, *args, **kwargs)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

    def _target_id_for_row(self, row: Dict[str, Any]) -> Optional[str]:
        bssid_norm = str(row.get("bssid_norm") or "").strip()
        if not bssid_norm:
            return None
        if self.target_bssids:
            return self.target_bssids.get(bssid_norm)
        if not self.auto_create_targets:
            return None
        return f"wifiap-{bssid_norm}"

    async def _ensure_target(self, row: Dict[str, Any]) -> Optional[str]:
        target_id = self._target_id_for_row(row)
        if not target_id:
            return None

        # Search Similar / known-target mode is already lifecycle-managed by
        # HIPRFISR geolocate_target_start()/stop().
        if self.target_bssids:
            return target_id

        if target_id in self._announced_targets:
            return target_id

        if self.max_targets and len(self._announced_targets) >= self.max_targets:
            if not self._limit_logged:
                self.logger.warning(
                    f"Wi-Fi geolocate all reached max auto-created "
                    f"Targets={self.max_targets}; additional BSSIDs will be ignored"
                )
                self._limit_logged = True
            return None

        if not self.target_callback:
            return None

        now = time.time()
        updated_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        lat = self._current_position.get("lat")
        lon = self._current_position.get("lon")
        alt = self._current_position.get("alt")

        summary = {
            "source": "wifi_geolocate_all",
            "auto_created": True,
        }
        if lat is not None and lon is not None:
            summary["observation_location"] = {
                "lat": float(lat),
                "lon": float(lon),
                "hae_m": float(alt or 0.0),
                "timestamp": now,
                "semantics": "receiver_observation",
            }

        wifi = {
            "bssid": row.get("bssid", ""),
            "ssid": row.get("ssid", ""),
            "channel": row.get("channel"),
            "band": row.get("band", ""),
            "frequency_mhz": row.get("frequency_mhz"),
            "rssi_dbm": row.get("rssi_dbm"),
            "encryption": row.get("encryption", ""),
            "last_observation_time": now,
        }

        patch = {
            "node_uid": str(self.node_uid),
            "state": "tracking",
            "frequency_mhz": row.get("frequency_mhz"),
            "classification": {
                "display_label": "Wi-Fi AP",
                "source": "wifi_geolocate_all",
                "candidates": [
                    {
                        "source": "wifi",
                        "label": "802.11 Access Point",
                    }
                ],
            },
            "wifi": {
                key: value
                for key, value in wifi.items()
                if value not in (None, "")
            },
            "summary": summary,
            "geolocate": {
                "status": "running",
                "mode": "wifi_all",
                "plugin": "WiFi",
                "action": "wifi_geolocate_all",
                "node_uids": [str(self.node_uid)],
                "error": "",
                "operation_id": str(self.opid),
                "updated_time": updated_time,
                "previous_state": "detected",
                "had_detections": False,
            },
        }

        history_entry = {
            "event": "wifi_geolocate_all_started",
            "source": "wifi_geolocate_all",
            "operation_id": self.opid,
            "bssid": row.get("bssid", ""),
        }

        await self._call(
            self.target_callback,
            target_id=target_id,
            patch=patch,
            history_entry=history_entry,
            artifact_id="",
        )

        self._announced_targets.add(target_id)
        return target_id

    async def _emit_detection(self, target_id: str, row: Dict[str, Any], rssi_dbm: float, sample_count: int) -> None:
        if not self.detection_callback:
            return

        lat = self._current_position.get("lat")
        lon = self._current_position.get("lon")
        alt = self._current_position.get("alt")
        if lat is None or lon is None:
            return

        frequency_mhz = row.get("frequency_mhz")
        try:
            frequency_hz = int(round(float(frequency_mhz) * 1e6)) if frequency_mhz is not None else None
        except (TypeError, ValueError):
            frequency_hz = None

        detection = {
            "kind": "detection",
            "event_type": "detection",
            "detection_kind": "wifi_geolocate_all",
            "detector": "wifi_geolocate_all",
            "event_uid": f"wifi-geolocate-all-{row['bssid_norm']}-{self.node_uid}",
            "target_id": target_id,
            "node_uid": str(self.node_uid),
            "source_id": self.source_id,
            "opid": self.opid,
            "operation_id": self.opid,
            "timestamp": time.time(),
            "latitude": float(lat),
            "longitude": float(lon),
            "altitude": float(alt or 0.0),
            "ssid": row.get("ssid", ""),
            "bssid": row.get("bssid", ""),
            "channel": row.get("channel"),
            "band": row.get("band", ""),
            "frequency_hz": frequency_hz,
            "power_dbm": float(rssi_dbm),
            "metric_units": "dBm",
            "encryption": row.get("encryption", ""),
            "aggregation": "median",
            "aggregation_window_s": float(self.aggregation_window_s),
            "aggregation_sample_count": int(sample_count),
            "location_semantics": "receiver_observation",
        }
        await self._call(self.detection_callback, {k: v for k, v in detection.items() if v is not None})

    async def run(self) -> None:
        gps_task = None
        try:
            self._apply_parameters_from_runner()
            if not self.detection_callback:
                raise RuntimeError("wifi_geolocate_all requires detection_callback")
            if self.auto_create_targets and not self.target_callback:
                raise RuntimeError("wifi_geolocate_all auto-create mode requires target_callback")

            mode_text = f"tracking {len(self.target_bssids)} known Wi-Fi Targets" if self.target_bssids else "discovering and geolocating visible Wi-Fi APs"
            await self._set_status(f"Wi-Fi locate all: {mode_text}; waiting for GPS")
            gps_task = asyncio.create_task(self._gps_loop())
            self._airodump_proc, self._airodump_iface_in_use = await self._start_airodump()
            if not self._airodump_proc:
                return

            while not self._should_stop():
                lat = self._current_position.get("lat")
                lon = self._current_position.get("lon")
                if lat is None or lon is None:
                    await self._set_status(f"Wi-Fi locate all: {mode_text}; waiting for GPS")
                    await asyncio.sleep(self.meas_every_s)
                    continue

                rows = await self._to_thread_compat(self._read_airodump_rows_once)
                rows.sort(key=lambda row: float(row.get("rssi_dbm")) if row.get("rssi_dbm") is not None else -999.0, reverse=True)
                now = time.time()
                visible_tracked = 0

                for row in rows:
                    bssid_norm = row.get("bssid_norm", "")
                    rssi = row.get("rssi_dbm")
                    if not bssid_norm or rssi is None:
                        continue

                    target_id = await self._ensure_target(row)
                    if not target_id:
                        continue
                    visible_tracked += 1

                    samples = self._samples_by_bssid.setdefault(bssid_norm, [])
                    samples.append((now, float(rssi)))
                    cutoff = now - self.aggregation_window_s
                    samples[:] = [(ts, value) for ts, value in samples if ts >= cutoff]

                    last_emit = self._last_emit_by_bssid.get(bssid_norm, 0.0)
                    if now - last_emit < self.emit_every_s:
                        continue

                    values = [value for _, value in samples]
                    if not values:
                        continue
                    median_rssi = float(statistics.median(values))
                    self._last_emit_by_bssid[bssid_norm] = now
                    await self._emit_detection(target_id, row, median_rssi, len(values))

                if self.target_bssids:
                    await self._set_status(f"Wi-Fi locate all: {visible_tracked}/{len(self.target_bssids)} known Targets visible")
                else:
                    limit_text = "unlimited" if self.max_targets == 0 else str(self.max_targets)
                    await self._set_status(f"Wi-Fi locate all: {len(self._announced_targets)}/{limit_text} auto Targets, {visible_tracked} visible")

                await asyncio.sleep(self.meas_every_s)

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.logger.exception(f"Wi-Fi geolocate all error: {exc}")
        finally:
            await self._stop_runtime(gps_task)


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})