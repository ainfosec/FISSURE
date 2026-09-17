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
import math
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
    def __init__(self, node_uid: str = "", logger: logging.Logger = logging.getLogger(__name__), alert_callback=None, tak_cot_callback=None, detection_callback=None, status_callback=None, target_callback=None, position_callback=None, artifact_manager=None, parameters: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(node_uid=node_uid, logger=logger, alert_callback=alert_callback, tak_cot_callback=tak_cot_callback, detection_callback=detection_callback, status_callback=status_callback, target_callback=target_callback, position_callback=position_callback, artifact_manager=artifact_manager)
        self.parameters = parameters or {}
        self.source_id = str(node_uid or "").strip() or "sensor_node"
        self.wifi_interface = "wlx00c0caa744fc"
        self.mon_suffix = MON_SUFFIX_DEFAULT
        self.airo_prefix = "/tmp/airodump"
        self.airo_csv_glob = self.airo_prefix + "-*.csv"
        self.meas_every_s = 0.5
        self.aggregation_window_s = 3.0
        self.cluster_radius_m = 8.0
        self.measurement_spacing_m = 20.0
        self.max_targets = 25
        self.auto_create_targets = True
        self.target_bssids: Dict[str, str] = {}

        self._airodump_proc = None
        self._airodump_iface_in_use = None
        self._announced_targets: Set[str] = set()
        self._last_source_seen_by_bssid: Dict[str, str] = {}
        self._clusters_by_bssid: Dict[str, Dict[str, Any]] = {}
        self._last_emitted_position_by_bssid: Dict[
            str,
            Tuple[float, float],
        ] = {}
        self._emitted_measurement_count_by_bssid: Dict[str, int] = {}
        self._limit_logged = False

    def _apply_parameters_from_runner(self) -> None:
        p = self.parameters if isinstance(self.parameters, dict) else {}
        self.source_id = str(p.get("source_id") or p.get("node_uid") or self.node_uid or "sensor_node").strip()
        self.wifi_interface = str(p.get("wifi_interface", self.wifi_interface) or self.wifi_interface)
        self.mon_suffix = str(p.get("mon_suffix", self.mon_suffix) or self.mon_suffix)
        self.airo_prefix = str(p.get("airo_prefix", self.airo_prefix) or self.airo_prefix)
        self.airo_csv_glob = self.airo_prefix + "-*.csv"
        self.meas_every_s = max(
            0.2,
            float(
                p.get(
                    "meas_every_s",
                    p.get(
                        "wifi_refresh_interval",
                        self.meas_every_s,
                    ),
                )
            ),
        )
        self.aggregation_window_s = max(
            0.5,
            float(
                p.get(
                    "aggregation_window_s",
                    self.aggregation_window_s,
                )
            ),
        )
        self.measurement_spacing_m = max(
            self.cluster_radius_m,
            float(
                p.get(
                    "measurement_spacing_m",
                    self.measurement_spacing_m,
                )
            ),
        )
        self.max_targets = max(
            0,
            int(float(p.get("max_targets", self.max_targets))),
        )

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
            self.logger.info(
                f"Monitor sub-interface unavailable; using {self.wifi_interface} "
                f"directly in monitor mode"
            )
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
                    "source_last_seen": r[2].strip(),
                })
            except Exception:
                continue
        return out

    def _snapshot_position(self) -> Dict[str, Any]:
        try:
            position = self.position_callback()
        except Exception as exc:
            self.logger.warning(f"Position callback failed: {exc}")
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

    @staticmethod
    def _distance_m(
        lat1: float,
        lon1: float,
        lat2: float,
        lon2: float,
    ) -> float:
        radius_m = 6371000.0
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlambda = math.radians(lon2 - lon1)
        a = (
            math.sin(dphi / 2.0) ** 2
            + math.cos(phi1)
            * math.cos(phi2)
            * math.sin(dlambda / 2.0) ** 2
        )
        return radius_m * 2.0 * math.atan2(
            math.sqrt(a),
            math.sqrt(max(0.0, 1.0 - a)),
        )

    def _start_cluster(
        self,
        bssid_norm: str,
        row: Dict[str, Any],
        position: Dict[str, Any],
        now_epoch: float,
    ) -> None:
        self._clusters_by_bssid[bssid_norm] = {
            "anchor_latitude": float(position["latitude"]),
            "anchor_longitude": float(position["longitude"]),
            "anchor_altitude": float(position.get("altitude") or 0.0),
            "location_source": str(position.get("source") or ""),
            "started_monotonic": time.monotonic(),
            "first_sample_epoch": now_epoch,
            "last_sample_epoch": now_epoch,
            "settled": False,
            "samples": [],
        }
        self._add_cluster_sample(
            bssid_norm,
            row,
            now_epoch,
        )

    def _add_cluster_sample(
        self,
        bssid_norm: str,
        row: Dict[str, Any],
        now_epoch: float,
    ) -> None:
        cluster = self._clusters_by_bssid.get(bssid_norm)
        if not cluster:
            return

        rssi = row.get("rssi_dbm")
        if rssi is None:
            return

        cluster["samples"].append({
            "timestamp_epoch": now_epoch,
            "rssi_dbm": float(rssi),
            "row": dict(row),
        })
        cluster["last_sample_epoch"] = now_epoch

    def _cluster_far_enough_to_emit(
        self,
        bssid_norm: str,
        cluster: Dict[str, Any],
    ) -> bool:
        previous = self._last_emitted_position_by_bssid.get(
            bssid_norm
        )
        if previous is None:
            return True

        distance = self._distance_m(
            float(previous[0]),
            float(previous[1]),
            float(cluster["anchor_latitude"]),
            float(cluster["anchor_longitude"]),
        )
        return distance >= self.measurement_spacing_m

    async def _finalize_cluster(
        self,
        bssid_norm: str,
        reason: str,
    ) -> bool:
        cluster = self._clusters_by_bssid.get(bssid_norm)
        if not cluster or cluster.get("settled", False):
            return False

        cluster["settled"] = True
        samples = cluster.get("samples") or []
        if not samples:
            return False

        if not self._cluster_far_enough_to_emit(
            bssid_norm,
            cluster,
        ):
            self.logger.debug(
                f"Skipping Wi-Fi geolocation cluster "
                f"bssid={bssid_norm} within "
                f"{self.measurement_spacing_m:.1f} m of the "
                "last emitted receiver position"
            )
            return False

        values = [
            float(sample["rssi_dbm"])
            for sample in samples
        ]
        median_rssi = float(statistics.median(values))
        latest_sample = max(
            samples,
            key=lambda sample: float(
                sample.get("timestamp_epoch") or 0.0
            ),
        )
        row = latest_sample.get("row") or {}

        target_id = self._target_id_for_row(row)
        if not target_id:
            return False

        lat = float(cluster["anchor_latitude"])
        lon = float(cluster["anchor_longitude"])
        alt = float(cluster.get("anchor_altitude") or 0.0)

        await self._emit_detection(
            target_id=target_id,
            row=row,
            rssi_dbm=median_rssi,
            sample_count=len(values),
            lat=lat,
            lon=lon,
            alt=alt,
            timestamp_epoch=float(
                latest_sample.get("timestamp_epoch")
                or time.time()
            ),
            location_source=str(
                cluster.get("location_source") or ""
            ),
        )

        self._last_emitted_position_by_bssid[
            bssid_norm
        ] = (lat, lon)
        count = (
            self._emitted_measurement_count_by_bssid.get(
                bssid_norm,
                0,
            )
            + 1
        )
        self._emitted_measurement_count_by_bssid[
            bssid_norm
        ] = count

        self.logger.info(
            f"Wi-Fi geolocate all measurement "
            f"target={target_id} "
            f"bssid={row.get('bssid', '')} "
            f"rssi_median={median_rssi:.1f} dBm "
            f"samples={len(values)} "
            f"position=({lat:.6f}, {lon:.6f}) "
            f"position_count={count} "
            f"reason={reason}"
        )
        return True

    async def _finalize_ready_clusters(self) -> None:
        now = time.monotonic()
        for bssid_norm, cluster in list(
            self._clusters_by_bssid.items()
        ):
            if cluster.get("settled", False):
                continue
            if (
                now
                - float(cluster["started_monotonic"])
            ) >= self.aggregation_window_s:
                await self._finalize_cluster(
                    bssid_norm,
                    "aggregation_window",
                )

    async def _finalize_all_clusters(self) -> None:
        for bssid_norm in list(
            self._clusters_by_bssid.keys()
        ):
            try:
                await self._finalize_cluster(
                    bssid_norm,
                    "operation_stopped",
                )
            except Exception:
                self.logger.exception(
                    "Unable to finalize Wi-Fi geolocation cluster "
                    f"for bssid={bssid_norm}"
                )


    async def _stop_runtime(self) -> None:
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

    async def _ensure_target(
        self,
        row: Dict[str, Any],
        position: Dict[str, Any],
    ) -> Optional[str]:
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
        updated_time = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(now),
        )
        lat = position.get("latitude")
        lon = position.get("longitude")
        alt = position.get("altitude")

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
                "source": str(position.get("source") or ""),
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

    async def _emit_detection(
        self,
        *,
        target_id: str,
        row: Dict[str, Any],
        rssi_dbm: float,
        sample_count: int,
        lat: float,
        lon: float,
        alt: float,
        timestamp_epoch: float,
        location_source: str,
    ) -> None:
        if not self.detection_callback:
            return

        frequency_mhz = row.get("frequency_mhz")
        try:
            frequency_hz = (
                int(round(float(frequency_mhz) * 1e6))
                if frequency_mhz is not None
                else None
            )
        except (TypeError, ValueError):
            frequency_hz = None

        detection = {
            "kind": "detection",
            "event_type": "detection",
            "detection_kind": "wifi_geolocate_all",
            "detector": "wifi_geolocate_all",
            "target_id": target_id,
            "node_uid": str(self.node_uid),
            "source_id": self.source_id,
            "opid": self.opid,
            "operation_id": self.opid,
            "timestamp": float(timestamp_epoch),
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
            "aggregation_window_s": float(
                self.aggregation_window_s
            ),
            "aggregation_sample_count": int(sample_count),
            "spatial_cluster_radius_m": float(
                self.cluster_radius_m
            ),
            "measurement_spacing_m": float(
                self.measurement_spacing_m
            ),
            "source_last_seen": str(
                row.get("source_last_seen") or ""
            ),
            "location_source": location_source,
            "location_semantics": "receiver_observation",
            "location_valid": True,
        }
        await self._call(
            self.detection_callback,
            {
                key: value
                for key, value in detection.items()
                if value is not None
            },
        )

    async def run(self) -> None:
        try:
            self._apply_parameters_from_runner()
            if not self.detection_callback:
                raise RuntimeError(
                    "wifi_geolocate_all requires detection_callback"
                )
            if (
                self.auto_create_targets
                and not self.target_callback
            ):
                raise RuntimeError(
                    "wifi_geolocate_all auto-create mode "
                    "requires target_callback"
                )

            mode_text = (
                f"tracking {len(self.target_bssids)} "
                "known Wi-Fi Targets"
                if self.target_bssids
                else "discovering and geolocating visible Wi-Fi APs"
            )
            await self._set_status(
                f"Wi-Fi locate all: {mode_text}"
            )

            (
                self._airodump_proc,
                self._airodump_iface_in_use,
            ) = await self._start_airodump()
            if not self._airodump_proc:
                return

            while not self._should_stop():
                rows = await self._to_thread_compat(
                    self._read_airodump_rows_once
                )
                rows.sort(
                    key=lambda row: (
                        float(row.get("rssi_dbm"))
                        if row.get("rssi_dbm") is not None
                        else -999.0
                    ),
                    reverse=True,
                )

                position = self._snapshot_position()
                position_valid = bool(
                    position.get("valid", False)
                )
                now_epoch = time.time()
                visible_tracked = 0

                for row in rows:
                    bssid_norm = str(
                        row.get("bssid_norm") or ""
                    ).strip()
                    rssi = row.get("rssi_dbm")
                    if not bssid_norm or rssi is None:
                        continue

                    if (
                        self.target_bssids
                        and bssid_norm
                        not in self.target_bssids
                    ):
                        continue

                    source_last_seen = str(
                        row.get("source_last_seen") or ""
                    ).strip()
                    if not source_last_seen:
                        continue

                    previous_source_seen = (
                        self._last_source_seen_by_bssid.get(
                            bssid_norm
                        )
                    )
                    if previous_source_seen == source_last_seen:
                        continue

                    # Consume the airodump sighting before position
                    # validation. A stale cumulative row must never be
                    # paired later with a newer receiver position.
                    self._last_source_seen_by_bssid[
                        bssid_norm
                    ] = source_last_seen

                    if not position_valid:
                        continue

                    target_id = await self._ensure_target(
                        row,
                        position,
                    )
                    if not target_id:
                        continue

                    visible_tracked += 1

                    cluster = self._clusters_by_bssid.get(
                        bssid_norm
                    )
                    if cluster is None:
                        self._start_cluster(
                            bssid_norm,
                            row,
                            position,
                            now_epoch,
                        )
                        continue

                    distance_from_anchor = self._distance_m(
                        float(cluster["anchor_latitude"]),
                        float(cluster["anchor_longitude"]),
                        float(position["latitude"]),
                        float(position["longitude"]),
                    )

                    if (
                        distance_from_anchor
                        > self.cluster_radius_m
                    ):
                        await self._finalize_cluster(
                            bssid_norm,
                            "receiver_moved",
                        )
                        self._start_cluster(
                            bssid_norm,
                            row,
                            position,
                            now_epoch,
                        )
                    elif not cluster.get("settled", False):
                        self._add_cluster_sample(
                            bssid_norm,
                            row,
                            now_epoch,
                        )

                await self._finalize_ready_clusters()

                if not position_valid:
                    await self._set_status(
                        f"Wi-Fi locate all: {mode_text}; "
                        "waiting for valid Sensor Node position"
                    )
                elif self.target_bssids:
                    await self._set_status(
                        f"Wi-Fi locate all: "
                        f"{visible_tracked}/"
                        f"{len(self.target_bssids)} "
                        "known Targets updated"
                    )
                else:
                    limit_text = (
                        "unlimited"
                        if self.max_targets == 0
                        else str(self.max_targets)
                    )
                    await self._set_status(
                        f"Wi-Fi locate all: "
                        f"{len(self._announced_targets)}/"
                        f"{limit_text} auto Targets, "
                        f"{visible_tracked} updated"
                    )

                await asyncio.sleep(self.meas_every_s)

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.logger.exception(
                f"Wi-Fi geolocate all error: {exc}"
            )
        finally:
            try:
                await self._finalize_all_clusters()
            except Exception:
                self.logger.exception(
                    "Unable to finalize Wi-Fi geolocation clusters"
                )

            await self._stop_runtime()



if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})