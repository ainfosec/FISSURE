#!/usr/bin/env python3
"""FISSURE - Dense Wi-Fi Wardrive Logger

High-volume Wi-Fi collection for driving, walking, and drone surveys. Keeps
collection local during the run, maintains one run-wide BSSID summary, records
only spatially or RF-useful observations, and normally creates one Artifact
when the operation stops. It does not create Detections, Targets, or
geolocation solutions.
"""

import asyncio
import csv
import glob
import json
import logging
import math
import os
import shutil
import subprocess
import sys
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

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
    def __init__(
        self,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback=None,
        status_callback: Union[Callable, None] = None,
        target_callback=None,
        position_callback=None,
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
            position_callback=position_callback,
            artifact_manager=artifact_manager,
        )
        self.parameters = parameters or {}
        self.source_id = str(node_uid or "").strip() or "sensor_node"
        self.wifi_interface = "wlx00c0caa744fc"
        self.mon_suffix = MON_SUFFIX_DEFAULT
        self.airo_prefix = "/tmp/airodump"
        self.airo_csv_glob = self.airo_prefix + "-*.csv"

        self.scan_interval_s = 0.5
        self.observation_max_gap_s = 10.0
        self.observation_distance_m = 20.0
        self.observation_rssi_change_db = 8.0
        self.artifact_rollover_mb = 250.0
        self.status_interval_s = 5.0
        self.checkpoint_interval_s = 30.0
        self.alert_every_unique = 0
        self.alert_on_artifact = False
        self.artifact_name_prefix = "Wi-Fi Wardrive"

        self._airodump_proc: Optional[asyncio.subprocess.Process] = None
        self._run_id = str(uuid.uuid4())
        self._run_started_epoch = time.time()
        self._run_stamp = time.strftime(
            "%Y%m%d_%H%M%S",
            time.gmtime(self._run_started_epoch),
        )

        self._summaries: Dict[str, Dict[str, Any]] = {}
        self._seen_bssids_total: Set[str] = set()
        self._seen_ssids_total: Set[str] = set()
        self._last_source_seen_by_bssid: Dict[str, str] = {}
        self._last_logged_by_bssid: Dict[str, Dict[str, Any]] = {}
        self._raw_sighting_count_total = 0
        self._logged_observation_count_total = 0

        self._last_alert_unique_count = 0
        self._last_status_epoch = 0.0
        self._last_checkpoint_epoch = 0.0

        self._part_index = 0
        self._part_operation_id = ""
        self._part_folder = ""
        self._part_started_epoch = 0.0
        self._part_observation_count = 0
        self._part_observation_path = ""
        self._part_summary_path = ""
        self._part_metadata_path = ""
        self._observation_file = None
        self._observation_writer = None
        self._artifact_ids: List[str] = []

    def _apply_parameters_from_runner(self) -> None:
        p = self.parameters if isinstance(self.parameters, dict) else {}
        self.source_id = str(
            p.get("source_id")
            or p.get("node_uid")
            or self.node_uid
            or "sensor_node"
        ).strip()
        self.wifi_interface = str(
            p.get("wifi_interface", self.wifi_interface)
            or self.wifi_interface
        )
        self.mon_suffix = str(
            p.get("mon_suffix", self.mon_suffix)
            or self.mon_suffix
        )
        self.airo_prefix = str(
            p.get("airo_prefix", self.airo_prefix)
            or self.airo_prefix
        )
        self.airo_csv_glob = self.airo_prefix + "-*.csv"

        self.scan_interval_s = max(
            0.2,
            float(p.get("scan_interval_s", self.scan_interval_s)),
        )
        self.observation_max_gap_s = max(
            0.0,
            float(
                p.get(
                    "observation_max_gap_s",
                    self.observation_max_gap_s,
                )
            ),
        )
        self.observation_distance_m = max(
            0.0,
            float(
                p.get(
                    "observation_distance_m",
                    self.observation_distance_m,
                )
            ),
        )
        self.observation_rssi_change_db = max(
            0.0,
            float(
                p.get(
                    "observation_rssi_change_db",
                    self.observation_rssi_change_db,
                )
            ),
        )
        self.artifact_rollover_mb = max(
            0.0,
            float(
                p.get(
                    "artifact_rollover_mb",
                    self.artifact_rollover_mb,
                )
            ),
        )
        self.alert_every_unique = max(
            0,
            int(p.get("alert_every_unique", self.alert_every_unique)),
        )
        self.alert_on_artifact = _to_bool(
            p.get("alert_on_artifact", self.alert_on_artifact),
            self.alert_on_artifact,
        )
        self.artifact_name_prefix = str(
            p.get("artifact_name_prefix", self.artifact_name_prefix)
            or self.artifact_name_prefix
        )
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

    async def _emit_alert(self, message: str, uid: str, alert_kind: str, extra: Optional[Dict[str, Any]] = None) -> None:
        if not self.alert_callback:
            return
        payload = {
            "uid": uid,
            "alert_kind": alert_kind,
            "alert_summary": message,
            "message": message,
            "node_uid": self.node_uid,
            "source_id": self.source_id,
            "operation_id": self.opid,
            "opid": self.opid,
            "plot_pin": False,
            "timestamp": time.time(),
        }
        if extra:
            payload.update(extra)
        try:
            await self._call(self.alert_callback, payload)
        except Exception:
            self.logger.exception("alert_callback failed")

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
                beacon_count = int(float(r[9].strip())) if r[9].strip() else None
                source_last_seen = r[2].strip()
                ssid = r[13].strip(" ,\t\r\n")
                if ssid.lower() in {"<hidden>", "broadcast", "unknown"}:
                    ssid = ""

                band, frequency_mhz = _channel_info(channel)
                out.append({
                    "bssid": bssid,
                    "bssid_norm": bssid_norm,
                    "ssid": ssid,
                    "channel": channel,
                    "band": band,
                    "frequency_mhz": frequency_mhz,
                    "rssi_dbm": rssi,
                    "encryption": r[5].strip(),
                    "beacon_count": beacon_count,
                    "source_last_seen": source_last_seen,
                })
            except Exception:
                continue
        return out

    def _snapshot_position(self) -> Dict[str, Any]:
        try:
            position = self.position_callback()
        except Exception as exc:
            self.logger.warning(f"Position callback failed: {exc}")
            return {"location_valid": False, "location_source": ""}

        if not isinstance(position, dict) or not position.get("valid", False):
            return {
                "location_valid": False,
                "location_source": str(
                    position.get("source") or ""
                    if isinstance(position, dict)
                    else ""
                ),
            }

        lat = position.get("latitude")
        lon = position.get("longitude")
        alt = position.get("altitude")
        if lat is None or lon is None:
            return {
                "location_valid": False,
                "location_source": str(position.get("source") or ""),
            }

        return {
            "location_valid": True,
            "location_source": str(position.get("source") or ""),
            "latitude": float(lat),
            "longitude": float(lon),
            "altitude_m": float(alt or 0.0),
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

    def _observation_reason(
        self,
        bssid_norm: str,
        now_epoch: float,
        position: Dict[str, Any],
        rssi_dbm: Optional[float],
    ) -> str:
        previous = self._last_logged_by_bssid.get(bssid_norm)
        if previous is None:
            return "new_bssid"

        previous_valid = bool(previous.get("location_valid", False))
        current_valid = bool(position.get("location_valid", False))

        if previous_valid != current_valid:
            return "location_state_changed"

        if (
            previous_valid
            and current_valid
            and self.observation_distance_m > 0
        ):
            distance = self._distance_m(
                float(previous["latitude"]),
                float(previous["longitude"]),
                float(position["latitude"]),
                float(position["longitude"]),
            )
            if distance >= self.observation_distance_m:
                return "receiver_moved"

        previous_rssi = previous.get("rssi_dbm")
        if (
            rssi_dbm is not None
            and previous_rssi is not None
            and self.observation_rssi_change_db > 0
            and abs(float(rssi_dbm) - float(previous_rssi))
            >= self.observation_rssi_change_db
        ):
            return "rssi_changed"

        if self.observation_max_gap_s > 0:
            elapsed = now_epoch - float(previous.get("timestamp_epoch", 0.0))
            if elapsed >= self.observation_max_gap_s:
                return "time_gap"

        return ""

    def _observation_fields(self) -> List[str]:
        return [
            "run_id",
            "part_index",
            "timestamp_iso",
            "timestamp_epoch",
            "source_last_seen",
            "node_uid",
            "source_id",
            "latitude",
            "longitude",
            "altitude_m",
            "location_valid",
            "location_source",
            "bssid",
            "ssid",
            "rssi_dbm",
            "channel",
            "band",
            "frequency_mhz",
            "encryption",
            "beacon_count",
            "reason",
            "location_semantics",
        ]

    def _summary_fields(self) -> List[str]:
        return [
            "run_id",
            "node_uid",
            "source_id",
            "bssid",
            "ssid",
            "first_seen_iso",
            "first_seen_epoch",
            "first_latitude",
            "first_longitude",
            "first_location_source",
            "last_seen_iso",
            "last_seen_epoch",
            "last_latitude",
            "last_longitude",
            "last_location_source",
            "strongest_seen_iso",
            "strongest_seen_epoch",
            "strongest_rssi_dbm",
            "strongest_latitude",
            "strongest_longitude",
            "strongest_location_source",
            "latest_rssi_dbm",
            "raw_sighting_count",
            "logged_observation_count",
            "channel",
            "band",
            "frequency_mhz",
            "encryption",
            "latest_beacon_count",
            "latest_source_last_seen",
        ]

    def _start_part(self) -> None:
        self._part_index += 1
        self._part_operation_id = str(uuid.uuid4())
        self._part_started_epoch = time.time()
        self._part_observation_count = 0

        if self.artifact_manager:
            _, self._part_folder = self.artifact_manager.create_operation_dir(
                self._part_operation_id
            )
        else:
            self._part_folder = os.path.join(
                "/tmp",
                f"fissure_wifi_wardrive_{self._run_id}",
                f"part_{self._part_index:04d}",
            )
            os.makedirs(self._part_folder, exist_ok=True)

        self._part_observation_path = os.path.join(
            self._part_folder,
            "observations.csv",
        )
        self._part_summary_path = os.path.join(
            self._part_folder,
            "summary.csv",
        )
        self._part_metadata_path = os.path.join(
            self._part_folder,
            "metadata.json",
        )

        self._observation_file = open(
            self._part_observation_path,
            "w",
            newline="",
            encoding="utf-8",
        )
        self._observation_writer = csv.DictWriter(
            self._observation_file,
            fieldnames=self._observation_fields(),
        )
        self._observation_writer.writeheader()

    def _append_observation(
        self,
        row: Dict[str, Any],
        position: Dict[str, Any],
        now_epoch: float,
        reason: str,
    ) -> None:
        if self._observation_writer is None:
            raise RuntimeError("Wardrive observation writer is not open")

        now_iso = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(now_epoch),
        )
        observation = {
            "run_id": self._run_id,
            "part_index": self._part_index,
            "timestamp_iso": now_iso,
            "timestamp_epoch": now_epoch,
            "source_last_seen": row.get("source_last_seen", ""),
            "node_uid": self.node_uid,
            "source_id": self.source_id,
            "latitude": (
                position.get("latitude")
                if position.get("location_valid")
                else None
            ),
            "longitude": (
                position.get("longitude")
                if position.get("location_valid")
                else None
            ),
            "altitude_m": (
                position.get("altitude_m")
                if position.get("location_valid")
                else None
            ),
            "location_valid": bool(
                position.get("location_valid", False)
            ),
            "location_source": position.get("location_source", ""),
            "bssid": row.get("bssid", ""),
            "ssid": row.get("ssid", ""),
            "rssi_dbm": row.get("rssi_dbm"),
            "channel": row.get("channel"),
            "band": row.get("band", ""),
            "frequency_mhz": row.get("frequency_mhz"),
            "encryption": row.get("encryption", ""),
            "beacon_count": row.get("beacon_count"),
            "reason": reason,
            "location_semantics": "receiver_observation",
        }

        self._observation_writer.writerow(observation)
        self._part_observation_count += 1
        self._logged_observation_count_total += 1

        self._last_logged_by_bssid[row["bssid_norm"]] = {
            "timestamp_epoch": now_epoch,
            "location_valid": observation["location_valid"],
            "latitude": observation["latitude"],
            "longitude": observation["longitude"],
            "rssi_dbm": observation["rssi_dbm"],
        }

    def _record_sighting(
        self,
        row: Dict[str, Any],
        now_epoch: float,
    ) -> bool:
        bssid_norm = row.get("bssid_norm", "")
        if not bssid_norm:
            return False

        source_last_seen = str(
            row.get("source_last_seen") or ""
        ).strip()
        if source_last_seen:
            previous_source_seen = self._last_source_seen_by_bssid.get(
                bssid_norm
            )
            if previous_source_seen == source_last_seen:
                return False
            self._last_source_seen_by_bssid[
                bssid_norm
            ] = source_last_seen

        self._raw_sighting_count_total += 1
        self._seen_bssids_total.add(bssid_norm)

        ssid = str(row.get("ssid") or "").strip()
        if ssid:
            self._seen_ssids_total.add(ssid)

        position = self._snapshot_position()
        now_iso = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(now_epoch),
        )
        rssi = row.get("rssi_dbm")
        summary = self._summaries.get(bssid_norm)
        new_strongest = False

        if summary is None:
            summary = {
                "run_id": self._run_id,
                "node_uid": self.node_uid,
                "source_id": self.source_id,
                "bssid": row.get("bssid", ""),
                "ssid": ssid,
                "first_seen_iso": now_iso,
                "first_seen_epoch": now_epoch,
                "first_latitude": (
                    position.get("latitude")
                    if position.get("location_valid")
                    else None
                ),
                "first_longitude": (
                    position.get("longitude")
                    if position.get("location_valid")
                    else None
                ),
                "first_location_source": position.get(
                    "location_source",
                    "",
                ),
                "last_seen_iso": now_iso,
                "last_seen_epoch": now_epoch,
                "last_latitude": (
                    position.get("latitude")
                    if position.get("location_valid")
                    else None
                ),
                "last_longitude": (
                    position.get("longitude")
                    if position.get("location_valid")
                    else None
                ),
                "last_location_source": position.get(
                    "location_source",
                    "",
                ),
                "strongest_seen_iso": now_iso,
                "strongest_seen_epoch": now_epoch,
                "strongest_rssi_dbm": rssi,
                "strongest_latitude": (
                    position.get("latitude")
                    if position.get("location_valid")
                    else None
                ),
                "strongest_longitude": (
                    position.get("longitude")
                    if position.get("location_valid")
                    else None
                ),
                "strongest_location_source": position.get(
                    "location_source",
                    "",
                ),
                "latest_rssi_dbm": rssi,
                "raw_sighting_count": 1,
                "logged_observation_count": 0,
                "channel": row.get("channel"),
                "band": row.get("band", ""),
                "frequency_mhz": row.get("frequency_mhz"),
                "encryption": row.get("encryption", ""),
                "latest_beacon_count": row.get("beacon_count"),
                "latest_source_last_seen": source_last_seen,
            }
            self._summaries[bssid_norm] = summary
            new_strongest = True
        else:
            summary["last_seen_iso"] = now_iso
            summary["last_seen_epoch"] = now_epoch
            summary["last_latitude"] = (
                position.get("latitude")
                if position.get("location_valid")
                else None
            )
            summary["last_longitude"] = (
                position.get("longitude")
                if position.get("location_valid")
                else None
            )
            summary["last_location_source"] = position.get(
                "location_source",
                "",
            )
            summary["latest_rssi_dbm"] = rssi
            summary["raw_sighting_count"] = int(
                summary.get("raw_sighting_count", 0)
            ) + 1
            summary["ssid"] = ssid or summary.get("ssid", "")
            summary["channel"] = row.get("channel")
            summary["band"] = row.get("band", "")
            summary["frequency_mhz"] = row.get("frequency_mhz")
            summary["encryption"] = row.get("encryption", "")
            summary["latest_beacon_count"] = row.get("beacon_count")
            summary["latest_source_last_seen"] = source_last_seen

            strongest = summary.get("strongest_rssi_dbm")
            if (
                rssi is not None
                and (strongest is None or float(rssi) > float(strongest))
            ):
                new_strongest = True
                summary["strongest_seen_iso"] = now_iso
                summary["strongest_seen_epoch"] = now_epoch
                summary["strongest_rssi_dbm"] = rssi
                summary["strongest_latitude"] = (
                    position.get("latitude")
                    if position.get("location_valid")
                    else None
                )
                summary["strongest_longitude"] = (
                    position.get("longitude")
                    if position.get("location_valid")
                    else None
                )
                summary["strongest_location_source"] = position.get(
                    "location_source",
                    "",
                )

        reason = self._observation_reason(
            bssid_norm,
            now_epoch,
            position,
            rssi,
        )
        if not reason:
            return False

        self._append_observation(
            row,
            position,
            now_epoch,
            reason,
        )
        summary["logged_observation_count"] = int(
            summary.get("logged_observation_count", 0)
        ) + 1
        return True

    def _write_summary(self) -> None:
        rows = list(self._summaries.values())
        temporary_path = self._part_summary_path + ".part"

        with open(
            temporary_path,
            "w",
            newline="",
            encoding="utf-8",
        ) as f:
            writer = csv.DictWriter(
                f,
                fieldnames=self._summary_fields(),
            )
            writer.writeheader()
            if rows:
                writer.writerows(rows)

        os.replace(
            temporary_path,
            self._part_summary_path,
        )

    def _metadata(
        self,
        reason: str,
        complete: bool,
    ) -> Dict[str, Any]:
        now_epoch = time.time()
        position = self._snapshot_position()
        return {
            "role": "wifi_wardrive_session_v4",
            "run_id": self._run_id,
            "part_index": self._part_index,
            "node_uid": self.node_uid,
            "source_id": self.source_id,
            "operation_id": self._part_operation_id,
            "run_started_time": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(self._run_started_epoch),
            ),
            "part_started_time": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(self._part_started_epoch),
            ),
            "created_time": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(now_epoch),
            ),
            "complete": bool(complete),
            "finalize_reason": reason,
            "unique_bssid_count_total": len(self._seen_bssids_total),
            "unique_ssid_count_total": len(self._seen_ssids_total),
            "raw_sighting_count_total": self._raw_sighting_count_total,
            "logged_observation_count_total": (
                self._logged_observation_count_total
            ),
            "logged_observation_count_part": (
                self._part_observation_count
            ),
            "summary_bssid_count": len(self._summaries),
            "summary_scope": "run_to_date",
            "observation_scope": "this_part",
            "location_semantics": "receiver_observation",
            "position_source": position.get("location_source", ""),
            "scan_interval_s": self.scan_interval_s,
            "observation_max_gap_s": self.observation_max_gap_s,
            "observation_distance_m": self.observation_distance_m,
            "observation_rssi_change_db": (
                self.observation_rssi_change_db
            ),
            "artifact_rollover_mb": self.artifact_rollover_mb,
            "summary_filename": os.path.basename(
                self._part_summary_path
            ),
            "observations_filename": os.path.basename(
                self._part_observation_path
            ),
        }

    def _write_metadata(
        self,
        reason: str,
        complete: bool,
    ) -> None:
        metadata = self._metadata(reason, complete)
        temporary_path = self._part_metadata_path + ".part"

        with open(
            temporary_path,
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(metadata, f, indent=2)

        os.replace(
            temporary_path,
            self._part_metadata_path,
        )

    def _checkpoint(self) -> None:
        if self._observation_file is not None:
            self._observation_file.flush()
        self._write_summary()
        self._write_metadata("running", False)

    def _part_size_mb(self) -> float:
        try:
            return os.path.getsize(
                self._part_observation_path
            ) / (1024.0 * 1024.0)
        except OSError:
            return 0.0

    async def _finalize_part(
        self,
        reason: str,
        *,
        start_next: bool,
    ) -> None:
        if self._observation_file is not None:
            self._observation_file.flush()
            self._observation_file.close()
            self._observation_file = None
            self._observation_writer = None

        if self._part_observation_count <= 0:
            self.logger.info(
                f"Wi-Fi wardrive part {self._part_index} had no observations; "
                "no Artifact created"
            )
            if start_next:
                self._start_part()
            return

        self._write_summary()
        self._write_metadata(reason, True)

        artifact_id = ""
        if self.artifact_manager:
            metadata = self._metadata(reason, True)
            name = (
                f"{self.artifact_name_prefix} "
                f"{self._run_stamp} Part {self._part_index}"
            )
            try:
                artifact_id = (
                    self.artifact_manager.create_zip_artifact_from_folder(
                        source_id=self.source_id,
                        operation_id=self._part_operation_id,
                        folder=self._part_folder,
                        name=name,
                        metadata=metadata,
                        arc_prefix=(
                            f"wifi_wardrive_{self._run_id}"
                            f"_part_{self._part_index:04d}"
                        ),
                    )
                )
            except Exception as exc:
                self.logger.warning(
                    f"Wardrive Artifact creation failed: {exc}"
                )

        if artifact_id:
            self._artifact_ids.append(str(artifact_id))

        self.logger.info(
            f"Wi-Fi wardrive part {self._part_index} saved "
            f"({reason}): "
            f"{len(self._seen_bssids_total)} BSSIDs, "
            f"{len(self._seen_ssids_total)} SSIDs, "
            f"{self._part_observation_count} observations, "
            f"artifact={artifact_id or '<none>'}"
        )

        if self.alert_on_artifact:
            await self._emit_alert(
                (
                    f"Wi-Fi wardrive saved: "
                    f"{len(self._seen_bssids_total)} BSSIDs / "
                    f"{self._part_observation_count} observations"
                ),
                (
                    f"wifi-wardrive-artifact-"
                    f"{self._run_id}-{self._part_index}"
                ),
                "wifi_wardrive_artifact",
                {
                    "run_id": self._run_id,
                    "part_index": self._part_index,
                    "artifact_id": artifact_id,
                },
            )

        if start_next:
            self._start_part()

    async def _maybe_rollover(self) -> None:
        if self.artifact_rollover_mb <= 0:
            return
        if self._part_size_mb() < self.artifact_rollover_mb:
            return

        await self._finalize_part(
            "size rollover",
            start_next=True,
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

    async def run(self) -> None:
        try:
            self._apply_parameters_from_runner()
            self._start_part()
            await self._set_status("Logging Wi-Fi")

            self._airodump_proc, _ = await self._start_airodump()
            if not self._airodump_proc:
                return

            while not self._should_stop():
                rows = await self._to_thread_compat(
                    self._read_airodump_rows_once
                )
                now = time.time()

                for row in rows:
                    bssid_norm = row.get("bssid_norm", "")
                    if not bssid_norm:
                        continue

                    before = len(self._seen_bssids_total)
                    logged = self._record_sighting(row, now)

                    if (
                        len(self._seen_bssids_total) > before
                        and self.alert_every_unique > 0
                    ):
                        count = len(self._seen_bssids_total)
                        if (
                            count - self._last_alert_unique_count
                        ) >= self.alert_every_unique:
                            self._last_alert_unique_count = count
                            await self._emit_alert(
                                (
                                    f"Wi-Fi wardrive has observed "
                                    f"{count} unique BSSIDs"
                                ),
                                (
                                    f"wifi-wardrive-unique-"
                                    f"{self._run_id}-{count}"
                                ),
                                "wifi_wardrive_summary",
                                {
                                    "run_id": self._run_id,
                                    "unique_bssid_count_total": count,
                                },
                            )

                    if logged:
                        await asyncio.sleep(0)

                if (
                    now - self._last_checkpoint_epoch
                ) >= self.checkpoint_interval_s:
                    self._last_checkpoint_epoch = now
                    await self._to_thread_compat(self._checkpoint)

                await self._maybe_rollover()

                if (
                    now - self._last_status_epoch
                ) >= self.status_interval_s:
                    self._last_status_epoch = now
                    position = self._snapshot_position()
                    gps_state = (
                        position.get("location_source") or "GPS"
                        if position.get("location_valid")
                        else "no GPS"
                    )
                    await self._set_status(
                        f"Wi-Fi logger: "
                        f"{len(self._seen_bssids_total)} BSSIDs / "
                        f"{len(self._seen_ssids_total)} SSIDs, "
                        f"{self._logged_observation_count_total} "
                        f"observations, "
                        f"{self._part_size_mb():.1f} MB "
                        f"({gps_state})"
                    )

                await asyncio.sleep(self.scan_interval_s)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("Wi-Fi wardrive logger failed")
        finally:
            try:
                if self._part_folder:
                    await self._finalize_part(
                        "operation stopped",
                        start_next=False,
                    )
            except Exception:
                self.logger.exception(
                    "Final Wi-Fi wardrive Artifact creation failed"
                )

            try:
                await self._stop_runtime()
            except Exception:
                self.logger.exception("Wi-Fi wardrive cleanup failed")

            await self._set_status("Idle")
            self.logger.info(
                f"Wi-Fi wardrive stopped. "
                f"Unique BSSIDs: {len(self._seen_bssids_total)}, "
                f"unique SSIDs: {len(self._seen_ssids_total)}, "
                f"observations: {self._logged_observation_count_total}"
            )

    async def _to_thread_compat(self, func, *args, **kwargs):
        if hasattr(asyncio, "to_thread"):
            return await asyncio.to_thread(func, *args, **kwargs)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})