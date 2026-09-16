#!/usr/bin/env python3
"""FISSURE - Dense Wi-Fi Wardrive Logger

High-volume Wi-Fi collection for driving, walking, and drone surveys. Keeps the
large observation stream local and writes bounded summary/observation batches
directly into FISSURE Artifacts. It does not create Detections, Targets, or
geolocation solutions.
"""

import asyncio
import csv
import glob
import json
import logging
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
    def __init__(self, node_uid: str = "", logger: logging.Logger = logging.getLogger(__name__), alert_callback: Union[Callable, None] = None, tak_cot_callback=None, status_callback: Union[Callable, None] = None, target_callback=None, artifact_manager=None, parameters: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(node_uid=node_uid, logger=logger, alert_callback=alert_callback, tak_cot_callback=tak_cot_callback, status_callback=status_callback, target_callback=target_callback, artifact_manager=artifact_manager)
        self.parameters = parameters or {}
        self.source_id = str(node_uid or "").strip() or "sensor_node"
        self.wifi_interface = "wlx00c0caa744fc"
        self.mon_suffix = MON_SUFFIX_DEFAULT
        self.airo_prefix = "/tmp/airodump"
        self.airo_csv_glob = self.airo_prefix + "-*.csv"
        self.gpsd_host = "127.0.0.1"
        self.gpsd_port = 2947
        self.scan_interval_s = 0.5
        self.observation_interval_s = 2.0
        self.batch_unique_devices = 500
        self.batch_observation_rows = 5000
        self.batch_duration_s = 300.0
        self.alert_every_unique = 0
        self.alert_on_batch = False
        self.artifact_name_prefix = "Wi-Fi Wardrive Batch"
        self._gps_stop = asyncio.Event()
        self._current_position = {"lat": None, "lon": None, "alt": 0.0}
        self._airodump_proc: Optional[asyncio.subprocess.Process] = None
        self._batch_summaries: Dict[str, Dict[str, Any]] = {}
        self._batch_observations: List[Dict[str, Any]] = []
        self._seen_bssids_total: Set[str] = set()
        self._last_observation_time_by_bssid: Dict[str, float] = {}
        self._last_alert_unique_count = 0
        self._batch_index = 0
        self._batch_started_epoch = time.time()
        self._run_id = str(uuid.uuid4())

    def _apply_parameters_from_runner(self) -> None:
        p = self.parameters if isinstance(self.parameters, dict) else {}
        self.source_id = str(p.get("source_id") or p.get("node_uid") or self.node_uid or "sensor_node").strip()
        self.wifi_interface = str(p.get("wifi_interface", self.wifi_interface) or self.wifi_interface)
        self.mon_suffix = str(p.get("mon_suffix", self.mon_suffix) or self.mon_suffix)
        self.airo_prefix = str(p.get("airo_prefix", self.airo_prefix) or self.airo_prefix)
        self.airo_csv_glob = self.airo_prefix + "-*.csv"
        self.gpsd_host = str(p.get("gpsd_host", self.gpsd_host) or self.gpsd_host)
        self.gpsd_port = int(p.get("gpsd_port", self.gpsd_port))
        self.scan_interval_s = max(0.2, float(p.get("scan_interval_s", p.get("wifi_refresh_interval", self.scan_interval_s))))
        self.observation_interval_s = max(0.0, float(p.get("observation_interval_s", p.get("min_log_interval_s", self.observation_interval_s))))
        self.batch_unique_devices = max(1, int(p.get("batch_unique_devices", self.batch_unique_devices)))
        self.batch_observation_rows = max(1, int(p.get("batch_observation_rows", self.batch_observation_rows)))
        self.batch_duration_s = max(0.0, float(p.get("batch_duration_s", self.batch_duration_s)))
        self.alert_every_unique = max(0, int(p.get("alert_every_unique", self.alert_every_unique)))
        self.alert_on_batch = _to_bool(p.get("alert_on_batch", self.alert_on_batch), self.alert_on_batch)
        self.artifact_name_prefix = str(p.get("artifact_name_prefix", self.artifact_name_prefix) or self.artifact_name_prefix)
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
                beacon_count = int(float(r[9].strip())) if r[9].strip() else None
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
                self.logger.debug(f"GPS unavailable: {exc}")
                await asyncio.sleep(2.0)

    def _record_observation(self, row: Dict[str, Any], now_epoch: float) -> bool:
        bssid_norm = row.get("bssid_norm", "")
        if not bssid_norm:
            return False

        last = self._last_observation_time_by_bssid.get(bssid_norm)
        if last is not None and self.observation_interval_s > 0 and (now_epoch - last) < self.observation_interval_s:
            return False
        self._last_observation_time_by_bssid[bssid_norm] = now_epoch

        lat = self._current_position.get("lat")
        lon = self._current_position.get("lon")
        alt = self._current_position.get("alt")
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch))
        observation = {
            "run_id": self._run_id,
            "batch_index": self._batch_index + 1,
            "timestamp_iso": now_iso,
            "timestamp_epoch": now_epoch,
            "node_uid": self.node_uid,
            "source_id": self.source_id,
            "latitude": float(lat) if lat is not None else None,
            "longitude": float(lon) if lon is not None else None,
            "altitude_m": float(alt or 0.0) if lat is not None and lon is not None else None,
            "location_valid": bool(lat is not None and lon is not None),
            "bssid": row.get("bssid", ""),
            "ssid": row.get("ssid", ""),
            "rssi_dbm": row.get("rssi_dbm"),
            "channel": row.get("channel"),
            "band": row.get("band", ""),
            "frequency_mhz": row.get("frequency_mhz"),
            "encryption": row.get("encryption", ""),
            "beacon_count": row.get("beacon_count"),
            "location_semantics": "receiver_observation",
        }
        self._batch_observations.append(observation)

        summary = self._batch_summaries.get(bssid_norm)
        if summary is None:
            summary = {
                "run_id": self._run_id,
                "batch_index": self._batch_index + 1,
                "node_uid": self.node_uid,
                "source_id": self.source_id,
                "bssid": row.get("bssid", ""),
                "ssid": row.get("ssid", ""),
                "first_seen_iso": now_iso,
                "first_seen_epoch": now_epoch,
                "last_seen_iso": now_iso,
                "last_seen_epoch": now_epoch,
                "first_latitude": observation["latitude"],
                "first_longitude": observation["longitude"],
                "last_latitude": observation["latitude"],
                "last_longitude": observation["longitude"],
                "strongest_rssi_dbm": row.get("rssi_dbm"),
                "strongest_latitude": observation["latitude"],
                "strongest_longitude": observation["longitude"],
                "latest_rssi_dbm": row.get("rssi_dbm"),
                "logged_observation_count": 1,
                "channel": row.get("channel"),
                "band": row.get("band", ""),
                "frequency_mhz": row.get("frequency_mhz"),
                "encryption": row.get("encryption", ""),
                "latest_beacon_count": row.get("beacon_count"),
            }
            self._batch_summaries[bssid_norm] = summary
            return True

        summary["last_seen_iso"] = now_iso
        summary["last_seen_epoch"] = now_epoch
        summary["last_latitude"] = observation["latitude"]
        summary["last_longitude"] = observation["longitude"]
        summary["latest_rssi_dbm"] = row.get("rssi_dbm")
        summary["logged_observation_count"] = int(summary.get("logged_observation_count", 0)) + 1
        summary["ssid"] = row.get("ssid", "") or summary.get("ssid", "")
        summary["channel"] = row.get("channel")
        summary["band"] = row.get("band", "")
        summary["frequency_mhz"] = row.get("frequency_mhz")
        summary["encryption"] = row.get("encryption", "")
        summary["latest_beacon_count"] = row.get("beacon_count")

        rssi = row.get("rssi_dbm")
        strongest = summary.get("strongest_rssi_dbm")
        if rssi is not None and (strongest is None or rssi > strongest):
            summary["strongest_rssi_dbm"] = rssi
            summary["strongest_latitude"] = observation["latitude"]
            summary["strongest_longitude"] = observation["longitude"]
        return True

    def _write_csv(self, path: str, rows: List[Dict[str, Any]]) -> None:
        if not rows:
            return
        fieldnames = list(rows[0].keys())
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    def _write_batch_files(
        self,
        summaries: List[Dict[str, Any]],
        observations: List[Dict[str, Any]],
        batch_index: int,
        folder: str,
    ) -> Tuple[str, str]:
        os.makedirs(folder, exist_ok=True)

        stamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        prefix = os.path.join(
            folder,
            f"wifi_wardrive_batch_{batch_index:04d}_{stamp}",
        )
        summary_path = prefix + "_summary.csv"
        observations_path = prefix + "_observations.csv"

        self._write_csv(summary_path, summaries)
        self._write_csv(observations_path, observations)

        return summary_path, observations_path

    def _create_batch_artifact(
        self,
        summaries: List[Dict[str, Any]],
        observations: List[Dict[str, Any]],
        batch_index: int,
    ) -> Tuple[str, str, str]:
        if not self.artifact_manager:
            raise RuntimeError("Artifact manager is unavailable")

        operation_id = str(uuid.uuid4())
        _, folder = self.artifact_manager.create_operation_dir(operation_id)

        summary_path, observations_path = self._write_batch_files(
            summaries,
            observations,
            batch_index,
            folder,
        )

        valid_positions = sum(
            1
            for row in observations
            if row.get("location_valid")
        )
        metadata = {
            "role": "wifi_wardrive_batch_v3",
            "run_id": self._run_id,
            "batch_index": batch_index,
            "node_uid": self.node_uid,
            "source_id": self.source_id,
            "operation_id": operation_id,
            "unique_bssid_count_batch": len(summaries),
            "observation_count_batch": len(observations),
            "observations_with_position": valid_positions,
            "unique_bssid_count_total": len(self._seen_bssids_total),
            "created_time": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(),
            ),
            "summary_filename": os.path.basename(summary_path),
            "observations_filename": os.path.basename(observations_path),
            "location_semantics": "receiver_observation",
        }

        with open(
            os.path.join(folder, "batch_metadata.json"),
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(metadata, f, indent=2)

        artifact = self.artifact_manager.create_zip_artifact_from_folder(
            source_id=self.source_id,
            operation_id=operation_id,
            folder=folder,
            name=f"{self.artifact_name_prefix} #{batch_index}",
            metadata=metadata,
            arc_prefix=f"wifi_wardrive_{operation_id}",
        )
        artifact_id = str(
            getattr(artifact, "id", artifact)
            if artifact
            else ""
        )

        return artifact_id, summary_path, observations_path

    async def _flush_batch(self, reason: str) -> None:
        if not self._batch_observations:
            self._batch_started_epoch = time.time()
            return

        summaries = list(self._batch_summaries.values())
        observations = list(self._batch_observations)
        next_batch_index = self._batch_index + 1

        artifact_id = ""
        summary_path = ""
        observations_path = ""

        try:
            (
                artifact_id,
                summary_path,
                observations_path,
            ) = self._create_batch_artifact(
                summaries,
                observations,
                next_batch_index,
            )
        except Exception as exc:
            self.logger.warning(
                f"Artifact creation failed for batch "
                f"{next_batch_index}: {exc}"
            )
            return

        self._batch_summaries.clear()
        self._batch_observations.clear()
        self._last_observation_time_by_bssid.clear()
        self._batch_index = next_batch_index
        self._batch_started_epoch = time.time()

        self.logger.info(
            f"Wi-Fi wardrive batch {self._batch_index} saved "
            f"to Artifact ({reason}): "
            f"{len(summaries)} BSSIDs, "
            f"{len(observations)} observations, "
            f"artifact={artifact_id or '<none>'}"
        )

        if self.alert_on_batch:
            await self._emit_alert(
                (
                    f"Wi-Fi wardrive batch {self._batch_index} saved: "
                    f"{len(summaries)} BSSIDs / "
                    f"{len(observations)} observations"
                ),
                f"wifi-wardrive-batch-{self._run_id}-{self._batch_index}",
                "wifi_wardrive_batch",
                {
                    "run_id": self._run_id,
                    "batch_index": self._batch_index,
                    "artifact_id": artifact_id,
                    "summary_path": summary_path,
                    "observations_path": observations_path,
                },
            )

    async def _maybe_flush_batch(self, now_epoch: float) -> None:
        if len(self._batch_summaries) >= self.batch_unique_devices:
            await self._flush_batch("unique-device limit")
        elif len(self._batch_observations) >= self.batch_observation_rows:
            await self._flush_batch("observation-row limit")
        elif self.batch_duration_s > 0 and self._batch_observations and (now_epoch - self._batch_started_epoch) >= self.batch_duration_s:
            await self._flush_batch("time limit")

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

    async def run(self) -> None:
        gps_task = None
        try:
            self._apply_parameters_from_runner()
            await self._set_status("Logging Wi-Fi")
            gps_task = asyncio.create_task(self._gps_loop())
            self._airodump_proc, _ = await self._start_airodump()
            if not self._airodump_proc:
                return

            while not self._should_stop():
                rows = await self._to_thread_compat(self._read_airodump_rows_once)
                now = time.time()
                for row in rows:
                    bssid_norm = row.get("bssid_norm", "")
                    if not bssid_norm:
                        continue

                    before = len(self._seen_bssids_total)
                    self._seen_bssids_total.add(bssid_norm)
                    if len(self._seen_bssids_total) > before and self.alert_every_unique > 0:
                        count = len(self._seen_bssids_total)
                        if (count - self._last_alert_unique_count) >= self.alert_every_unique:
                            self._last_alert_unique_count = count
                            await self._emit_alert(
                                f"Wi-Fi wardrive has observed {count} unique BSSIDs",
                                f"wifi-wardrive-unique-{self._run_id}-{count}",
                                "wifi_wardrive_summary",
                                {"run_id": self._run_id, "unique_bssid_count_total": count},
                            )

                    self._record_observation(row, now)

                await self._maybe_flush_batch(now)
                gps_state = "GPS" if self._current_position.get("lat") is not None and self._current_position.get("lon") is not None else "no GPS"
                await self._set_status(
                    f"Wi-Fi logger: {len(self._seen_bssids_total)} unique total, "
                    f"{len(self._batch_summaries)} current BSSIDs, {len(self._batch_observations)} observations ({gps_state})"
                )
                await asyncio.sleep(self.scan_interval_s)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("Wi-Fi wardrive logger failed")
        finally:
            try:
                await self._flush_batch("operation stopped")
            except Exception:
                self.logger.exception("Final Wi-Fi wardrive batch flush failed")
            try:
                await self._stop_runtime(gps_task)
            except Exception:
                self.logger.exception("Wi-Fi wardrive cleanup failed")
            await self._set_status("Idle")
            self.logger.info(f"Wi-Fi wardrive stopped. Unique BSSIDs observed: {len(self._seen_bssids_total)}")

    async def _to_thread_compat(self, func, *args, **kwargs):
        if hasattr(asyncio, "to_thread"):
            return await asyncio.to_thread(func, *args, **kwargs)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})