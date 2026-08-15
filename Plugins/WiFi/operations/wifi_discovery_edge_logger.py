#!/usr/bin/env python3
"""
FISSURE – Wi-Fi Discovery Logger (Urban / High-Volume)
------------------------------------------------------
Purpose
-------
Observe visible Wi-Fi APs in dense environments and log summarized observations
in batches without creating targets.

Behavior
--------
- Does NOT create targets
- Does NOT geolocate
- Does NOT create per-device alerts
- Maintains one summarized record per BSSID per batch
- Throttles record updates for repeated sightings
- Writes periodic CSV batches of Wi-Fi observations
- Optionally packages each batch as a zip artifact
- Sends summary alerts periodically based on unique-device thresholds

Expected "parameters" keys:
- wifi_interface: str
- mon_suffix: str
- airo_prefix: str
- gpsd_host: str
- gpsd_port: int
- gps_refresh_interval: float
- wifi_refresh_interval: float
- log_dir: str
- batch_unique_devices: int
- min_log_interval_s: float
- alert_every_unique: int
- create_artifacts: bool
- artifact_name_prefix: str
- source_id: str
"""

import os
import sys
import csv
import glob
import time
import json
import uuid
import asyncio
import subprocess
import signal
import logging
import inspect
import shutil
from typing import Dict, Tuple, Optional, List, Any, Callable, Union, Set

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))
SCRIPTS_DIR = os.path.join(PLUGIN_ROOT, "scripts")
WIFI_LIB_DIR = os.path.join(SCRIPTS_DIR, "wifi_lib")
RESOURCES_DIR = os.path.join(PLUGIN_ROOT, "resources")

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT, SCRIPTS_DIR, WIFI_LIB_DIR, RESOURCES_DIR):
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
CALLBACK_TIMEOUT_S = 2.0


def _to_bool(v: Any, default: bool = False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)

    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    return default


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

        self.log_dir: str = os.path.join(FISSURE_ROOT, "logs", "plugins", "WiFi")
        self.batch_unique_devices: int = 500
        self.min_log_interval_s: float = 5.0
        self.alert_every_unique: int = 100
        self.create_artifacts: bool = True
        self.artifact_name_prefix: str = "Wi-Fi Urban Logger Batch"

        self._gps_stop = asyncio.Event()
        self._current_position = {"lat": None, "lon": None, "alt": 0.0}

        self._airodump_proc: Optional[asyncio.subprocess.Process] = None
        self._airodump_iface_in_use: Optional[str] = None

        self._batch_records: Dict[str, Dict[str, Any]] = {}
        self._seen_bssids_total: Set[str] = set()
        self._last_update_time_by_bssid: Dict[str, float] = {}
        self._last_alert_unique_count: int = 0
        self._batch_index: int = 0
        self._run_id: str = str(uuid.uuid4())

    # -----------------------------
    # Compatibility helpers
    # -----------------------------
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

    async def _bounded_callback(self, callback: Callable, *args, **kwargs) -> Any:
        result = callback(*args, **kwargs)
        if inspect.isawaitable(result):
            return await asyncio.wait_for(result, timeout=CALLBACK_TIMEOUT_S)
        return result

    async def _set_status(self, status: str) -> None:
        if not getattr(self, "status_callback", None):
            return
        try:
            await self._bounded_callback(self.status_callback, status)
        except Exception:
            self.logger.exception("status_callback failed")

    def _apply_parameters_from_runner(self) -> None:
        p = getattr(self, "parameters", None)
        self.logger.info(f"_apply_parameters_from_runner self.parameters={p!r} type={type(p)}")

        if not isinstance(p, dict):
            return

        self.source_id = str(
            p.get("source_id")
            or p.get("node_uid")
            or self.node_uid
            or self.source_id
            or "sensor_node"
        ).strip()

        self.wifi_interface = str(p.get("wifi_interface", self.wifi_interface) or self.wifi_interface)
        self.mon_suffix = str(p.get("mon_suffix", self.mon_suffix) or self.mon_suffix)

        self.airo_prefix = str(p.get("airo_prefix", self.airo_prefix) or self.airo_prefix)
        self.airo_csv_glob = self.airo_prefix + "-*.csv"

        self.gpsd_host = str(p.get("gpsd_host", self.gpsd_host) or self.gpsd_host)
        self.gpsd_port = int(p.get("gpsd_port", self.gpsd_port))
        self.gps_refresh_interval = float(p.get("gps_refresh_interval", self.gps_refresh_interval))
        self.wifi_refresh_interval = float(p.get("wifi_refresh_interval", self.wifi_refresh_interval))

        self.log_dir = str(p.get("log_dir", self.log_dir) or self.log_dir)
        self.batch_unique_devices = max(1, int(p.get("batch_unique_devices", self.batch_unique_devices)))
        self.min_log_interval_s = float(p.get("min_log_interval_s", self.min_log_interval_s))
        self.alert_every_unique = max(1, int(p.get("alert_every_unique", self.alert_every_unique)))
        self.create_artifacts = _to_bool(p.get("create_artifacts", self.create_artifacts), True)
        self.artifact_name_prefix = str(
            p.get("artifact_name_prefix", self.artifact_name_prefix)
            or self.artifact_name_prefix
        )

        os.makedirs(self.log_dir, exist_ok=True)
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

    async def _emit_alert(
        self,
        message: str,
        uid: str = "",
        alert_kind: str = "wifi_discovery_edge_logger",
        alert_summary: str = "",
        remarks_extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        ts = time.time()
        payload = {
            "kind": "alert",
            "event_type": "alert",
            "node_uid": self.node_uid,
            "source_id": self.source_id,
            "operation_id": self.opid,
            "opid": self.opid,
            "alert_kind": alert_kind,
            "alert_summary": alert_summary or message,
            "message": message,
            "timestamp": ts,
        }
        if remarks_extra:
            payload.update(remarks_extra)

        if self.alert_callback:
            try:
                await self._bounded_callback(self.alert_callback, self.node_uid, self.opid, message, self.logger)
            except Exception as e:
                self.logger.warning(f"alert_callback failed: {e}")

        if not self.tak_cot_callback:
            return

        try:
            tak_msg = {
                "msg_type": "event",
                "uid": uid or f"wifi-logger-alert-{int(ts * 1000)}",
                "remarks": json.dumps(payload),
                "tak_icon": "b-t-f-r",
                "opid": self.opid,
                "kind": "alert",
                "event_type": "alert",
                "alert_kind": alert_kind,
                "alert_summary": alert_summary or message,
                "node_uid": self.node_uid,
                "source_id": self.source_id,
                "lat": True,
                "lon": True,
                "alt": True,
                "time": True,
                "plot_pin": False,
                "data": payload,
            }
            await self._bounded_callback(self.tak_cot_callback, tak_msg)
        except Exception as e:
            self.logger.warning(f"tak_cot_callback alert emit failed: {e}")

    @staticmethod
    def _normalize_bssid(bssid: str) -> str:
        return (bssid or "").replace(":", "").replace("-", "").strip().lower()

    def _iface(self, cmd: List[str]) -> None:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

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

        airodump_path = shutil.which("airodump-ng")
        if not airodump_path:
            self.logger.error("airodump-ng not found in PATH")
            return None, None

        self._kill_existing_airodump()

        self._iface(["sudo", "ip", "link", "set", mon, "down"])
        self._iface(["sudo", "iw", "dev", mon, "del"])

        use: Optional[str] = None
        add = subprocess.run(
            ["sudo", "iw", "dev", self.wifi_interface, "interface", "add", mon, "type", "monitor"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
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

        cmd = [
            "sudo", "-n",
            airodump_path,
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
                if proc.stderr:
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

    def _read_airodump_rows_once(self) -> List[Dict[str, Any]]:
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

        out: List[Dict[str, Any]] = []
        for r in rows[idx + 1:]:
            if not r or all(c.strip() == "" for c in r):
                break

            try:
                bssid = r[0].strip()
                channel_text = r[3].strip() if len(r) > 3 else ""
                privacy = r[5].strip() if len(r) > 5 else ""
                power_text = r[8].strip() if len(r) > 8 else ""
                ssid = r[13].strip(" ,\t\r\n") if len(r) > 13 else ""

                if (not ssid) or (ssid.lower() in ("<hidden>", "broadcast", "unknown")):
                    ssid = ""

                channel = None
                if channel_text:
                    try:
                        channel = int(float(channel_text))
                    except Exception:
                        channel = None

                rssi = None
                if power_text:
                    try:
                        rssi = float(power_text)
                    except Exception:
                        rssi = None

                band = ""
                freq_mhz = None
                if channel is not None:
                    if 1 <= channel <= 14:
                        band = "2.4GHz"
                        freq_mhz = 2484.0 if channel == 14 else 2412.0 + 5.0 * (channel - 1)
                    elif 30 <= channel <= 177:
                        band = "5GHz"
                        freq_mhz = 5000.0 + 5.0 * channel

                out.append({
                    "ssid": ssid,
                    "bssid": bssid,
                    "bssid_norm": self._normalize_bssid(bssid),
                    "channel": channel,
                    "band": band,
                    "frequency_mhz": freq_mhz,
                    "rssi_dbm": rssi,
                    "encryption": privacy,
                })
            except Exception:
                continue

        return out

    async def _gps_loop(self) -> None:
        self.logger.info("Starting GPS loop (GPSD)")
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

                            if lat is not None and lon is not None:
                                self._current_position.update({
                                    "lat": float(lat),
                                    "lon": float(lon),
                                    "alt": float(alt),
                                })

                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

            except Exception as e:
                self.logger.warning(f"GPS error: {e}")
                await asyncio.sleep(2.0)

    def _write_batch_csv(self, rows: List[Dict[str, Any]], batch_index: int) -> str:
        os.makedirs(self.log_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        path = os.path.join(self.log_dir, f"wifi_logger_batch_{batch_index:04d}_{ts}.csv")

        fieldnames = [
            "kind",
            "event_type",
            "source_id",
            "first_seen_iso",
            "first_seen_epoch",
            "last_seen_iso",
            "last_seen_epoch",
            "node_uid",
            "last_lat",
            "last_lon",
            "last_alt_m",
            "bssid",
            "ssid",
            "strongest_rssi_dbm",
            "latest_rssi_dbm",
            "observation_count",
            "channel",
            "band",
            "frequency_mhz",
            "encryption",
        ]

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: row.get(k) for k in fieldnames})

        return path

    def _create_batch_artifact(self, csv_path: str, rows: List[Dict[str, Any]], batch_index: int) -> str:
        operation_id = str(uuid.uuid4())
        _, capture_folder = self.artifact_manager.create_operation_dir(operation_id)

        dst_csv = os.path.join(capture_folder, os.path.basename(csv_path))
        with open(csv_path, "r", encoding="utf-8") as src, open(dst_csv, "w", encoding="utf-8") as dst:
            dst.write(src.read())

        metadata = {
            "kind": "artifact",
            "event_type": "artifact",
            "role": "wifi_urban_logger_batch_v2",
            "run_id": self._run_id,
            "batch_index": batch_index,
            "node_uid": self.node_uid,
            "source_id": self.source_id,
            "operation_id": operation_id,
            "row_count": len(rows),
            "unique_bssid_count_batch": len(rows),
            "unique_bssid_count_total": len(self._seen_bssids_total),
            "created_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "csv_filename": os.path.basename(csv_path),
        }

        meta_path = os.path.join(capture_folder, "batch_metadata.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        if not self.artifact_manager:
            return operation_id

        artifact = self.artifact_manager.create_zip_artifact_from_folder(
            source_id=self.source_id,
            operation_id=operation_id,
            folder=capture_folder,
            name=f"{self.artifact_name_prefix} #{batch_index}",
            metadata=metadata,
            arc_prefix=f"wifi_logger_{operation_id}",
        )
        return str(getattr(artifact, "id", artifact) if artifact else "")

    async def _flush_batch(self) -> None:
        if not self._batch_records:
            return

        rows = list(self._batch_records.values())
        self._batch_records.clear()
        self._last_update_time_by_bssid.clear()
        self._batch_index += 1

        csv_path = self._write_batch_csv(rows, self._batch_index)
        artifact_id = ""

        if self.create_artifacts:
            try:
                artifact_id = self._create_batch_artifact(csv_path, rows, self._batch_index)
            except Exception as e:
                self.logger.warning(f"Artifact creation failed for batch {self._batch_index}: {e}")

        self.logger.info(
            f"Wrote Wi-Fi logger batch {self._batch_index}: "
            f"rows={len(rows)}, csv={csv_path}, artifact_id={artifact_id or '<none>'}"
        )

        await self._emit_alert(
            message=(
                f"Wi-Fi logger batch {self._batch_index} written: "
                f"{len(rows)} unique devices"
            ),
            uid=f"wifi-logger-batch-{self._batch_index}",
            alert_kind="wifi_discovery_edge_logger_batch",
            alert_summary=f"Wi-Fi logger batch {self._batch_index} saved",
            remarks_extra={
                "batch_index": self._batch_index,
                "row_count": len(rows),
                "artifact_id": artifact_id,
                "csv_path": csv_path,
                "run_id": self._run_id,
            },
        )

    async def run(self):
        self.logger.info("Starting Wi-Fi urban logger operation")
        self._apply_parameters_from_runner()
        await self._set_status("Starting Wi-Fi urban logger")

        gps_task: Optional[asyncio.Task] = asyncio.create_task(self._gps_loop())

        self._airodump_proc, self._airodump_iface_in_use = await self._start_airodump()
        if not self._airodump_proc:
            self._gps_stop.set()
            if gps_task:
                gps_task.cancel()
                try:
                    await gps_task
                except asyncio.CancelledError:
                    pass
                except Exception:
                    pass
            await self._set_status("Idle")
            return

        try:
            while not self._should_stop():
                lat = self._current_position.get("lat")
                lon = self._current_position.get("lon")
                alt = self._current_position.get("alt")

                if lat is None or lon is None:
                    await asyncio.sleep(self.wifi_refresh_interval)
                    continue

                rows = await self._to_thread_compat(self._read_airodump_rows_once)
                if not rows:
                    await asyncio.sleep(self.wifi_refresh_interval)
                    continue

                now_epoch = time.time()
                now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch))

                for row in rows:
                    bssid = row.get("bssid", "")
                    bssid_norm = row.get("bssid_norm", "")
                    if not bssid_norm:
                        continue

                    ssid = row.get("ssid", "")
                    rssi_dbm = row.get("rssi_dbm")
                    channel = row.get("channel")
                    band = row.get("band", "")
                    frequency_mhz = row.get("frequency_mhz")
                    encryption = row.get("encryption", "")

                    prev_total = len(self._seen_bssids_total)
                    self._seen_bssids_total.add(bssid_norm)
                    new_total = len(self._seen_bssids_total)

                    if new_total > prev_total and (new_total - self._last_alert_unique_count) >= self.alert_every_unique:
                        self._last_alert_unique_count = new_total
                        await self._emit_alert(
                            message=f"Wi-Fi urban logger has observed {new_total} unique devices",
                            uid=f"wifi-logger-unique-{new_total}",
                            alert_kind="wifi_discovery_edge_logger_summary",
                            alert_summary=f"{new_total} unique Wi-Fi devices observed",
                            remarks_extra={
                                "unique_bssid_count_total": new_total,
                                "run_id": self._run_id,
                            },
                        )

                    rec = self._batch_records.get(bssid_norm)
                    if rec is None:
                        self._batch_records[bssid_norm] = {
                            "kind": "wifi_observation",
                            "event_type": "wifi_observation",
                            "source_id": self.source_id,
                            "first_seen_iso": now_iso,
                            "first_seen_epoch": now_epoch,
                            "last_seen_iso": now_iso,
                            "last_seen_epoch": now_epoch,
                            "node_uid": self.node_uid,
                            "last_lat": float(lat),
                            "last_lon": float(lon),
                            "last_alt_m": float(alt or 0.0),
                            "bssid": bssid,
                            "ssid": ssid,
                            "strongest_rssi_dbm": rssi_dbm,
                            "latest_rssi_dbm": rssi_dbm,
                            "observation_count": 1,
                            "channel": channel,
                            "band": band,
                            "frequency_mhz": frequency_mhz,
                            "encryption": encryption,
                        }
                        self._last_update_time_by_bssid[bssid_norm] = now_epoch
                        continue

                    rec["observation_count"] += 1

                    if rssi_dbm is not None:
                        strongest = rec.get("strongest_rssi_dbm")
                        if strongest is None or rssi_dbm > strongest:
                            rec["strongest_rssi_dbm"] = rssi_dbm

                    last_update = self._last_update_time_by_bssid.get(bssid_norm, 0.0)
                    if (now_epoch - last_update) < self.min_log_interval_s:
                        continue

                    self._last_update_time_by_bssid[bssid_norm] = now_epoch

                    rec["last_seen_iso"] = now_iso
                    rec["last_seen_epoch"] = now_epoch
                    rec["last_lat"] = float(lat)
                    rec["last_lon"] = float(lon)
                    rec["last_alt_m"] = float(alt or 0.0)
                    rec["ssid"] = ssid
                    rec["latest_rssi_dbm"] = rssi_dbm
                    rec["channel"] = channel
                    rec["band"] = band
                    rec["frequency_mhz"] = frequency_mhz
                    rec["encryption"] = encryption

                if len(self._batch_records) >= self.batch_unique_devices:
                    await self._flush_batch()

                await self._set_status(
                    f"Wi-Fi urban logger running: {len(self._seen_bssids_total)} unique devices total, "
                    f"{len(self._batch_records)} unique devices in current batch"
                )

                await asyncio.sleep(self.wifi_refresh_interval)

        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.exception(f"Wi-Fi urban logger operation error: {e}")
        finally:
            try:
                await self._flush_batch()
            except Exception as e:
                self.logger.warning(f"Final batch flush failed: {e}")

            self._gps_stop.set()
            if gps_task:
                gps_task.cancel()
                try:
                    await asyncio.wait_for(gps_task, timeout=3.0)
                except asyncio.CancelledError:
                    pass
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
                        await self._airodump_proc.wait()
            except Exception:
                pass

            try:
                await self._to_thread_compat(self._restore_managed)
            except Exception:
                pass

            await self._set_status("Idle")

            self.logger.info(
                f"Wi-Fi urban logger stopped cleanly. "
                f"Unique devices seen: {len(self._seen_bssids_total)}"
            )

    async def _to_thread_compat(self, func, *args, **kwargs):
        if hasattr(asyncio, "to_thread"):
            return await asyncio.to_thread(func, *args, **kwargs)

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})