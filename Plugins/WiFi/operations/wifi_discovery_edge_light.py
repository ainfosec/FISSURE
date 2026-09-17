#!/usr/bin/env python3
"""FISSURE - Passive Wi-Fi Discovery (Light)

Low-volume discovery. Emits stable BSSID-based Detections for operator review/promotion. It does not solve or create Targets by default.
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
    def __init__(self, node_uid: str = "", logger: logging.Logger = logging.getLogger(__name__), alert_callback=None, tak_cot_callback=None, detection_callback=None, status_callback=None, target_callback=None, position_callback=None, artifact_manager=None, parameters: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(node_uid=node_uid, logger=logger, alert_callback=alert_callback, tak_cot_callback=tak_cot_callback, detection_callback=detection_callback, status_callback=status_callback, target_callback=target_callback, position_callback=position_callback, artifact_manager=artifact_manager)
        self.parameters = parameters or {}
        self.source_id = str(node_uid or "").strip() or "sensor_node"
        self.wifi_interface = "wlx00c0caa744fc"
        self.mon_suffix = MON_SUFFIX_DEFAULT
        self.airo_prefix = "/tmp/airodump"
        self.airo_csv_glob = self.airo_prefix + "-*.csv"
        self.scan_interval_s = 0.5
        self.reemit_interval_s = 0.0
        self.max_emit_rate_hz = 5.0
        self.max_emit_burst = 3
        self.pending_ttl_s = 3.0
        self.max_pending_bssids = 50
        self.status_interval_s = 5.0
        self.alert_on_new_detection = False
        self._airodump_proc = None
        self._airodump_iface_in_use = None
        self._last_emit_by_bssid: Dict[str, float] = {}
        self._last_source_seen_by_bssid: Dict[str, str] = {}
        self._seen_bssids: Set[str] = set()
        self._pending_by_bssid: Dict[str, Dict[str, Any]] = {}
        self._emit_tokens = 0.0
        self._emit_token_time = time.monotonic()
        self._last_status_epoch = 0.0

    def _apply_parameters_from_runner(self) -> None:
        p = self.parameters if isinstance(self.parameters, dict) else {}
        self.source_id = str(p.get("source_id") or p.get("node_uid") or self.node_uid or "sensor_node").strip()
        self.wifi_interface = str(p.get("wifi_interface", self.wifi_interface) or self.wifi_interface)
        self.mon_suffix = str(p.get("mon_suffix", self.mon_suffix) or self.mon_suffix)
        self.airo_prefix = str(p.get("airo_prefix", self.airo_prefix) or self.airo_prefix)
        self.airo_csv_glob = self.airo_prefix + "-*.csv"
        self.scan_interval_s = max(0.2, float(p.get("scan_interval_s", p.get("wifi_refresh_interval", self.scan_interval_s))))
        self.reemit_interval_s = max(0.0, float(p.get("reemit_interval_s", self.reemit_interval_s)))
        self.max_emit_rate_hz = max(0.1, float(p.get("max_emit_rate_hz", self.max_emit_rate_hz)))
        self.alert_on_new_detection = _to_bool(p.get("alert_on_new_detection", p.get("alert_on_new_target", self.alert_on_new_detection)), self.alert_on_new_detection)
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
                source_last_seen = r[2].strip()
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
                    "source_last_seen": source_last_seen,
                })
            except Exception:
                continue
        return out

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
        await self._set_status("Idle")

    async def _to_thread_compat(self, func, *args, **kwargs):
        if hasattr(asyncio, "to_thread"):
            return await asyncio.to_thread(func, *args, **kwargs)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

    def _snapshot_position(self) -> Dict[str, Any]:
        try:
            position = self.position_callback()
        except Exception as exc:
            self.logger.warning(f"Position callback failed: {exc}")
            return {"location_valid": False}

        if not isinstance(position, dict) or not position.get("valid", False):
            return {"location_valid": False}

        lat = position.get("latitude")
        lon = position.get("longitude")
        alt = position.get("altitude")
        if lat is None or lon is None:
            return {"location_valid": False}

        return {
            "location_valid": True,
            "latitude": float(lat),
            "longitude": float(lon),
            "altitude": float(alt or 0.0),
            "location_source": str(position.get("source") or ""),
        }

    def _queue_pending_detection(
        self,
        row: Dict[str, Any],
        *,
        first_seen: bool,
        now_epoch: float,
    ) -> None:
        bssid_norm = row.get("bssid_norm", "")
        if not bssid_norm:
            return

        now_monotonic = time.monotonic()
        existing = self._pending_by_bssid.get(bssid_norm)

        pending = dict(row)
        pending.update(self._snapshot_position())
        pending["_observation_epoch"] = now_epoch
        pending["_first_seen"] = bool(first_seen)
        pending["_pending_since_monotonic"] = (
            existing.get("_pending_since_monotonic", now_monotonic)
            if existing
            else now_monotonic
        )

        self._pending_by_bssid[bssid_norm] = pending

        if len(self._pending_by_bssid) <= self.max_pending_bssids:
            return

        oldest_bssid = min(
            self._pending_by_bssid,
            key=lambda key: float(
                self._pending_by_bssid[key].get(
                    "_pending_since_monotonic",
                    now_monotonic,
                )
            ),
        )
        self._pending_by_bssid.pop(oldest_bssid, None)

    def _prune_pending(self) -> None:
        now = time.monotonic()
        expired = [
            bssid
            for bssid, pending in self._pending_by_bssid.items()
            if (
                now
                - float(
                    pending.get(
                        "_pending_since_monotonic",
                        now,
                    )
                )
            )
            > self.pending_ttl_s
        ]
        for bssid in expired:
            self._pending_by_bssid.pop(bssid, None)

    def _take_emit_budget(self) -> int:
        now = time.monotonic()
        elapsed = max(0.0, now - self._emit_token_time)
        self._emit_token_time = now

        burst_capacity = min(
            float(self.max_emit_burst),
            max(1.0, float(self.max_emit_rate_hz)),
        )
        self._emit_tokens = min(
            burst_capacity,
            self._emit_tokens + elapsed * self.max_emit_rate_hz,
        )
        return int(self._emit_tokens)
    
    async def _emit_detection(self, row: Dict[str, Any], *, first_seen: bool) -> None:
        if not self.detection_callback:
            return

        location_valid = bool(row.get("location_valid", False))
        bssid_norm = row["bssid_norm"]
        source_key = str(self.node_uid or self.source_id or "sensor_node").strip()

        frequency_mhz = row.get("frequency_mhz")
        try:
            frequency_hz = int(round(float(frequency_mhz) * 1e6)) if frequency_mhz is not None else None
        except (TypeError, ValueError):
            frequency_hz = None

        detection = {
            "kind": "detection",
            "event_type": "detection",
            "detection_kind": "wifi_discovery",
            "detector": "wifi_discovery_edge_light",
            "event_uid": f"wifi-discovery-{source_key}-{bssid_norm}",
            "node_uid": str(self.node_uid),
            "source_id": self.source_id,
            "opid": self.opid,
            "operation_id": self.opid,
            "timestamp": float(row.get("_observation_epoch") or time.time()),
            "ssid": row.get("ssid", ""),
            "bssid": row.get("bssid", ""),
            "channel": row.get("channel"),
            "band": row.get("band", ""),
            "frequency_hz": frequency_hz,
            "power_dbm": row.get("rssi_dbm"),
            "encryption": row.get("encryption", ""),
            "first_seen": bool(first_seen),
            "location_semantics": "receiver_observation",
            "location_source": row.get("location_source", ""),
            "location_valid": location_valid,
        }

        if location_valid:
            detection["latitude"] = float(row["latitude"])
            detection["longitude"] = float(row["longitude"])
            detection["altitude"] = float(row.get("altitude") or 0.0)

        detection = {k: v for k, v in detection.items() if v is not None}
        await self._call(self.detection_callback, detection)

        if first_seen and self.alert_on_new_detection and self.alert_callback:
            try:
                await self._call(
                    self.alert_callback,
                    {
                        "uid": f"wifi-discovery-alert-{source_key}-{bssid_norm}",
                        "alert_kind": "wifi_discovery",
                        "alert_summary": f"Wi-Fi discovered: {row.get('ssid') or '<hidden>'} {row.get('bssid')}",
                        "message": f"Wi-Fi discovered: {row.get('ssid') or '<hidden>'} {row.get('bssid')}",
                        "node_uid": self.node_uid,
                        "source_id": self.source_id,
                        "operation_id": self.opid,
                        "plot_pin": False,
                    },
                )
            except Exception:
                self.logger.exception("alert_callback failed")

    async def run(self) -> None:
        try:
            self._apply_parameters_from_runner()
            if not self.detection_callback:
                raise RuntimeError("wifi_discovery_edge_light requires detection_callback")

            burst_capacity = min(
                float(self.max_emit_burst),
                max(1.0, float(self.max_emit_rate_hz)),
            )
            self._emit_tokens = burst_capacity
            self._emit_token_time = time.monotonic()
            self._last_status_epoch = 0.0

            await self._set_status("Discovering Wi-Fi")
            self._airodump_proc, self._airodump_iface_in_use = await self._start_airodump()
            if not self._airodump_proc:
                return

            while not self._should_stop():
                rows = await self._to_thread_compat(self._read_airodump_rows_once)
                now = time.time()
                self._prune_pending()

                for row in rows:
                    bssid_norm = row.get("bssid_norm", "")
                    if not bssid_norm:
                        continue

                    source_last_seen = str(row.get("source_last_seen") or "").strip()
                    if source_last_seen:
                        previous_source_seen = self._last_source_seen_by_bssid.get(bssid_norm)
                        if previous_source_seen == source_last_seen:
                            continue
                        self._last_source_seen_by_bssid[bssid_norm] = source_last_seen

                    first_seen = bssid_norm not in self._seen_bssids
                    if not first_seen:
                        if self.reemit_interval_s <= 0:
                            continue

                        last_emit = self._last_emit_by_bssid.get(bssid_norm, 0.0)
                        if now - last_emit < self.reemit_interval_s:
                            continue

                    self._queue_pending_detection(
                        row,
                        first_seen=first_seen,
                        now_epoch=now,
                    )

                pending = sorted(
                    self._pending_by_bssid.values(),
                    key=lambda row: (
                        0 if row.get("_first_seen", False) else 1,
                        -float(row.get("rssi_dbm"))
                        if row.get("rssi_dbm") is not None
                        else float("inf"),
                        -float(row.get("_observation_epoch") or 0.0),
                    ),
                )

                budget = self._take_emit_budget()
                for row in pending[:budget]:
                    if self._should_stop():
                        break

                    bssid_norm = row["bssid_norm"]
                    first_seen = bool(row.get("_first_seen", False))

                    await self._emit_detection(row, first_seen=first_seen)

                    self._seen_bssids.add(bssid_norm)
                    self._last_emit_by_bssid[bssid_norm] = time.time()
                    self._pending_by_bssid.pop(bssid_norm, None)
                    self._emit_tokens = max(0.0, self._emit_tokens - 1.0)

                    # Keep control/status traffic responsive between detections.
                    await asyncio.sleep(0)

                if (now - self._last_status_epoch) >= self.status_interval_s:
                    self._last_status_epoch = now
                    await self._set_status(
                        f"Discovering Wi-Fi: {len(self._seen_bssids)} BSSIDs"
                        f" ({len(self._pending_by_bssid)} pending)"
                    )

                await asyncio.sleep(self.scan_interval_s)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.logger.exception(f"Wi-Fi light discovery error: {exc}")
        finally:
            await self._stop_runtime()


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})