#!/usr/bin/env python3
"""
FISSURE – Wi-Fi Discovery by OUI (Target Creation Only)
-------------------------------------------------------
Purpose
-------
Observe visible Wi-Fi APs, filter by one or more OUI prefixes, and create/update
targets for matching APs.

Behavior
--------
- Filters APs by user-provided OUI prefix list
- Creates targets for matching APs
- Sends one table-only alert per newly created Wi-Fi target
- Does NOT create artifacts
- Does NOT perform edge geolocation refinement
- Uses current node position for initial target location

Expected "parameters" keys:
- oui_filter: str                      REQUIRED for useful behavior
    Examples:
      "00:11:22"
      "001122"
      "00:11:22, AABBCC, 34-de-ad"
- wifi_interface: str
- mon_suffix: str
- airo_prefix: str
- gpsd_host: str
- gpsd_port: int
- gps_refresh_interval: float
- wifi_refresh_interval: float
- alert_on_new_target: bool
- log_dir: str
"""

import asyncio
import csv
import glob
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

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

        self.alert_on_new_target: bool = True
        self.log_dir: str = os.path.join(FISSURE_ROOT, "logs", "plugins", "WiFi")
        os.makedirs(self.log_dir, exist_ok=True)

        self.oui_filter_raw: str = ""
        self.oui_prefixes: Set[str] = set()

        self._gps_stop = asyncio.Event()
        self._current_position = {"lat": None, "lon": None, "alt": 0.0}

        self._airodump_proc: Optional[asyncio.subprocess.Process] = None
        self._airodump_iface_in_use: Optional[str] = None

        self._ap_db: Dict[str, Dict[str, Any]] = {}

    # -----------------------------
    # Compatibility / callbacks
    # -----------------------------
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

    async def _maybe_await(self, result):
        if asyncio.iscoroutine(result) or isinstance(result, asyncio.Future):
            return await result
        return result

    async def _call_with_timeout(self, callback: Callable, *args, **kwargs):
        result = callback(*args, **kwargs)
        if asyncio.iscoroutine(result) or isinstance(result, asyncio.Future):
            return await asyncio.wait_for(result, timeout=CALLBACK_TIMEOUT_S)
        return result

    async def _set_status(self, status: str) -> None:
        if not self.status_callback:
            return
        try:
            await self._call_with_timeout(self.status_callback, status)
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
        )
        self.wifi_interface = str(p.get("wifi_interface", self.wifi_interface) or self.wifi_interface)
        self.mon_suffix = str(p.get("mon_suffix", self.mon_suffix) or self.mon_suffix)

        self.airo_prefix = str(p.get("airo_prefix", self.airo_prefix) or self.airo_prefix)
        self.airo_csv_glob = self.airo_prefix + "-*.csv"

        self.gpsd_host = str(p.get("gpsd_host", self.gpsd_host) or self.gpsd_host)
        self.gpsd_port = int(p.get("gpsd_port", self.gpsd_port))
        self.gps_refresh_interval = float(p.get("gps_refresh_interval", self.gps_refresh_interval))
        self.wifi_refresh_interval = float(p.get("wifi_refresh_interval", self.wifi_refresh_interval))

        self.alert_on_new_target = _to_bool(
            p.get("alert_on_new_target", self.alert_on_new_target),
            default=self.alert_on_new_target,
        )

        self.log_dir = str(p.get("log_dir", self.log_dir) or self.log_dir)
        os.makedirs(self.log_dir, exist_ok=True)

        self.oui_filter_raw = str(p.get("oui_filter", "") or "")
        self.oui_prefixes = self._parse_oui_filter(self.oui_filter_raw)

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

        patch.setdefault("kind", "target")
        patch.setdefault("event_type", "target")
        patch.setdefault("node_uid", self.node_uid)
        patch.setdefault("source_id", self.source_id)

        hist = history_entry or {}
        hist.setdefault("kind", "target_history")
        hist.setdefault("event_type", "target_update")
        hist.setdefault("node_uid", self.node_uid)
        hist.setdefault("source_id", self.source_id)

        try:
            await self._call_with_timeout(
                cb,
                target_id=target_id,
                patch=patch,
                history_entry=hist,
                artifact_id=artifact_id or "",
            )
            return
        except TypeError as e:
            self.logger.warning(f"target_callback keyword call failed: {e}")
        except Exception as e:
            self.logger.warning(f"target_callback keyword emit failed: {e}")
            return

        try:
            await self._call_with_timeout(
                cb,
                {
                    "kind": "target",
                    "event_type": "target_update",
                    "node_uid": self.node_uid,
                    "source_id": self.source_id,
                    "target_id": target_id,
                    "patch": patch,
                    "history_entry": hist,
                    "artifact_id": artifact_id or "",
                },
            )
        except Exception as e:
            self.logger.error(f"target_callback patch emit failed: {e}")

    async def _emit_alert(
        self,
        message: str,
        uid: str = "",
        alert_kind: str = "wifi_discovery_edge_oui",
        alert_summary: str = "",
        lat: Optional[float] = None,
        lon: Optional[float] = None,
        alt: Optional[float] = None,
        remarks_extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not self.alert_callback:
            return

        alert_payload = {
            "uid": uid or f"wifi-oui-alert-{int(time.time() * 1000)}",
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
            await self._call_with_timeout(self.alert_callback, alert_payload)
        except Exception as e:
            self.logger.warning(f"alert_callback failed: {e}")

    @staticmethod
    def _normalize_bssid(bssid: str) -> str:
        return (bssid or "").replace(":", "").replace("-", "").strip().lower()

    @staticmethod
    def _normalize_oui(value: str) -> str:
        return "".join(c for c in (value or "") if c.isalnum()).lower()[:6]

    def _parse_oui_filter(self, value: str) -> Set[str]:
        prefixes: Set[str] = set()

        if not value:
            return prefixes

        raw_parts = []
        for part in str(value).replace(";", ",").split(","):
            part = part.strip()
            if part:
                raw_parts.append(part)

        for part in raw_parts:
            norm = self._normalize_oui(part)
            if len(norm) == 6:
                prefixes.add(norm)
            else:
                self.logger.warning(f"Ignoring invalid OUI filter entry: {part!r}")

        return prefixes

    def _bssid_matches_oui(self, bssid: str) -> bool:
        if not self.oui_prefixes:
            return False

        norm_bssid = self._normalize_bssid(bssid)
        if len(norm_bssid) < 6:
            return False

        return norm_bssid[:6] in self.oui_prefixes

    # -----------------------------
    # Interface / airodump helpers
    # -----------------------------
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
        airodump = shutil.which("airodump-ng") or "airodump-ng"
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
            airodump,
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
                    ssid = f"HIDDEN_{bssid[-5:].replace(':', '')}"

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

    # -----------------------------
    # GPS
    # -----------------------------
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

    # -----------------------------
    # run()
    # -----------------------------
    async def run(self):
        gps_task: Optional[asyncio.Task] = None

        try:
            if not self.target_callback:
                raise RuntimeError("wifi_discovery_edge_oui requires target_callback to be wired")

            self.logger.info("Starting Wi-Fi OUI discovery operation")
            self._apply_parameters_from_runner()
            await self._set_status("Starting Wi-Fi OUI discovery")

            if not self.oui_prefixes:
                raise RuntimeError("wifi_discovery_edge_oui requires at least one valid OUI filter")

            self.logger.info(f"OUI filter prefixes: {sorted(self.oui_prefixes)}")

            gps_task = asyncio.create_task(self._gps_loop())

            self._airodump_proc, self._airodump_iface_in_use = await self._start_airodump()
            if not self._airodump_proc:
                self._gps_stop.set()
                return

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

                now = time.time()

                for row in rows:
                    if self._should_stop():
                        break

                    ssid = row.get("ssid", "")
                    bssid = row.get("bssid", "")
                    bssid_norm = row.get("bssid_norm", "")
                    rssi_dbm = row.get("rssi_dbm")
                    channel = row.get("channel")
                    band = row.get("band", "")
                    frequency_mhz = row.get("frequency_mhz")
                    encryption = row.get("encryption", "")

                    if not self._bssid_matches_oui(bssid):
                        continue

                    ap = self._ap_db.setdefault(
                        bssid_norm,
                        {
                            "bssid": bssid,
                            "ssid": ssid,
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

                    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

                    classification = {
                        "display_label": "Wi-Fi AP",
                        "candidates": [
                            {"source": "database", "label": "Wi-Fi AP"},
                            {"source": "model", "label": "802.11 Access Point", "confidence": 0.95},
                        ],
                    }

                    location = {
                        "lat": float(lat),
                        "lon": float(lon),
                        "hae_m": float(alt or 0.0),
                        "ce_m": 0,
                        "timestamp": now_iso,
                        "source": "wifi_oui_discovery",
                    }

                    wifi_block = {
                        "ssid": ssid,
                        "bssid": bssid,
                        "channel": channel,
                        "band": band,
                        "frequency_mhz": frequency_mhz,
                        "rssi_dbm": float(rssi_dbm) if rssi_dbm is not None else None,
                        "encryption": encryption,
                        "last_observation_time": now_iso,
                        "oui_prefix": bssid_norm[:6],
                    }

                    patch = {
                        "kind": "target",
                        "event_type": "target",
                        "target_id": ap["target_id"],
                        "node_uid": self.node_uid,
                        "source_id": self.source_id,
                        "source_soi_id": "",
                        "frequency_mhz": float(frequency_mhz) if frequency_mhz is not None else None,
                        "classification": classification,
                        "location": location,
                        "state": "detected",
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
                            "event": "wifi_oui_target_update",
                            "bssid": bssid,
                            "oui_prefix": bssid_norm[:6],
                        },
                        artifact_id="",
                    )

                    if not ap["target_created"]:
                        ap["target_created"] = True
                        self.logger.info(
                            f"Created Wi-Fi OUI target {ap['target_id']} for BSSID {bssid} SSID {ssid!r}"
                        )

                    if self.alert_on_new_target and not ap["alert_sent"]:
                        ap["alert_sent"] = True

                        alert_message = (
                            f"New OUI-matched Wi-Fi target discovered: SSID={ssid or '<hidden>'}, "
                            f"BSSID={bssid}, OUI={bssid_norm[:6].upper()}, "
                            f"RSSI={rssi_dbm if rssi_dbm is not None else 'n/a'} dBm"
                        )

                        await self._emit_alert(
                            message=alert_message,
                            uid=f"wifi-oui-alert-{ap['target_id']}",
                            alert_kind="wifi_discovery_edge_oui",
                            alert_summary=f"OUI Wi-Fi target discovered: {ssid or '<hidden>'}",
                            lat=None,
                            lon=None,
                            alt=None,
                            remarks_extra={
                                "target_id": ap["target_id"],
                                "ssid": ssid or "<hidden>",
                                "bssid": bssid,
                                "oui_prefix": bssid_norm[:6].upper(),
                                "rssi_dbm": rssi_dbm,
                            },
                        )

                await self._set_status(
                    f"Scanning Wi-Fi APs for {len(self.oui_prefixes)} OUI prefix match(es)"
                )

                await asyncio.sleep(self.wifi_refresh_interval)

        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.exception(f"Wi-Fi OUI discovery operation error: {e}")
        finally:
            self._gps_stop.set()
            if gps_task is not None:
                try:
                    gps_task.cancel()
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
            self.logger.info("Wi-Fi OUI discovery operation stopped cleanly.")

    async def _to_thread_compat(self, func, *args, **kwargs):
        if hasattr(asyncio, "to_thread"):
            return await asyncio.to_thread(func, *args, **kwargs)

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})