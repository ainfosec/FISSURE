#!/usr/bin/env python3
"""
FISSURE – Wi-Fi Geolocate Specific Target
-----------------------------------------
Purpose
-------
Observe one existing Wi-Fi target and emit detection events tagged with that
target_id so HIPRFISR can multilaterate at the hub.

This operation does NOT create/update targets directly.
It emits detections for a selected target only.

Expected "parameters" keys (all optional unless noted):
- target_id: str                       REQUIRED
- wifi_interface: str
- mon_suffix: str
- airo_prefix: str
- wifi_refresh_interval: float
- aggregation_window_s: float
- measurement_spacing_m: float

Target assumptions
------------------
For Wi-Fi targets created by wifi_discovery_edge, target_id is expected to look like:
    wifiap-<BSSID_WITHOUT_COLONS_UPPER_OR_LOWER>

Example:
    wifiap-24F5A28FC8DF

We derive the expected BSSID from target_id and only emit detections for that AP.
"""

import asyncio
import csv
import glob
import inspect
import logging
import os
import shutil
import subprocess
import sys
import time
import math
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


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




class OperationMain(Operation):
    def __init__(
        self,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        detection_callback: Union[Callable, None] = None,
        status_callback: Union[Callable, None] = None,
        target_callback: Union[Callable, None] = None,
        position_callback=None,
        artifact_manager=None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            detection_callback=detection_callback,
            status_callback=status_callback,
            target_callback=target_callback,
            position_callback=position_callback,
            artifact_manager=artifact_manager,
        )

        self.parameters: Dict[str, Any] = parameters or {}

        self.target_id: str = ""
        self.target_bssid: str = ""
        self.target_channel: Optional[int] = None
        self.target_frequency_mhz: Optional[float] = None
        self.source_id: str = str(node_uid or "").strip() or "sensor_node"

        self.wifi_interface: str = "wlx00c0caa744fc"
        self.mon_suffix: str = MON_SUFFIX_DEFAULT

        self.airo_prefix: str = "/tmp/airodump"
        self.airo_csv_glob: str = self.airo_prefix + "-*.csv"

        self.wifi_refresh_interval: float = 0.2
        self.aggregation_window_s: float = 3.0
        self.cluster_radius_m: float = 8.0
        self.measurement_spacing_m: float = 20.0

        self._airodump_proc: Optional[asyncio.subprocess.Process] = None
        self._airodump_iface_in_use: Optional[str] = None

        self._target_bssid_norm: str = ""
        self._target_bssid_colon: str = ""
        self._last_source_seen: str = ""
        self._active_cluster: Optional[Dict[str, Any]] = None
        self._last_emitted_position: Optional[Tuple[float, float]] = None
        self._emitted_measurement_count: int = 0

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

    async def _maybe_await(self, result: Any) -> Any:
        if inspect.isawaitable(result):
            return await result
        return result

    async def _run_callback(self, name: str, callback: Optional[Callable], *args, timeout: float = 2.0, **kwargs) -> Any:
        if not callback:
            return None
        try:
            return await asyncio.wait_for(self._maybe_await(callback(*args, **kwargs)), timeout=timeout)
        except asyncio.TimeoutError:
            self.logger.warning("%s timed out", name)
        except Exception:
            self.logger.exception("%s failed", name)
        return None

    async def _set_status(self, text: str) -> None:
        await self._run_callback("status_callback", getattr(self, "status_callback", None), text)

    def _apply_parameters_from_runner(self) -> None:
        p = getattr(self, "parameters", None)
        self.logger.info(f"_apply_parameters_from_runner self.parameters={p!r} type={type(p)}")

        if not isinstance(p, dict):
            return

        self.target_id = str(p.get("target_id", self.target_id or "")).strip()
        self.target_bssid = str(p.get("bssid", self.target_bssid or "")).strip()
        channel_value = p.get("channel", self.target_channel)
        try:
            self.target_channel = int(float(channel_value)) if channel_value not in (None, "", "None") else None
        except Exception:
            self.target_channel = None

        frequency_value = p.get("frequency_mhz", self.target_frequency_mhz)
        try:
            self.target_frequency_mhz = float(frequency_value) if frequency_value not in (None, "", "None") else None
        except Exception:
            self.target_frequency_mhz = None

        self.source_id = str(p.get("source_id") or self.node_uid or "sensor_node").strip()
        self.wifi_interface = str(p.get("wifi_interface", self.wifi_interface) or self.wifi_interface)
        self.mon_suffix = str(p.get("mon_suffix", self.mon_suffix) or self.mon_suffix)

        self.airo_prefix = str(p.get("airo_prefix", self.airo_prefix) or self.airo_prefix)
        self.airo_csv_glob = self.airo_prefix + "-*.csv"

        self.wifi_refresh_interval = max(
            0.1,
            float(
                p.get(
                    "meas_every_s",
                    p.get(
                        "wifi_refresh_interval",
                        self.wifi_refresh_interval,
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

    # -----------------------
    # Target helpers
    # -----------------------
    def _derive_bssid_from_target_id(self, target_id: str) -> Tuple[str, str]:
        """
        Convert target_id like wifiap-24F5A28FC8DF into:
            normalized: 24f5a28fc8df
            colonized:  24:F5:A2:8F:C8:DF
        """
        if not target_id:
            return "", ""

        raw = target_id.strip()
        if raw.lower().startswith("wifiap-"):
            raw = raw[7:]

        raw = raw.replace(":", "").replace("-", "").strip()
        if len(raw) != 12:
            return "", ""

        norm = raw.lower()
        colon = ":".join(raw[i:i + 2] for i in range(0, 12, 2)).upper()
        return norm, colon

    @staticmethod
    def _normalize_bssid(bssid: str) -> str:
        return (bssid or "").replace(":", "").replace("-", "").strip().lower()

    # -----------------------
    # Airodump helpers
    # -----------------------
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
            self.logger.info(
                f"Monitor sub-interface unavailable; using {self.wifi_interface} "
                f"directly in monitor mode"
            )
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
            "sudo", "-n", airodump_path,
            "--berlin", "1",
            "--write-interval", "1",
        ]
        if self.target_channel is not None and self.target_channel > 0:
            cmd.extend(["--channel", str(self.target_channel)])
        else:
            cmd.extend(["--band", "abg"])
        if self._target_bssid_colon:
            cmd.extend(["--bssid", self._target_bssid_colon])
        cmd.extend([
            "--output-format", "csv",
            "--write", self.airo_prefix,
            use,
        ])

        self.logger.info(
            f"Launching airodump-ng on {use}: bssid={self._target_bssid_colon or 'any'}, "
            f"channel={self.target_channel if self.target_channel is not None else 'hop'}"
        )
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

    def _read_airodump_rows_once(self) -> List[Dict[str, Any]]:
        """Read only the AP section from the latest airodump-ng CSV."""
        csv_path = self._latest_csv_path()
        if not csv_path:
            return []

        try:
            with open(csv_path, errors="ignore", newline="") as f:
                rows = list(csv.reader(f))
        except Exception:
            return []

        idx = next((i for i, r in enumerate(rows) if r and r[0].strip().upper() == "BSSID"), None)
        if idx is None:
            return []

        out: List[Dict[str, Any]] = []
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
                bssid_norm = self._normalize_bssid(bssid)
                if len(bssid_norm) != 12 or any(c not in "0123456789abcdef" for c in bssid_norm):
                    continue

                channel = int(float(r[3].strip())) if r[3].strip() else None
                if channel is not None and channel <= 0:
                    channel = None

                rssi = float(r[8].strip()) if r[8].strip() else None
                ssid = r[13].strip(" ,\t\r\n")
                if ssid.lower() in {"<hidden>", "broadcast", "unknown"}:
                    ssid = ""

                band = ""
                frequency_mhz = None
                if channel is not None:
                    if 1 <= channel <= 14:
                        band = "2.4GHz"
                        frequency_mhz = 2484.0 if channel == 14 else 2412.0 + 5.0 * (channel - 1)
                    elif 30 <= channel <= 177:
                        band = "5GHz"
                        frequency_mhz = 5000.0 + 5.0 * channel

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

    # -----------------------
    # Position / spatial sampling
    # -----------------------
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
        row: Dict[str, Any],
        position: Dict[str, Any],
        now_epoch: float,
    ) -> None:
        self._active_cluster = {
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
        self._add_cluster_sample(row, now_epoch)

    def _add_cluster_sample(
        self,
        row: Dict[str, Any],
        now_epoch: float,
    ) -> None:
        if self._active_cluster is None:
            return

        rssi = row.get("rssi_dbm")
        if rssi is None:
            return

        self._active_cluster["samples"].append({
            "timestamp_epoch": now_epoch,
            "rssi_dbm": float(rssi),
            "row": dict(row),
        })
        self._active_cluster["last_sample_epoch"] = now_epoch

    def _cluster_far_enough_to_emit(
        self,
        cluster: Dict[str, Any],
    ) -> bool:
        if self._last_emitted_position is None:
            return True

        distance = self._distance_m(
            float(self._last_emitted_position[0]),
            float(self._last_emitted_position[1]),
            float(cluster["anchor_latitude"]),
            float(cluster["anchor_longitude"]),
        )
        return distance >= self.measurement_spacing_m

    async def _finalize_active_cluster(
        self,
        reason: str,
    ) -> bool:
        cluster = self._active_cluster
        if not cluster or cluster.get("settled", False):
            return False

        cluster["settled"] = True
        samples = cluster.get("samples") or []
        if not samples:
            return False

        if not self._cluster_far_enough_to_emit(cluster):
            self.logger.debug(
                "Skipping Wi-Fi geolocation cluster within "
                f"{self.measurement_spacing_m:.1f} m of the last "
                "emitted receiver position"
            )
            return False

        values = sorted(
            float(sample["rssi_dbm"])
            for sample in samples
        )
        midpoint = len(values) // 2
        if len(values) % 2:
            median_rssi = values[midpoint]
        else:
            median_rssi = 0.5 * (
                values[midpoint - 1]
                + values[midpoint]
            )

        latest_sample = max(
            samples,
            key=lambda sample: float(
                sample.get("timestamp_epoch") or 0.0
            ),
        )
        row = latest_sample.get("row") or {}

        channel = (
            row.get("channel")
            if row.get("channel") is not None
            else self.target_channel
        )
        frequency_mhz = row.get("frequency_mhz")
        if frequency_mhz is None:
            frequency_mhz = self.target_frequency_mhz

        lat = float(cluster["anchor_latitude"])
        lon = float(cluster["anchor_longitude"])
        alt = float(cluster.get("anchor_altitude") or 0.0)

        await self._emit_detection(
            target_id=self.target_id,
            ssid=row.get("ssid", ""),
            bssid=row.get("bssid", "") or self._target_bssid_colon,
            channel=channel,
            band=row.get("band", ""),
            frequency_mhz=frequency_mhz,
            rssi_dbm=median_rssi,
            encryption=row.get("encryption", ""),
            lat=lat,
            lon=lon,
            alt=alt,
            timestamp_epoch=float(
                latest_sample.get("timestamp_epoch")
                or time.time()
            ),
            source_last_seen=str(
                row.get("source_last_seen") or ""
            ),
            location_source=str(
                cluster.get("location_source") or ""
            ),
            aggregation_sample_count=len(values),
        )

        self._last_emitted_position = (lat, lon)
        self._emitted_measurement_count += 1

        self.logger.info(
            f"Wi-Fi geolocation measurement "
            f"target={self.target_id} "
            f"bssid={self._target_bssid_colon} "
            f"rssi_median={median_rssi:.1f} dBm "
            f"samples={len(values)} "
            f"position=({lat:.6f}, {lon:.6f}) "
            f"reason={reason}"
        )
        await self._set_status(
            f"Tracking Wi-Fi target {self.target_id}: "
            f"{median_rssi:.1f} dBm / "
            f"{self._emitted_measurement_count} positions"
        )
        return True

    # -----------------------
    # Detection emit
    # -----------------------
    async def _emit_detection(
        self,
        *,
        target_id: str,
        ssid: str,
        bssid: str,
        channel: Optional[int],
        band: str,
        frequency_mhz: Optional[float],
        rssi_dbm: Optional[float],
        encryption: str,
        lat: float,
        lon: float,
        alt: float,
        timestamp_epoch: float,
        source_last_seen: str,
        location_source: str,
        aggregation_sample_count: int,
    ) -> None:
        detection = {
            "kind": "detection",
            "event_type": "detection",
            "detection_kind": "wifi_geolocate_target",
            "target_id": target_id,
            "node_uid": str(self.node_uid),
            "source_id": self.source_id,
            "frequency_hz": int(round(float(frequency_mhz) * 1e6)) if frequency_mhz is not None else None,
            "power_dbm": float(rssi_dbm) if rssi_dbm is not None else None,
            "metric_units": "dBm",
            "timestamp": float(timestamp_epoch),
            "detector": "wifi_geolocate_target",
            "opid": self.opid,
            "operation_id": self.opid,
            "ssid": ssid,
            "bssid": bssid,
            "channel": channel,
            "band": band,
            "encryption": encryption,
            "latitude": float(lat),
            "longitude": float(lon),
            "altitude": float(alt or 0.0),
            "aggregation": "median",
            "aggregation_window_s": float(self.aggregation_window_s),
            "aggregation_sample_count": int(aggregation_sample_count),
            "spatial_cluster_radius_m": float(self.cluster_radius_m),
            "measurement_spacing_m": float(self.measurement_spacing_m),
            "source_last_seen": source_last_seen,
            "location_source": location_source,
            "location_semantics": "receiver_observation",
            "location_valid": True,
        }
        detection = {k: v for k, v in detection.items() if v is not None}

        await self._run_callback(
            "detection_callback",
            getattr(self, "detection_callback", None),
            detection,
        )

    async def _stop_airodump(self) -> None:
        proc = self._airodump_proc
        if not proc or proc.returncode is not None:
            return

        self._kill_existing_airodump("TERM")

        try:
            await asyncio.wait_for(
                proc.wait(),
                timeout=1.5,
            )
        except asyncio.TimeoutError:
            self._kill_existing_airodump("KILL")

            try:
                await asyncio.wait_for(
                    proc.wait(),
                    timeout=0.75,
                )
            except asyncio.TimeoutError:
                self.logger.warning(
                    "airodump-ng did not exit after SIGKILL"
                )

        if proc.stderr:
            try:
                stderr_data = await asyncio.wait_for(
                    proc.stderr.read(),
                    timeout=0.5,
                )
            except Exception:
                stderr_data = b""

            if stderr_data:
                self.logger.debug(
                    "airodump-ng stderr:\n"
                    + stderr_data.decode(errors="ignore")
                )

    # -----------------------
    # Main run
    # -----------------------
    async def run(self) -> None:
        try:
            self._apply_parameters_from_runner()

            if not self.target_id:
                raise RuntimeError(
                    "wifi_geolocate_target requires target_id"
                )

            if self.target_bssid:
                bssid_norm = self._normalize_bssid(self.target_bssid)
                if len(bssid_norm) != 12:
                    raise RuntimeError(
                        "wifi_geolocate_target received invalid "
                        f"BSSID={self.target_bssid}"
                    )
                self._target_bssid_norm = bssid_norm
                self._target_bssid_colon = ":".join(
                    bssid_norm[i:i + 2]
                    for i in range(0, 12, 2)
                ).upper()
            else:
                (
                    self._target_bssid_norm,
                    self._target_bssid_colon,
                ) = self._derive_bssid_from_target_id(
                    self.target_id
                )

            if not self._target_bssid_norm:
                raise RuntimeError(
                    "wifi_geolocate_target could not resolve BSSID "
                    f"for target_id={self.target_id}"
                )

            self.logger.info(
                "Starting Wi-Fi geolocate target operation: "
                f"target_id={self.target_id}, "
                f"target_bssid={self._target_bssid_colon}, "
                f"channel={self.target_channel}, "
                f"scan_refresh_s={self.wifi_refresh_interval}, "
                f"aggregation_window_s={self.aggregation_window_s}, "
                f"cluster_radius_m={self.cluster_radius_m}, "
                f"measurement_spacing_m={self.measurement_spacing_m}"
            )
            await self._set_status(
                f"Geolocating Wi-Fi target {self.target_id}"
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

                matched_row = None
                for row in rows:
                    if (
                        row.get("bssid_norm", "")
                        == self._target_bssid_norm
                    ):
                        matched_row = row
                        break

                if matched_row is not None:
                    source_last_seen = str(
                        matched_row.get("source_last_seen") or ""
                    ).strip()

                    if (
                        source_last_seen
                        and source_last_seen
                        != self._last_source_seen
                    ):
                        # Consume the airodump sighting before checking
                        # position. A stale cumulative row must never be
                        # paired later with a newer receiver position.
                        self._last_source_seen = source_last_seen

                        position = self._snapshot_position()
                        if position.get("valid", False):
                            now_epoch = time.time()

                            if self._active_cluster is None:
                                self._start_cluster(
                                    matched_row,
                                    position,
                                    now_epoch,
                                )
                            else:
                                distance_from_anchor = self._distance_m(
                                    float(
                                        self._active_cluster[
                                            "anchor_latitude"
                                        ]
                                    ),
                                    float(
                                        self._active_cluster[
                                            "anchor_longitude"
                                        ]
                                    ),
                                    float(position["latitude"]),
                                    float(position["longitude"]),
                                )

                                if (
                                    distance_from_anchor
                                    > self.cluster_radius_m
                                ):
                                    await self._finalize_active_cluster(
                                        "receiver_moved"
                                    )
                                    self._start_cluster(
                                        matched_row,
                                        position,
                                        now_epoch,
                                    )
                                elif not self._active_cluster.get(
                                    "settled",
                                    False,
                                ):
                                    self._add_cluster_sample(
                                        matched_row,
                                        now_epoch,
                                    )
                        else:
                            await self._set_status(
                                "Waiting for valid Sensor Node position "
                                f"while tracking {self.target_id}"
                            )

                cluster = self._active_cluster
                if (
                    cluster
                    and not cluster.get("settled", False)
                    and (
                        time.monotonic()
                        - float(cluster["started_monotonic"])
                    )
                    >= self.aggregation_window_s
                ):
                    await self._finalize_active_cluster(
                        "aggregation_window"
                    )

                if (
                    matched_row is None
                    and self._active_cluster is None
                ):
                    await self._set_status(
                        f"Searching for Wi-Fi target {self.target_id}"
                    )

                await asyncio.sleep(self.wifi_refresh_interval)

        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.exception(
                f"Wi-Fi geolocate target operation error: {e}"
            )
        finally:
            try:
                await self._finalize_active_cluster(
                    "operation_stopped"
                )
            except Exception:
                self.logger.exception(
                    "Unable to finalize last Wi-Fi geolocation cluster"
                )

            try:
                await self._stop_airodump()
            except Exception:
                pass

            try:
                await self._to_thread_compat(
                    self._restore_managed
                )
            except Exception:
                pass

            await self._set_status("Idle")
            self.logger.info(
                "Wi-Fi geolocate target operation stopped cleanly."
            )

    async def _to_thread_compat(self, func, *args, **kwargs):
        if hasattr(asyncio, "to_thread"):
            return await asyncio.to_thread(func, *args, **kwargs)

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})