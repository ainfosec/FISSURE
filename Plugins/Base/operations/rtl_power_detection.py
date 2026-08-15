#!/usr/bin/env python3
"""
RTL-SDR Segmented Spectrum Detector (rtl_power) - FISSURE Plugin

Calls external rtl_power and emits periodic detections for strongest
max-hold signals observed in a selected segment.
"""

import asyncio
import contextlib
import logging
import os
import shutil
import statistics
import sys
import time
from typing import Any, Callable, Dict, Optional, Union


PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

try:
    from fissure.utils.plugins.operations import Operation
except ImportError:
    if FISSURE_REPO_ROOT not in sys.path:
        sys.path.insert(0, FISSURE_REPO_ROOT)

    if PLUGIN_ROOT not in sys.path:
        sys.path.insert(0, PLUGIN_ROOT)

    from fissure.utils.plugins.operations import Operation


ALLOWED_SEGMENT_RANGES_MHZ = {
    "24-300": (24e6, 300e6),
    "300-600": (300e6, 600e6),
    "600-900": (600e6, 900e6),
    "900-1200": (900e6, 1200e6),
    "1200-1500": (1200e6, 1500e6),
    "1500-1764": (1500e6, 1764e6),
}

STEP = 100e3
DWELL = 0.05

BASELINE_SWEEPS = 4
BASELINE_ALPHA = 0.1

MAX_ALERT_SIGNALS = 5
MAX_HOLD_WINDOW = 5.0


def tstamp() -> str:
    return time.strftime("%H:%M:%S.") + f"{int((time.time() % 1) * 1000):03d}"


def parse_rtl_power_csv(line: str):
    parts = line.strip().split(",")

    if len(parts) < 7:
        return None

    try:
        start = float(parts[2])
        step = float(parts[4])
        n = int(parts[5])
        bins = [float(x) for x in parts[6 : 6 + n]]
        return start, step, bins
    except Exception:
        return None


def compute_hotspot_weights(baseline_sweeps):
    num_bins = len(baseline_sweeps[0])
    weights = [1.0] * num_bins

    medians = []
    stds = []
    maxvals = []

    for i in range(num_bins):
        col = [s[i] for s in baseline_sweeps]
        med = statistics.median(col)
        std = statistics.pstdev(col)
        mx = max(col)

        medians.append(med)
        stds.append(std)
        maxvals.append(mx)

    overall_med = statistics.median(medians)
    overall_std = statistics.pstdev(medians) if len(medians) > 1 else 0

    for i in range(num_bins):
        if medians[i] > overall_med + 2 * overall_std:
            weights[i] = 0.25

        if stds[i] > 8.0:
            weights[i] = min(weights[i], 0.4)

        if maxvals[i] > overall_med + 20:
            weights[i] = 0.15

    return weights


def cluster_maxhold(max_vals, seg_start, step, threshold):
    clusters = []
    i = 0
    n = len(max_vals)

    while i < n:
        if max_vals[i] >= threshold:
            best_i = i
            best_val = max_vals[i]
            i += 1

            while i < n and max_vals[i] >= threshold:
                if max_vals[i] > best_val:
                    best_val = max_vals[i]
                    best_i = i
                i += 1

            freq = seg_start + best_i * step
            clusters.append((freq, best_val))

        else:
            i += 1

    return clusters


class OperationMain(Operation):
    """RTL-SDR rtl_power detection operation."""

    def __init__(
        self,
        segment_range_mhz: str = "300-600",
        alert_interval_s: Union[str, float] = 5.0,
        detection_threshold_db: Union[str, float] = 8.0,
        description: str = "RTL-SDR rtl_power detection",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Optional[Callable] = None,
        tak_cot_callback: Optional[Callable] = None,
        detection_callback: Optional[Callable] = None,
        status_callback: Optional[Callable] = None,
    ):
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            detection_callback=detection_callback,
            status_callback=status_callback,
        )

        key = str(segment_range_mhz or "").strip()

        if key not in ALLOWED_SEGMENT_RANGES_MHZ:
            raise ValueError(
                f"segment_range_mhz {key!r} invalid. "
                f"Valid: {', '.join(ALLOWED_SEGMENT_RANGES_MHZ.keys())}"
            )

        self.segment_range_mhz = key
        self.seg_start, self.seg_stop = ALLOWED_SEGMENT_RANGES_MHZ[key]

        self.alert_interval_s = max(0.1, self._float(alert_interval_s, 5.0))
        self.detection_threshold_db = self._float(detection_threshold_db, 8.0)
        self.description = str(description or "RTL-SDR rtl_power detection").strip()

        self.logger.info(
            "rtl_power_detection init params: "
            f"segment_range_mhz={self.segment_range_mhz}, "
            f"alert_interval_s={self.alert_interval_s}, "
            f"detection_threshold_db={self.detection_threshold_db}, "
            f"description={self.description}"
        )

    @staticmethod
    def get_resources() -> Dict[str, Any]:
        return {}

    async def run(self) -> None:
        """Run rtl_power detection."""

        try:
            await self._run_rtl_power()

        except asyncio.CancelledError:
            self.logger.info("[RTL-POWER] rtl_power_detection cancelled")
            raise

        except Exception:
            self.logger.exception("[RTL-POWER] rtl_power_detection failed")
            raise

        finally:
            if self.status_callback:
                try:
                    await self.status_callback("Idle")
                except Exception:
                    self.logger.exception("[RTL-POWER] status_callback failed while setting Idle")

    async def _run_rtl_power(self) -> None:
        self.logger.info(
            f"[RTL-POWER] Starting sweep segment {self.segment_range_mhz}: "
            f"{self.seg_start / 1e6:.1f}-{self.seg_stop / 1e6:.1f} MHz"
        )
        self.logger.info(
            f"[RTL-POWER] Baseline sweeps={BASELINE_SWEEPS}, "
            f"step={STEP / 1e3:.0f} kHz, dwell={DWELL}s"
        )

        rtl_power_path = shutil.which("rtl_power")
        if not rtl_power_path:
            raise RuntimeError("rtl_power executable not found in PATH")

        cmd = [
            rtl_power_path,
            "-f",
            f"{int(self.seg_start)}:{int(self.seg_stop)}:{int(STEP)}",
            "-i",
            str(DWELL),
            "-",
        ]

        stdbuf_path = shutil.which("stdbuf")
        if stdbuf_path:
            cmd = [stdbuf_path, "-oL"] + cmd

        self.logger.info(f"[RTL-POWER] Sweep argv: {cmd!r}")

        if self.status_callback:
            await self.status_callback(f"Running: RTL power {self.segment_range_mhz} MHz")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def drain_stderr() -> None:
            if proc.stderr is None:
                return

            while True:
                line = await proc.stderr.readline()
                if not line:
                    break

                text = line.decode(errors="ignore").strip()
                if text:
                    self.logger.warning(f"[RTL-POWER stderr] {text}")

        stderr_task = asyncio.create_task(drain_stderr())

        blocks = []
        last_start = None
        sweeps_seen = 0

        baseline_ready = False
        baseline = None
        baseline_sweeps = []
        weights = None

        max_hold_vals = None
        max_hold_ts = None
        last_alert_time = time.time()

        try:
            if proc.stdout is None:
                raise RuntimeError("rtl_power stdout pipe was not created")

            while not self._stop:
                try:
                    raw = await asyncio.wait_for(proc.stdout.readline(), timeout=0.25)
                except asyncio.TimeoutError:
                    continue

                if not raw:
                    self.logger.info("[RTL-POWER] rtl_power exited: EOF on stdout")
                    break

                parsed = parse_rtl_power_csv(raw.decode(errors="ignore"))

                if parsed is None:
                    continue

                start, step, bins = parsed

                if not bins:
                    continue

                if last_start is not None and start < last_start:
                    all_bins = []
                    for _block_start, block_bins in blocks:
                        all_bins.extend(block_bins)

                    num_bins = len(all_bins)
                    now = time.time()

                    if num_bins <= 0:
                        blocks = []
                        last_start = start
                        continue

                    if baseline is None:
                        baseline = all_bins.copy()
                        baseline_sweeps = [all_bins.copy()]
                        max_hold_vals = [float("-inf")] * num_bins
                        max_hold_ts = [0.0] * num_bins
                        sweeps_seen = 1

                        self.logger.info(
                            f"[RTL-POWER] Baseline warmup {sweeps_seen}/{BASELINE_SWEEPS}"
                        )

                    elif not baseline_ready:
                        sweeps_seen += 1
                        baseline_sweeps.append(all_bins.copy())

                        baseline = [
                            max(baseline_value, sample_value)
                            for baseline_value, sample_value in zip(baseline, all_bins)
                        ]

                        self.logger.info(
                            f"[RTL-POWER] Baseline warmup {sweeps_seen}/{BASELINE_SWEEPS}"
                        )

                        if sweeps_seen >= BASELINE_SWEEPS:
                            weights = compute_hotspot_weights(baseline_sweeps)
                            baseline_ready = True
                            self.logger.info("[RTL-POWER] Baseline ready.")

                    else:
                        if (
                            baseline is None
                            or weights is None
                            or max_hold_vals is None
                            or max_hold_ts is None
                        ):
                            self.logger.warning("[RTL-POWER] Detection state incomplete; resetting baseline")
                            baseline = None
                            baseline_sweeps = []
                            weights = None
                            max_hold_vals = None
                            max_hold_ts = None
                            baseline_ready = False
                            sweeps_seen = 0
                            blocks = []
                            last_start = start
                            continue

                        if len(all_bins) != len(baseline):
                            self.logger.warning(
                                "[RTL-POWER] Sweep bin count changed; resetting baseline "
                                f"old={len(baseline)} new={len(all_bins)}"
                            )
                            baseline = None
                            baseline_sweeps = []
                            weights = None
                            max_hold_vals = None
                            max_hold_ts = None
                            baseline_ready = False
                            sweeps_seen = 0
                            blocks = []
                            last_start = start
                            continue

                        baseline = [
                            BASELINE_ALPHA * new_value + (1 - BASELINE_ALPHA) * baseline_value
                            for new_value, baseline_value in zip(all_bins, baseline)
                        ]

                        raw_delta = [
                            new_value - baseline_value
                            for new_value, baseline_value in zip(all_bins, baseline)
                        ]
                        weighted_delta = [
                            delta * weight
                            for delta, weight in zip(raw_delta, weights)
                        ]

                        for i in range(num_bins):
                            if now - max_hold_ts[i] > MAX_HOLD_WINDOW:
                                max_hold_vals[i] = float("-inf")
                                max_hold_ts[i] = 0.0

                        for i, value in enumerate(weighted_delta):
                            if value > max_hold_vals[i]:
                                max_hold_vals[i] = value
                                max_hold_ts[i] = now

                        if now - last_alert_time >= self.alert_interval_s:
                            clusters = cluster_maxhold(
                                max_hold_vals,
                                seg_start=self.seg_start,
                                step=step,
                                threshold=self.detection_threshold_db,
                            )
                            clusters.sort(key=lambda x: x[1], reverse=True)
                            clusters = clusters[:MAX_ALERT_SIGNALS]

                            if clusters:
                                freqs_mhz = [round(freq / 1e6, 3) for freq, _delta in clusters]
                                deltas_db = [round(delta, 1) for _freq, delta in clusters]
                                await self._issue_alert(freqs_mhz, deltas_db)
                            else:
                                self.logger.info(f"[{tstamp()}][RTL-POWER] No signals above threshold")

                            max_hold_vals = [float("-inf")] * num_bins
                            max_hold_ts = [0.0] * num_bins
                            last_alert_time = now

                    blocks = []

                blocks.append((start, bins))
                last_start = start

                await asyncio.sleep(0)

        finally:
            if stderr_task and not stderr_task.done():
                stderr_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await stderr_task

            if proc.returncode is None:
                self.logger.info("[RTL-POWER] Terminating sweep...")
                proc.terminate()

                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    self.logger.warning("[RTL-POWER] Killing sweep...")
                    proc.kill()
                    await proc.wait()

            self.logger.info("[RTL-POWER] Sweep stopped.")

    async def _issue_alert(self, freqs_mhz, deltas_db) -> None:
        if not freqs_mhz:
            return

        ts = time.time()
        cb_timeout_s = 2.0

        freq_str = ",".join(str(x) for x in freqs_mhz)
        delta_str = ",".join(str(x) for x in deltas_db)
        alert_text = f"RTL f:{freq_str} d:{delta_str}"

        primary_freq_mhz = float(freqs_mhz[0])
        primary_delta_db = float(deltas_db[0])

        detection = {
            "kind": "detection",
            "event_type": "detection",
            "node_uid": self.node_uid,
            "source_id": self.node_uid,
            "description": self.description,
            "frequency_hz": int(primary_freq_mhz * 1e6),
            "frequency_mhz": primary_freq_mhz,
            "power_dbm": primary_delta_db,
            "timestamp": int(ts),
            "detector": "rtl_power_detection",
            "opid": self.opid,
            "device": "RTL-SDR",
            "frequencies_mhz": freqs_mhz,
            "deltas_db": deltas_db,
            "segment_range_mhz": self.segment_range_mhz,
            "detection_threshold_db": self.detection_threshold_db,
        }

        if self.detection_callback:
            try:
                await asyncio.wait_for(self.detection_callback(detection), timeout=cb_timeout_s)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception("[RTL-POWER] detection_callback failed")
        else:
            self.logger.warning("[RTL-POWER] No detection_callback configured")

        if self.alert_callback:
            try:
                await asyncio.wait_for(
                    self.alert_callback(
                        self.node_uid,
                        self.opid,
                        alert_text,
                        self.logger,
                    ),
                    timeout=cb_timeout_s,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception("[RTL-POWER] alert_callback failed")

    @staticmethod
    def _float(value, default: float) -> float:
        try:
            return float(value)
        except Exception:
            return float(default)


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test

    run_test(OperationMain, {}, {})