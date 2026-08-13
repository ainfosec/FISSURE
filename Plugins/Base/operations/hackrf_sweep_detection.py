#!/usr/bin/env python3
"""
HackRF Sweep - FISSURE Plugin

Produces periodic alerts with strongest signals observed in a band.

Updated:
- Uses restricted string band_range_mhz values, e.g. "300-600".
- Uses per-instance values instead of module globals for alert interval / threshold.
- Calls external hackrf_sweep executable.
- Emits native Detections through detection_callback and optional alerts through alert_callback.
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


ALLOWED_BAND_RANGES_MHZ = {
    "1-300": (1e6, 300e6),
    "300-600": (300e6, 600e6),
    "600-900": (600e6, 900e6),
    "900-1500": (900e6, 1500e6),
    "1500-2000": (1500e6, 2000e6),
    "2000-2600": (2000e6, 2600e6),
    "2600-3000": (2600e6, 3000e6),
}

BIN_WIDTH = 200e3
BASELINE_SWEEPS = 30
WARMUP_SWEEPS = 5
MAX_ALERT_SIGNALS = 5


def parse_sweep_line(line: str):
    parts = line.split(",")

    if len(parts) < 6:
        return None

    try:
        f_start = float(parts[2])
        f_end = float(parts[3])
        n = int(parts[5])
        bins = [float(x) for x in parts[6 : 6 + n]]
        return f_start, f_end, bins
    except Exception:
        return None


def compute_hotspot_weights(baseline):
    num_bins = len(baseline[0])
    weights = [1.0] * num_bins

    medians = []
    stds = []
    maxvals = []

    for i in range(num_bins):
        col = [s[i] for s in baseline]
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


class OperationMain(Operation):
    """HackRF sweep detection operation."""

    def __init__(
        self,
        band_range_mhz: str = "300-600",
        alert_interval_s: Union[str, float] = 5.0,
        detection_threshold_db: Union[str, float] = 12.0,
        description: str = "HackRF sweep detection",
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

        key = str(band_range_mhz or "").strip()

        if key not in ALLOWED_BAND_RANGES_MHZ:
            allowed = ", ".join(ALLOWED_BAND_RANGES_MHZ.keys())
            raise ValueError(f"Invalid band_range_mhz={key!r}. Allowed: {allowed}")

        self.band_range_mhz = key
        self.F_START, self.F_STOP = ALLOWED_BAND_RANGES_MHZ[key]

        self.alert_interval_s = max(0.1, self._float(alert_interval_s, 5.0))
        self.detection_threshold_db = self._float(detection_threshold_db, 12.0)
        self.description = str(description or "HackRF sweep detection").strip()

        self.blocks: Dict[float, Dict[str, Any]] = {}
        self.window_detections = []
        self.last_alert_time = time.time()

        self.logger.info(
            "[HACKRF] init params: "
            f"band_range_mhz={self.band_range_mhz}, "
            f"start={self.F_START / 1e6:.1f} MHz, "
            f"stop={self.F_STOP / 1e6:.1f} MHz, "
            f"alert_interval_s={self.alert_interval_s}, "
            f"detection_threshold_db={self.detection_threshold_db}, "
            f"description={self.description}"
        )

    @staticmethod
    def get_resources() -> Dict[str, Any]:
        return {}

    async def run(self) -> None:
        """Run HackRF sweep detection."""

        try:
            await self._run_sweep()

        except asyncio.CancelledError:
            self.logger.info("[HACKRF] hackrf_sweep_detection cancelled")
            raise

        except Exception:
            self.logger.exception("[HACKRF] hackrf_sweep_detection failed")
            raise

        finally:
            if self.status_callback:
                try:
                    await self.status_callback("Idle")
                except Exception:
                    self.logger.exception("[HACKRF] status_callback failed while setting Idle")

    async def _run_sweep(self) -> None:
        self.logger.info(
            f"[HACKRF] Starting sweep band={self.band_range_mhz} "
            f"{self.F_START / 1e6:.1f}-{self.F_STOP / 1e6:.1f} MHz"
        )

        hackrf_sweep_path = shutil.which("hackrf_sweep")
        if not hackrf_sweep_path:
            raise RuntimeError("hackrf_sweep executable not found in PATH")

        cmd = [
            hackrf_sweep_path,
            "-f",
            f"{int(self.F_START / 1e6)}:{int(self.F_STOP / 1e6)}",
            "-w",
            str(int(BIN_WIDTH)),
        ]

        stdbuf_path = shutil.which("stdbuf")
        if stdbuf_path:
            cmd = [stdbuf_path, "-oL"] + cmd

        self.logger.info(f"[HACKRF] Sweep argv: {cmd!r}")

        if self.status_callback:
            await self.status_callback(f"Running: HackRF sweep {self.band_range_mhz} MHz")

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
                    self.logger.warning(f"[HACKRF stderr] {text}")

        stderr_task = asyncio.create_task(drain_stderr())

        try:
            if proc.stdout is None:
                raise RuntimeError("hackrf_sweep stdout pipe was not created")

            while not self._stop:
                try:
                    raw = await asyncio.wait_for(proc.stdout.readline(), timeout=0.25)
                except asyncio.TimeoutError:
                    continue

                if not raw:
                    self.logger.info("[HACKRF] hackrf_sweep exited: EOF on stdout")
                    break

                line = raw.decode(errors="ignore").strip()
                parsed = parse_sweep_line(line)

                if parsed is None:
                    continue

                f_start, _f_end, bins = parsed

                if not bins:
                    continue

                if f_start not in self.blocks:
                    self.blocks[f_start] = {
                        "baseline_sweeps": [],
                        "baseline": None,
                        "weights": None,
                        "ready": False,
                        "warmup": 0,
                    }

                blk = self.blocks[f_start]

                if blk["warmup"] < WARMUP_SWEEPS:
                    blk["warmup"] += 1
                    continue

                if not blk["ready"]:
                    blk["baseline_sweeps"].append(bins)

                    if blk["baseline"] is None:
                        blk["baseline"] = bins.copy()
                    else:
                        blk["baseline"] = [
                            max(baseline_value, sample_value)
                            for baseline_value, sample_value in zip(blk["baseline"], bins)
                        ]

                    if len(blk["baseline_sweeps"]) >= BASELINE_SWEEPS:
                        blk["weights"] = compute_hotspot_weights(blk["baseline_sweeps"])
                        blk["ready"] = True
                        self.logger.info(
                            f"[HACKRF] Baseline ready for block starting {f_start / 1e6:.3f} MHz"
                        )

                    continue

                weighted = [
                    (sample_value - baseline_value) * weight
                    for sample_value, baseline_value, weight in zip(
                        bins,
                        blk["baseline"],
                        blk["weights"],
                    )
                ]

                if not weighted:
                    continue

                max_delta = max(weighted)
                idx = weighted.index(max_delta)
                freq = f_start + idx * BIN_WIDTH

                if max_delta >= self.detection_threshold_db:
                    self.window_detections.append((freq, max_delta))

                now = time.time()
                if now - self.last_alert_time >= self.alert_interval_s:
                    if self.window_detections:
                        self.window_detections.sort(key=lambda x: x[1], reverse=True)
                        strongest = self.window_detections[:MAX_ALERT_SIGNALS]

                        freqs = [round(f / 1e6, 3) for f, _d in strongest]
                        deltas = [round(d, 2) for _f, d in strongest]

                        await self._issue_alert(freqs, deltas)

                    self.window_detections.clear()
                    self.last_alert_time = now

        finally:
            if stderr_task and not stderr_task.done():
                stderr_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await stderr_task

            if proc.returncode is None:
                self.logger.info("[HACKRF] Terminating sweep...")
                proc.terminate()

                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    self.logger.warning("[HACKRF] Killing sweep...")
                    proc.kill()
                    await proc.wait()

            self.logger.info("[HACKRF] Sweep stopped.")

    async def _issue_alert(self, freqs, deltas) -> None:
        if not freqs:
            return

        ts = time.time()
        cb_timeout_s = 2.0

        freqs_str = ",".join(str(x) for x in freqs)
        deltas_str = ",".join(str(x) for x in deltas)

        alert_text = f"HackRF sweep f:{freqs_str} d:{deltas_str}"

        primary_freq_mhz = float(freqs[0])
        primary_delta_db = float(deltas[0])

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
            "detector": "hackrf_sweep_detection",
            "opid": self.opid,
            "device": "HackRF",
            "frequencies_mhz": freqs,
            "deltas_db": deltas,
            "band_range_mhz": self.band_range_mhz,
            "detection_threshold_db": self.detection_threshold_db,
        }

        if self.detection_callback:
            try:
                await asyncio.wait_for(self.detection_callback(detection), timeout=cb_timeout_s)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception("[HACKRF] detection_callback failed")
        else:
            self.logger.warning("[HACKRF] No detection_callback configured")

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
                self.logger.exception("[HACKRF] alert_callback failed")

    @staticmethod
    def _float(value, default: float) -> float:
        try:
            return float(value)
        except Exception:
            return float(default)


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test

    run_test(OperationMain, {}, {})