"""Shared receiver, lifecycle, FISSURE callbacks, and Artifacts for both scans.

This is a mixin, not a standalone Operation. The two OperationMain classes
combine it with FISSURE's Operation base for normal setup/stop/teardown.
"""
import asyncio
from datetime import datetime, timezone
import json
import logging
import math
import os
from pathlib import Path
import shutil
import time
from typing import Any, Callable, Dict, List, Optional

from nrsc5_parser import parse_nrsc5_output
from hd_radio_survey import parse_rtl_power_csv, select_candidates
from hd_radio_report import render_text, render_csv, summarize


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def channel_tenths(value: Any, name: str) -> int:
    try:
        value = float(value)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError("%s must be a US FM channel" % name) from exc
    if not math.isfinite(value):
        raise ValueError("%s must be finite" % name)
    tenths = round(value * 10)
    if abs(tenths / 10 - value) > 0.0001 or tenths < 881 or tenths > 1079 or tenths % 2 != 1:
        raise ValueError("%s must be an odd-tenth FM channel 88.1–107.9 MHz" % name)
    return tenths


def int_param(value: Any, name: str, minimum: int, maximum: int) -> int:
    try:
        number = float(value)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError("%s must be an integer" % name) from exc
    if not math.isfinite(number) or not number.is_integer() or not minimum <= number <= maximum:
        raise ValueError("%s must be an integer in [%d, %d]" % (name, minimum, maximum))
    return int(number)


def float_param(value: Any, name: str, minimum: float, maximum: float) -> float:
    try:
        number = float(value)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError("%s must be numeric" % name) from exc
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise ValueError("%s must be between %g and %g" % (name, minimum, maximum))
    return number


class ScanCore:
    """Common implementation; mix with FISSURE Operation in each entry point."""

    mode = "full"

    def __init__(
        self,
        start_frequency_mhz: float = 88.1,
        stop_frequency_mhz: float = 107.9,
        sdr_index: int = 0,
        gain_db: float = -1,
        acquisition_time_s: float = 15,
        ppm_correction: int = 0,
        survey_seconds: float = 6,
        threshold_db: float = 6,
        max_candidates: int = 40,
        min_candidates: int = 12,
        retry_sync_seconds: float = 12,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        status_callback: Optional[Callable] = None,
        artifact_manager=None,
    ) -> None:
        """Configure a finite US FM NRSC-5 scan.

        Parameters
        ----------
        start_frequency_mhz : float, optional
            First US FM channel, inclusive.
        stop_frequency_mhz : float, optional
            Last US FM channel, inclusive.
        sdr_index : int, optional
            Local RTL2832U index used by nrsc5 and rtl_power.
        gain_db : float, optional
            Tuner gain in dB; -1 uses automatic gain.
        acquisition_time_s : float, optional
            NRSC-5 dwell time per channel (full scan, or quick first pass).
        ppm_correction : int, optional
            Frequency calibration in parts per million.
        survey_seconds : float, optional
            FFT survey integration duration in seconds (Quick only).
        threshold_db : float, optional
            Minimum power above survey noise reference (Quick only).
        max_candidates : int, optional
            Maximum surveyed channel centers to decode; 0 means unlimited (Quick only).
        min_candidates : int, optional
            Minimum highest-power centers decoded even below threshold (Quick only).
        retry_sync_seconds : float, optional
            Additional dwell on sync-only channels (Quick only).
        node_uid : str, optional
            Injected FISSURE Sensor Node UID.
        logger : logging.Logger, optional
            Injected FISSURE logger.
        status_callback : Callable, optional
            Injected FISSURE status callback accepting one string.
        artifact_manager : ArtifactManager, optional
            Injected FISSURE ArtifactManager.
        """
        self.sdr_index = int_param(sdr_index, "sdr_index", 0, 31)
        self.resource_args = {"sdr_index": self.sdr_index}
        super().__init__(node_uid=node_uid, logger=logger, status_callback=status_callback,
                         artifact_manager=artifact_manager)
        first = channel_tenths(start_frequency_mhz, "start_frequency_mhz")
        last = channel_tenths(stop_frequency_mhz, "stop_frequency_mhz")
        if first > last:
            raise ValueError("start_frequency_mhz cannot exceed stop_frequency_mhz")
        self.channels_tenths = list(range(first, last + 1, 2))
        self.start_frequency_mhz = first / 10
        self.stop_frequency_mhz = last / 10
        self.ppm_correction = int_param(ppm_correction, "ppm_correction", -150, 150)
        self.acquisition_time_s = float_param(acquisition_time_s, "acquisition_time_s", 3, 120)
        self.gain_db = float_param(gain_db, "gain_db", -1, 50)
        if -1 < self.gain_db < 0:
            raise ValueError("gain_db must be -1 for auto, or 0–50")
        self.survey_seconds = float_param(survey_seconds, "survey_seconds", 2, 60)
        self.threshold_db = float_param(threshold_db, "threshold_db", 0, 40)
        self.max_candidates = int_param(max_candidates, "max_candidates", 0, 100)
        self.min_candidates = int_param(min_candidates, "min_candidates", 0, 100)
        if self.max_candidates and self.min_candidates > self.max_candidates:
            raise ValueError("min_candidates must not exceed max_candidates")
        self.retry_sync_seconds = float_param(retry_sync_seconds, "retry_sync_seconds", 0, 120)
        self._process = None
        self._reader_task = None

    @staticmethod
    def get_resources(sdr_index: int = 0) -> Dict[str, Dict[str, str]]:
        return {"rtl_sdr": {"type": "sdr", "model": "RTL2832U", "serial": str(sdr_index)}}

    async def _status(self, text: str) -> None:
        try:
            # SensorNode.publish_status_to_hiprfisr accepts ONE status string.
            await asyncio.wait_for(self.status_callback(text), timeout=3)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.logger.warning("HD Radio status callback failed: %s", exc)

    def _command(self, executable: str, frequency_mhz: float) -> List[str]:
        # -t is NOT accepted by the owner's nrsc5 (older CLI). Use -o only.
        cmd = [executable, "-d", str(self.sdr_index), "-p", str(self.ppm_correction),
               "-o", os.devnull]
        if self.gain_db >= 0:
            cmd.extend(["-g", str(self.gain_db)])
        cmd.extend(["%.1f" % frequency_mhz, "0"])
        return cmd

    def _survey_command(self, executable: str) -> List[str]:
        # Include the full skirts of the first and last requested stations.
        low = int(self.channels_tenths[0] * 100000 - 150000)
        high = int(self.channels_tenths[-1] * 100000 + 150000)
        cmd = [executable, "-f", "%d:%d:100000" % (low, high),
               "-i", "%gs" % self.survey_seconds, "-1",
               "-d", str(self.sdr_index), "-p", str(self.ppm_correction)]
        if self.gain_db >= 0:
            cmd.extend(["-g", str(self.gain_db)])
        # stdout CSV, stderr diagnostic, no survey output left on disk.
        cmd.append("-")
        return cmd

    async def _read_lines(self, process, collected: List[str]) -> None:
        while True:
            data = await process.stdout.readline()
            if not data:
                return
            if len(collected) < 3000:
                collected.append(data.decode("utf-8", errors="replace").rstrip("\r\n"))

    async def _end_process(self, process) -> None:
        if process is None:
            return
        if process.returncode is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(process.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                if process.returncode is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                await process.wait()
        if self._reader_task is not None:
            try:
                await asyncio.wait_for(self._reader_task, timeout=2.0)
            except asyncio.TimeoutError:
                self._reader_task.cancel()
                await asyncio.gather(self._reader_task, return_exceptions=True)
            finally:
                self._reader_task = None

    async def _acquire(self, executable: str, frequency_mhz: float, duration_s: float,
                       sync_extension_s: float = 0) -> Dict[str, Any]:
        """Acquire on one receiver session; extend a sync-only Quick dwell in place."""
        lines = []
        started = asyncio.get_running_loop().time()
        process = None
        unexpected_exit = False
        extended = False
        try:
            process = await asyncio.create_subprocess_exec(
                *self._command(executable, frequency_mhz),
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT)
            self._process = process
            self._reader_task = asyncio.create_task(self._read_lines(process, lines))
            deadline = started + duration_s
            while not self._stop:
                if process.returncode is not None:
                    unexpected_exit = True
                    break
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    if sync_extension_s > 0 and not extended:
                        preliminary = parse_nrsc5_output(lines, frequency_mhz)
                        if preliminary["classification"] == "sync_only_unconfirmed":
                            extended = True
                            deadline += sync_extension_s
                            await self._status(
                                "HD Radio Quick Scan: synced %.1f MHz; extending decode" % frequency_mhz)
                            continue
                    break
                await asyncio.sleep(min(0.1, remaining))
        finally:
            await self._end_process(process)
            self._process = None
        record = parse_nrsc5_output(lines, frequency_mhz)
        record["acquisition_seconds"] = round(asyncio.get_running_loop().time() - started, 2)
        record["observed_at_utc"] = utc_now()
        if extended:
            record["extended_after_sync"] = True
            record["notes"].append("Quick Scan extended its original NRSC-5 session after synchronization.")
        if self._stop:
            record["acquisition_status"] = "interrupted"
        elif unexpected_exit:
            record["acquisition_status"] = "failed"
            record["error"] = "nrsc5 exited before acquisition timeout: " + " | ".join(lines[-5:])[:600]
            record["classification"] = "no_hd_confirmed"
        else:
            record["acquisition_status"] = "complete"
        return record

    async def _survey(self, executable: str):
        await self._status("HD Radio Quick Scan: surveying FM spectrum with rtl_power")
        process = None
        task = None
        start = asyncio.get_running_loop().time()
        try:
            process = await asyncio.create_subprocess_exec(
                *self._survey_command(executable),
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            self._process = process
            task = asyncio.create_task(process.communicate())
            # -1 exits after a single FFT integration. A bounded timeout stops
            # pathological driver hangs without stopping a normally slow hop.
            timeout = max(20, self.survey_seconds + 20)
            while not self._stop and not task.done():
                if asyncio.get_running_loop().time() - start > timeout:
                    raise RuntimeError("rtl_power survey exceeded %.0f seconds" % timeout)
                await asyncio.sleep(0.1)
            if self._stop:
                return None
            stdout, stderr = await task
            if process.returncode != 0:
                raise RuntimeError("rtl_power survey failed (%s): %s" % (
                    process.returncode, stderr.decode("utf-8", "replace")[-450:]))
            bins = parse_rtl_power_csv(stdout.decode("utf-8", "replace"))
            survey = select_candidates(bins, self.channels_tenths, self.threshold_db,
                                       self.max_candidates, self.min_candidates)
            survey["seconds_elapsed"] = round(asyncio.get_running_loop().time() - start, 2)
            survey["fft_bins"] = len(bins)
            return survey
        finally:
            # process.communicate() drains pipes, but must be cancelled *after*
            # termination on Stop, including interrupted acquisition.
            if process and process.returncode is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(process.wait(), timeout=2)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
            if task is not None and not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            self._process = None

    def _parameters(self):
        data = {"start_frequency_mhz": self.start_frequency_mhz,
                "stop_frequency_mhz": self.stop_frequency_mhz,
                "sdr_index": self.sdr_index, "gain_db": self.gain_db,
                "acquisition_time_s": self.acquisition_time_s,
                "ppm_correction": self.ppm_correction, "step_mhz": 0.2}
        if self.mode == "quick":
            data.update({"survey_seconds": self.survey_seconds,
                         "threshold_db": self.threshold_db,
                         "max_candidates": self.max_candidates,
                         "min_candidates": self.min_candidates,
                         "retry_sync_seconds": self.retry_sync_seconds})
        return data

    def _write_artifact(self, payload: Dict[str, Any]) -> str:
        if self.artifact_manager is None:
            raise RuntimeError("FISSURE ArtifactManager is unavailable")
        _, files_dir = self.artifact_manager.create_operation_dir(self.opid)
        directory = Path(files_dir)
        data = {
            directory / "hd_radio_stations.txt": (render_text(payload), "summary", "text/plain"),
            directory / "hd_radio_stations.csv": (render_csv(payload), "stations", "text/csv"),
            directory / "hd_radio_scan.json": (json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
                                                   "observations", "application/json"),
        }
        for path, (content, _, _) in data.items():
            path.write_text(content, encoding="utf-8")
        metadata = {
            "role": "hd_radio_scan", "scan_mode": self.mode,
            "scan_status": payload["status"],
            "confirmed_station_count": len(payload["confirmed_stations"]),
            "sync_only_count": len(payload["synchronization_candidates"]),
            "channels_scanned": len(payload["observations"]),
            "start_frequency_mhz": self.start_frequency_mhz,
            "stop_frequency_mhz": self.stop_frequency_mhz,
        }
        files = [str(path) for path in data]
        file_metadata = {str(path): {"role": role, "content_type": mime}
                         for path, (_, role, mime) in data.items()}
        identifier = self.create_artifact(
            files=files,
            name="HD Radio %s Scan (%s)" % (self.mode.title(), payload["status"]),
            artifact_type="analysis", metadata=metadata, file_metadata=file_metadata)
        if not identifier:
            raise RuntimeError("FISSURE did not register the scan Artifact")
        return identifier

    async def run(self) -> None:
        """Finite scan; runner handles final teardown and SDR resource release."""
        started_wall = utc_now()
        started = time.monotonic()
        observations = []
        errors = []
        survey = None
        status = "completed"
        failure = None
        try:
            executable = shutil.which("nrsc5")
            if not executable:
                raise RuntimeError("nrsc5 executable missing on the Sensor Node")
            frequencies = [f / 10 for f in self.channels_tenths]
            if self.mode == "quick":
                rtl_power = shutil.which("rtl_power")
                if not rtl_power:
                    raise RuntimeError("rtl_power executable missing; Quick Scan needs rtl-sdr tools")
                survey = await self._survey(rtl_power)
                if self._stop:
                    status = "interrupted"
                    return
                frequencies = survey["candidate_frequencies_mhz"]
                await self._status("HD Radio Quick Scan: %d/%d candidate FM channels (%.1fs survey)" % (
                    len(frequencies), len(self.channels_tenths), survey["seconds_elapsed"]))
            for index, frequency in enumerate(frequencies, 1):
                if self._stop:
                    status = "interrupted"
                    break
                await self._status("HD Radio %s Scan: %.1f MHz (%d/%d); confirmed %d, sync-only %d" % (
                    self.mode.title(), frequency, index, len(frequencies),
                    sum(r["classification"] == "confirmed_hd_radio" and r["acquisition_status"] == "complete"
                        for r in observations),
                    sum(r["classification"] == "sync_only_unconfirmed" and r["acquisition_status"] == "complete"
                        for r in observations)))
                record = await self._acquire(
                    executable, frequency, self.acquisition_time_s,
                    self.retry_sync_seconds if self.mode == "quick" else 0)
                observations.append(record)
                if record["acquisition_status"] == "interrupted":
                    status = "interrupted"
                    break
                if record["acquisition_status"] == "failed":
                    errors.append({"frequency_mhz": frequency, "error": record["error"]})
                    status = "failed"
                    failure = RuntimeError("NRSC-5 acquisition failed at %.1f MHz: %s" % (
                        frequency, record.get("error", "unknown decoder failure")))
                    break
                if record["classification"] == "confirmed_hd_radio":
                    name = record["station_identifiers"].get("station_name") or "identity unavailable"
                    message = "HD Radio %s Scan: confirmed %.1f MHz %s (%d stations)" % (
                        self.mode.title(), frequency, name,
                        sum(r["classification"] == "confirmed_hd_radio" and r["acquisition_status"] == "complete"
                            for r in observations))
                    self.logger.info(message)
                    await self._status(message)
                await asyncio.sleep(0)
            if self._stop:
                status = "interrupted"
        except asyncio.CancelledError:
            status = "interrupted"
            self._stop = True
            raise
        except Exception as exc:
            status = "failed"
            failure = exc
            errors.append({"error": str(exc)})
            self.logger.exception("HD Radio %s Scan failed", self.mode)
        finally:
            # Cancellation/Stop/failure all terminate child processes; FISSURE
            # itself invokes teardown to release the claimed SDR resource.
            await self._end_process(self._process)
            self._process = None
            payload = {
                "format": "fissure.hd_radio_scan.v2",
                "plugin": "HD-Radio",
                "plugin_version": "1.0.0",
                "mode": self.mode,
                "node_uid": self.node_uid,
                "operation_id": self.opid,
                "started_at_utc": started_wall,
                "finished_at_utc": utc_now(),
                "duration_seconds": round(time.monotonic() - started, 2),
                "status": status,
                "parameters": self._parameters(),
                "channels_mhz": [f / 10 for f in self.channels_tenths],
                "channels_requested": len(self.channels_tenths),
                "observations": observations,
                "survey": survey,
                "errors": errors,
                "interpretation": "Only NRSC-5 synchronization with decoded station/service metadata confirms HD Radio.",
            }
            summarize(payload)
            try:
                identifier = self._write_artifact(payload)
                result = "HD Radio %s Scan %s: %d confirmed, %d sync-only, %d/%d acquired, %.1fs, Artifact %s" % (
                    self.mode.title(), status, payload["statistics"]["confirmed"],
                    payload["statistics"]["sync_only"], len(observations),
                    len(self.channels_tenths), payload["duration_seconds"], identifier)
                self.logger.info(result)
                await self._status(result)
            except Exception as exc:
                self.logger.exception("Unable to register %s HD Radio Artifact", self.mode)
                if failure is None:
                    failure = RuntimeError("Unable to register HD Radio %s Scan Artifact: %s" % (
                        self.mode, exc))
                await self._status("HD Radio %s Scan: ARTIFACT ERROR: %s" % (self.mode.title(), exc))
        if failure is not None:
            raise RuntimeError("HD Radio %s Scan failed: %s" % (self.mode.title(), failure)) from failure
