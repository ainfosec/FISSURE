#!/usr/bin/env python3
"""
Promote to SOI Operation

This operation:
1. Runs the normal_decay GNU Radio helper from scripts/promote_to_soi_lib.
2. Captures up to N burst IQ files.
3. Stops when either N files exist on disk or timeout occurs.
4. Waits for selected files to settle before computing metadata.
5. Registers the resulting files as artifacts when artifact_manager is available.
"""

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Union


PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT):
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


def list_files(path: str) -> Dict[str, os.stat_result]:
    """Return {filename: os.stat_result} for regular files under path."""
    out: Dict[str, os.stat_result] = {}

    try:
        for fname in os.listdir(path):
            full = os.path.join(path, fname)
            if os.path.isfile(full):
                out[fname] = os.stat(full)
    except FileNotFoundError:
        return {}

    return out


def is_file_stable(
    prev: os.stat_result,
    cur: os.stat_result,
    settle_seconds: float,
) -> bool:
    """
    A file is considered stable if:
      - size has not changed between observations
      - mtime has not changed between observations
      - mtime is at least settle_seconds old
    """
    return (
        prev.st_size == cur.st_size
        and prev.st_mtime == cur.st_mtime
        and (time.time() - cur.st_mtime) >= settle_seconds
    )


async def wait_for_files_to_settle(
    paths: List[str],
    settle_seconds: float = 0.4,
    max_wait: float = 3.0,
    poll: float = 0.05,
    logger: Optional[logging.Logger] = None,
) -> Dict[str, os.stat_result]:
    """
    Wait until all given file paths are stable, or until max_wait elapses.

    Returns {path: os.stat_result} using the latest observed stats.
    """
    start = time.time()
    prev: Dict[str, os.stat_result] = {}

    while True:
        curr: Dict[str, os.stat_result] = {}
        all_exist = True

        for path in paths:
            try:
                curr[path] = os.stat(path)
            except FileNotFoundError:
                all_exist = False

        if all_exist:
            if prev:
                all_stable = True

                for path in paths:
                    if not is_file_stable(prev[path], curr[path], settle_seconds):
                        all_stable = False
                        break

                if all_stable:
                    return curr

            prev = curr

        if (time.time() - start) > max_wait:
            if logger:
                logger.warning(
                    f"Timed out waiting for files to settle after {max_wait:.2f}s; "
                    "proceeding best-effort."
                )
            return curr

        await asyncio.sleep(poll)


class OperationMain(Operation):
    """Promote to SOI Operation"""

    def __init__(
        self,
        frequency_mhz: Optional[Union[str, float]] = None,
        max_files: Union[str, int] = 5,
        sample_rate: Union[str, float] = 1e6,
        threshold: Union[str, float] = 0.004,
        decay: Union[str, float] = 0.0002,
        rx_channel: str = "A:A",
        ip_address: str = "",
        serial: str = "False",
        antenna: str = "TX/RX",
        gain: Union[str, float] = 60,
        description: str = "Promote to SOI",
        operation_id: str = "",
        source_id: str = "",
        node_uid: str = "",
        soi_id: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        status_callback: Union[Callable, None] = None,
        artifact_manager=None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            status_callback=status_callback,
            artifact_manager=artifact_manager,
        )

        if frequency_mhz is None:
            self.frequency_mhz = None
        else:
            self.frequency_mhz = self._float(frequency_mhz, 0.0)

        self.max_files = max(1, self._int(max_files, 5))
        self.sample_rate = self._float(sample_rate, 1e6)
        self.threshold = self._float(threshold, 0.004)
        self.decay = self._float(decay, 0.0002)
        self.rx_channel = str(rx_channel or "A:A").strip()
        self.ip_address = str(ip_address or "").strip()
        self.serial = str(serial or "False").strip()
        self.antenna = str(antenna or "TX/RX").strip()
        self.gain = self._float(gain, 60.0)
        self.description = str(description or "Promote to SOI").strip()

        self.operation_id = str(operation_id or self.opid or uuid.uuid4())
        self.source_id = str(source_id or "").strip() or self.node_uid or "sensor_node"
        self.soi_id = str(soi_id or "").strip()

        self.logger.info(
            "promote_to_soi init params: "
            f"operation_id={self.operation_id}, "
            f"source_id={self.source_id}, "
            f"frequency_mhz={self.frequency_mhz}, "
            f"max_files={self.max_files}, "
            f"sample_rate={self.sample_rate}, "
            f"threshold={self.threshold}, "
            f"decay={self.decay}, "
            f"rx_channel={self.rx_channel}, "
            f"antenna={self.antenna}, "
            f"gain={self.gain}"
        )

    async def run(self) -> None:
        """Run the promote-to-SOI capture stage."""

        try:
            await self._run_capture()

        except asyncio.CancelledError:
            self.logger.info("promote_to_soi cancelled")
            raise

        except Exception:
            self.logger.exception("promote_to_soi failed")
            raise

        finally:
            if self.status_callback:
                try:
                    await self.status_callback("Idle")
                except Exception:
                    self.logger.exception("promote_to_soi status_callback failed while setting Idle")

    async def _run_capture(self) -> None:
        if self.frequency_mhz is None:
            raise ValueError("Missing required parameter: frequency_mhz")

        settle_seconds = 0.4
        timeout_no_files_sec = 180.0
        timeout_after_first_sec = 30.0
        settle_max_wait = 3.0
        settle_poll = 0.05

        if not self.artifact_manager:
            raise RuntimeError("promote_to_soi requires artifact_manager")

        _, output_dir = self.artifact_manager.create_operation_dir(self.operation_id)

        flowgraph_path = os.path.join(
            PLUGIN_ROOT,
            "scripts",
            "promote_to_soi_lib",
            "normal_decay.py",
        )

        if not os.path.isfile(flowgraph_path):
            raise FileNotFoundError(f"Promote-to-SOI helper flow graph not found: {flowgraph_path}")

        cmd = [
            sys.executable,
            "-u",
            flowgraph_path,
            "--sample-rate",
            str(self.sample_rate),
            "--threshold",
            str(self.threshold),
            "--decay",
            str(self.decay),
            "--max-bursts",
            str(self.max_files),
            "--rx-freq",
            str(self.frequency_mhz),
            "--channel",
            self.rx_channel,
            "--ip-address",
            self.ip_address,
            "--serial",
            self.serial,
            "--antenna",
            self.antenna,
            "--gain",
            str(self.gain),
        ]

        self.logger.info(f"Promote-to-SOI flow graph argv: {cmd!r}")
        self.logger.info(f"Promote-to-SOI output directory: {output_dir}")

        if self.status_callback:
            await self.status_callback("Running: Promote to SOI")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=output_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def _log_stdout() -> None:
            if proc.stdout is None:
                return

            while True:
                line = await proc.stdout.readline()
                if not line:
                    break

                text = line.decode(errors="ignore").strip()
                if text:
                    self.logger.debug(f"promote_to_soi stdout: {text}")

        async def _log_stderr() -> None:
            if proc.stderr is None:
                return

            while True:
                line = await proc.stderr.readline()
                if not line:
                    break

                text = line.decode(errors="ignore").strip()
                if text:
                    self.logger.warning(f"promote_to_soi stderr: {text}")

        stdout_task = asyncio.create_task(_log_stdout())
        stderr_task = asyncio.create_task(_log_stderr())

        start_time = time.time()
        first_file_time = None
        known_files: Dict[str, os.stat_result] = {}
        stable_files = set()
        stop_reason = "unknown"

        try:
            while True:
                now = time.time()

                if self._stop:
                    stop_reason = "stop_requested"
                    self.logger.info("Stop requested; exiting capture loop.")
                    break

                if proc.returncode is not None:
                    stop_reason = f"process_exited_{proc.returncode}"
                    self.logger.info(f"Promote-to-SOI process exited: rc={proc.returncode}")
                    break

                current = list_files(output_dir)
                n_files = len(current)

                if n_files > 0 and first_file_time is None:
                    first_file_time = now

                if n_files >= self.max_files:
                    stop_reason = "max_files_reached"
                    self.logger.info(f"Reached {n_files} files on disk; stopping capture.")
                    break

                if n_files == 0:
                    if (now - start_time) > timeout_no_files_sec:
                        stop_reason = "timeout_no_files"
                        self.logger.info("Capture timeout reached: no files.")
                        break
                else:
                    if first_file_time is not None and (
                        now - first_file_time
                    ) > timeout_after_first_sec:
                        stop_reason = "timeout_after_first"
                        self.logger.info("Capture timeout reached: after first file.")
                        break

                for fname, stat in current.items():
                    prev = known_files.get(fname)

                    if prev is not None and is_file_stable(prev, stat, settle_seconds):
                        if fname not in stable_files:
                            stable_files.add(fname)
                            self.logger.debug(f"File settled during capture: {fname}")

                    known_files[fname] = stat

                await asyncio.sleep(0.05)

        finally:
            if proc.returncode is None:
                self.logger.info(f"Stopping promote-to-SOI flow graph: reason={stop_reason}")
                proc.terminate()

                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    self.logger.warning("Promote-to-SOI flow graph did not terminate quickly; killing...")
                    proc.kill()
                    await proc.wait()

            for task in (stdout_task, stderr_task):
                if task and not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

        current = list_files(output_dir)

        if not current:
            self.logger.warning("No SOI artifacts captured.")
            return

        ordered = sorted(current.items(), key=lambda kv: (kv[1].st_mtime, kv[0]))
        selected = [fname for fname, _ in ordered[: self.max_files]]
        selected_paths = [os.path.join(output_dir, fname) for fname in selected]

        final_stats = await wait_for_files_to_settle(
            selected_paths,
            settle_seconds=settle_seconds,
            max_wait=settle_max_wait,
            poll=settle_poll,
            logger=self.logger,
        )

        manifest_path = self._write_manifest(
            output_dir=output_dir,
            selected=selected,
            final_stats=final_stats,
            stop_reason=stop_reason,
        )

        artifact_ids = self._register_artifacts(
            output_dir=output_dir,
            selected=selected,
            final_stats=final_stats,
            manifest_path=manifest_path,
            stop_reason=stop_reason,
        )

        self.logger.info(
            f"Promote-to-SOI complete: files={len(selected)}, "
            f"artifact_ids={artifact_ids}, stop_reason={stop_reason}"
        )

        await self._emit_alert(
            selected=selected,
            artifact_ids=artifact_ids,
            stop_reason=stop_reason,
        )

    def _write_manifest(
        self,
        *,
        output_dir: str,
        selected: List[str],
        final_stats: Dict[str, os.stat_result],
        stop_reason: str,
    ) -> str:
        files = []

        for fname in selected:
            full_path = os.path.join(output_dir, fname)
            st = final_stats.get(full_path)

            if st is None:
                try:
                    st = os.stat(full_path)
                except FileNotFoundError:
                    self.logger.warning(f"Final artifact missing unexpectedly: {full_path}")
                    continue

            files.append(
                {
                    "filename": fname,
                    "path": full_path,
                    "size_bytes": int(st.st_size),
                    "mtime": float(st.st_mtime),
                }
            )

        manifest = {
            "role": "promote_to_soi_v1",
            "operation_id": self.operation_id,
            "opid": self.opid,
            "node_uid": self.node_uid,
            "source_id": self.source_id,
            "description": self.description,
            "frequency_mhz": self.frequency_mhz,
            "sample_rate": self.sample_rate,
            "threshold": self.threshold,
            "decay": self.decay,
            "max_files": self.max_files,
            "rx_channel": self.rx_channel,
            "antenna": self.antenna,
            "gain": self.gain,
            "stop_reason": stop_reason,
            "files": files,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        manifest_path = os.path.join(output_dir, "promote_to_soi_manifest.json")

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return manifest_path

    def _register_artifacts(
        self,
        *,
        output_dir: str,
        selected: List[str],
        final_stats: Dict[str, os.stat_result],
        manifest_path: str,
        stop_reason: str,
    ) -> List[str]:
        """
        Register the complete Promote-to-SOI capture as one logical artifact.
        """
        if not self.artifact_manager:
            self.logger.warning(
                "No artifact_manager available; SOI files were not registered."
            )
            return []

        artifact_files: List[str] = []
        file_metadata: Dict[str, Dict[str, Any]] = {}

        for fname in selected:
            full_path = os.path.join(output_dir, fname)

            try:
                stat_result = final_stats.get(full_path) or os.stat(full_path)
            except FileNotFoundError:
                self.logger.warning(
                    "Skipping missing SOI capture file: %s",
                    full_path,
                )
                continue

            artifact_files.append(full_path)
            file_metadata[full_path] = {
                "role": "iq_burst",
                "content_type": "application/octet-stream",
                "frequency_mhz": self.frequency_mhz,
                "sample_rate": self.sample_rate,
                "data_type": "Complex Float 32",
                "captured_size": int(stat_result.st_size),
                "captured_mtime": float(stat_result.st_mtime),
            }

        if manifest_path and os.path.isfile(manifest_path):
            artifact_files.append(manifest_path)
            file_metadata[manifest_path] = {
                "role": "operation_metadata",
                "content_type": "application/json",
            }

        artifact_files = list(dict.fromkeys(artifact_files))

        if not artifact_files:
            return []

        relations = []

        if self.soi_id:
            relations.append(
                (
                    "soi",
                    self.soi_id,
                    "source_capture",
                )
            )

        metadata = {
            "role": "promote_to_soi_capture_v2",
            "operation_id": self.operation_id,
            "opid": self.opid,
            "node_uid": self.node_uid,
            "source_id": self.source_id,
            "description": self.description,
            "frequency_mhz": self.frequency_mhz,
            "sample_rate": self.sample_rate,
            "threshold": self.threshold,
            "decay": self.decay,
            "rx_channel": self.rx_channel,
            "antenna": self.antenna,
            "gain": self.gain,
            "stop_reason": stop_reason,
            "captured_file_count": len(selected),
            "manifest_name": os.path.basename(manifest_path) if manifest_path else "",
            "created_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(),
            ),
        }

        artifact_id = self.artifact_manager.create_artifact(
            source_id=self.source_id,
            operation_id=self.operation_id,
            files=artifact_files,
            name=self.description or "Promote to SOI Capture",
            artifact_type="soi_capture",
            metadata=metadata,
            relations=relations,
            file_metadata=file_metadata,
        )

        self.logger.info(
            "Registered Promote-to-SOI artifact: artifact_id=%s files=%s",
            artifact_id,
            len(artifact_files),
        )

        return [str(artifact_id)]

    async def _emit_alert(
        self,
        *,
        selected: List[str],
        artifact_ids: List[str],
        stop_reason: str,
    ) -> None:
        if not self.alert_callback:
            return

        payload = {
            "type": "promote_to_soi",
            "kind": "alert",
            "node_uid": self.node_uid,
            "source_id": self.source_id,
            "operation_id": self.operation_id,
            "opid": self.opid,
            "frequency_mhz": self.frequency_mhz,
            "file_count": len(selected),
            "files": selected,
            "artifact_ids": artifact_ids,
            "stop_reason": stop_reason,
            "description": self.description,
        }

        try:
            await asyncio.wait_for(
                self.alert_callback(
                    self.node_uid,
                    self.opid,
                    json.dumps(payload),
                    self.logger,
                ),
                timeout=2.0,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("alert_callback failed for promote_to_soi")

    @staticmethod
    def _float(value: Any, default: float) -> float:
        try:
            return float(value)
        except Exception:
            return float(default)

    @staticmethod
    def _int(value: Any, default: int) -> int:
        try:
            return int(float(value))
        except Exception:
            return int(default)


if __name__ == "__main__":
    async def _main():
        logging.basicConfig(level=logging.INFO)
        op = OperationMain(
            node_uid="test-node",
            logger=logging.getLogger("promote_to_soi_test"),
            frequency_mhz=311.0,
        )
        await op.run()

    asyncio.run(_main())