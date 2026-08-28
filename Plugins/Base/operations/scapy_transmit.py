#!/usr/bin/env python3
"""Scapy packet transmission operation for the Base plugin."""

import asyncio
from datetime import datetime, timezone
import inspect
import logging
import os
import sys
import time
import uuid
from typing import Callable, Union


PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from fissure.utils.plugins.operations import Operation
from fissure.utils import scapy_compat


SCAPY_METHOD_AUTO = "Auto"
SCAPY_METHOD_SENDP = "sendp (Layer 2)"
SCAPY_METHOD_SEND = "send (Layer 3)"


class OperationMain(Operation):
    """Transmit one serialized Scapy packet through a privileged helper."""

    def __init__(
        self,
        operation_id: str = "",
        requester: str = "",
        packet_hex: str = "",
        root_layer: str = "Ether",
        interface: str = "",
        method: str = SCAPY_METHOD_AUTO,
        interval: Union[str, float] = 0.1,
        count: Union[str, int] = 1,
        loop: Union[str, bool] = False,
        description: str = "Scapy packet transmission",
        progress_callback: Union[Callable, None] = None,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        status_callback: Union[Callable, None] = None,
        target_callback: Union[Callable, None] = None,
        soi_callback: Union[Callable, None] = None,
        artifact_manager=None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            status_callback=status_callback,
            target_callback=target_callback,
            soi_callback=soi_callback,
            artifact_manager=artifact_manager,
        )

        self.operation_id = str(operation_id or self.opid or uuid.uuid4())
        self.opid = self.operation_id
        self.requester = str(requester or "").strip()
        self.packet_hex = str(packet_hex or "").strip()
        self.root_layer = str(root_layer or "Ether").strip()
        self.interface = str(interface or "").strip()
        self.method = str(method or SCAPY_METHOD_AUTO).strip()
        self.interval = float(interval)
        self.count = int(float(count))
        self.loop = self._as_bool(loop)
        self.description = str(description or "Scapy packet transmission").strip()
        self.progress_callback = progress_callback

        self.resolved_method = ""
        self.packets_sent = 0
        self.started = ""
        self._last_progress_time = 0.0
        self._process = None
        self._stop_file = os.path.join("/tmp", f"fissure-scapy-{self.operation_id}.stop")

    @staticmethod
    def get_resources() -> dict:
        return {}

    @staticmethod
    def _as_bool(value) -> bool:
        if isinstance(value, bool):
            return value

        return str(value or "").strip().lower() in {"1", "true", "yes", "on"}

    def _set_rate_text(self) -> str:
        if self.interval <= 0:
            return "Maximum"

        return f"{1.0 / self.interval:.3f} pkt/s"

    def _validate(self) -> None:
        if not scapy_compat.is_available():
            detail = str(scapy_compat.import_error() or "").strip()
            raise RuntimeError("Scapy is unavailable" + (f": {detail}" if detail else "."))

        if not self.interface:
            raise ValueError("No interface selected.")

        interface_names = {
            str(row.get("name", "") or "").strip()
            for row in scapy_compat.get_interfaces()
            if isinstance(row, dict)
        }

        if self.interface not in interface_names:
            raise ValueError(f"Interface '{self.interface}' is not available on this Sensor Node.")

        if self.method not in {SCAPY_METHOD_AUTO, SCAPY_METHOD_SENDP, SCAPY_METHOD_SEND}:
            raise ValueError(f"Unsupported Scapy method: {self.method}")

        if self.interval < 0:
            raise ValueError("Interval cannot be negative.")

        if not self.loop and self.count < 1:
            raise ValueError("Packet count must be at least 1.")

        if not self.root_layer:
            raise ValueError("Root Layer is required.")

        layer_class = scapy_compat.get_layer_class(self.root_layer)
        if layer_class is None:
            raise ValueError(f"Scapy layer '{self.root_layer}' is unavailable on this Sensor Node.")

        packet_hex = self.packet_hex
        if packet_hex.lower().startswith("0x"):
            packet_hex = packet_hex[2:]

        try:
            packet_bytes = bytes.fromhex(packet_hex)
        except ValueError as exc:
            raise ValueError("Packet Hex is not valid hexadecimal.") from exc

        if not packet_bytes:
            raise ValueError("Packet is empty.")

        try:
            layer_class(packet_bytes)
        except Exception as exc:
            raise ValueError(f"Could not rebuild packet as {self.root_layer}: {exc}") from exc

        if self.method == SCAPY_METHOD_AUTO:
            self.resolved_method = SCAPY_METHOD_SEND if self.root_layer in {"IP", "IPv6"} else SCAPY_METHOD_SENDP
        else:
            self.resolved_method = self.method

    async def _emit_progress(self, state: str, message: str = "", force: bool = False) -> None:
        if not callable(self.progress_callback):
            return

        now = time.monotonic()
        if not force and state == "running" and (now - self._last_progress_time) < 0.25:
            return

        self._last_progress_time = now

        try:
            result = self.progress_callback(
                operation_id=self.operation_id,
                state=str(state or ""),
                message=str(message or ""),
                packets_sent=int(self.packets_sent),
                set_rate=self._set_rate_text(),
                started=self.started,
            )

            if inspect.isawaitable(result):
                await result

        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("Scapy progress callback failed.")

    def _request_helper_stop(self) -> None:
        try:
            with open(self._stop_file, "w", encoding="utf-8"):
                pass
        except Exception:
            self.logger.exception("Could not create Scapy helper stop file.")

    def _clear_stop_file(self) -> None:
        try:
            if os.path.exists(self._stop_file):
                os.remove(self._stop_file)
        except Exception:
            self.logger.exception("Could not remove Scapy helper stop file.")

    async def _launch_helper(self):
        helper_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "scapy_send.py")
        )

        if not os.path.isfile(helper_path):
            raise FileNotFoundError(f"Scapy helper not found: {helper_path}")

        command = [
            "sudo",
            "-n",
            "/usr/bin/python3",
            helper_path,
            "--packet-hex",
            self.packet_hex,
            "--root-layer",
            self.root_layer,
            "--interface",
            self.interface,
            "--method",
            self.resolved_method,
            "--interval",
            str(self.interval),
            "--count",
            str(self.count),
            "--stop-file",
            self._stop_file,
        ]

        if self.loop:
            command.append("--loop")

        return await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def _read_helper(self) -> None:
        helper_error = ""

        while True:
            if self._stop:
                self._request_helper_stop()

            try:
                raw_line = await asyncio.wait_for(self._process.stdout.readline(), timeout=0.10)
            except asyncio.TimeoutError:
                if self._process.returncode is not None:
                    break
                continue

            if not raw_line:
                if self._process.returncode is not None:
                    break

                await asyncio.sleep(0)
                continue

            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            kind, _, value = line.partition("\t")

            if kind == "READY":
                await self._emit_progress(
                    "started",
                    f"{self.resolved_method} on {self.interface}",
                    force=True,
                )
            elif kind == "SENT":
                try:
                    self.packets_sent = int(value)
                except ValueError:
                    self.packets_sent += 1

                await self._emit_progress("running", "Running")
            elif kind in {"STOPPED", "DONE"}:
                try:
                    self.packets_sent = int(value)
                except ValueError:
                    pass
            elif kind == "ERROR":
                helper_error = value or "Scapy helper failed."

        stderr_bytes = await self._process.stderr.read()
        stderr_text = stderr_bytes.decode("utf-8", errors="replace").strip()
        return_code = await self._process.wait()

        if return_code != 0:
            detail = helper_error or stderr_text or f"Scapy helper exited with code {return_code}."
            raise RuntimeError(detail)

    async def run(self) -> None:
        """Run Scapy packet transmission."""
        self._clear_stop_file()

        try:
            self._validate()
            self.started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            self.logger.info(
                "Starting Scapy transmission: "
                f"operation_id={self.operation_id}, "
                f"interface={self.interface}, "
                f"method={self.resolved_method}, "
                f"root_layer={self.root_layer}, "
                f"interval={self.interval}, "
                f"count={self.count}, "
                f"loop={self.loop}"
            )

            if self.status_callback:
                await self.status_callback("Running: Scapy Transmit")

            self._process = await self._launch_helper()
            await self._read_helper()

            if self._stop:
                await self._emit_progress("stopped", "Stopped", force=True)
            else:
                await self._emit_progress("completed", "Completed", force=True)

        except asyncio.CancelledError:
            self._request_helper_stop()
            self.logger.info("Scapy transmission cancelled.")
            raise

        except Exception as exc:
            self.logger.exception("Scapy transmission failed.")
            await self._emit_progress("error", str(exc), force=True)
            raise

        finally:
            self._request_helper_stop()

            if self._process is not None and self._process.returncode is None:
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    self.logger.warning("Scapy helper did not exit within the stop timeout.")

            self._clear_stop_file()

            if self.status_callback:
                try:
                    await self.status_callback("Idle")
                except Exception:
                    self.logger.exception(
                        "Scapy transmit status_callback failed while setting Idle."
                    )


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})
