import asyncio
import threading

import serial

from .base import BaseListeningPost


class SerialPortListeningPost(BaseListeningPost):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.port = str(self.parameters.get("serial_port", "/dev/ttyUSB0") or "/dev/ttyUSB0")
        self.baud_rate = int(self.parameters.get("baud_rate", 9600))
        self.serial_connection = None
        self.read_thread = None

    async def start(self):
        if self.running:
            return

        self.serial_connection = serial.Serial(
            self.port,
            self.baud_rate,
            timeout=1,
        )
        self.running = True
        self.read_thread = threading.Thread(
            target=self._read_loop,
            daemon=True,
            name=f"ListeningPost-{self.name}",
        )
        self.read_thread.start()

    async def stop(self):
        self.running = False

        if self.serial_connection is not None:
            try:
                if self.serial_connection.is_open:
                    self.serial_connection.close()
            except Exception:
                pass
            self.serial_connection = None

        if self.read_thread is not None and self.read_thread.is_alive():
            await self.loop.run_in_executor(
                None,
                lambda: self.read_thread.join(timeout=2.0),
            )
        self.read_thread = None

    def _read_loop(self):
        try:
            while self.running:
                connection = self.serial_connection
                if connection is None or not connection.is_open:
                    break

                raw = connection.readline()
                if not raw:
                    continue

                message = raw.decode("utf-8", errors="replace").strip()
                if message:
                    self.emit_message_threadsafe(
                        message,
                        source=self.port,
                        transport="Serial Port",
                    )
        except Exception as exc:
            if self.running:
                self.running = False
                self.report_activity_threadsafe(
                    "ERROR",
                    f"Serial listener stopped: {exc}",
                )
