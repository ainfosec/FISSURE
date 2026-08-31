from meshtastic.serial_interface import SerialInterface
from pubsub import pub

from .base import BaseListeningPost


class MeshtasticListeningPost(BaseListeningPost):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.serial_port = str(self.parameters.get("serial_port", "/dev/ttyUSB0") or "/dev/ttyUSB0")
        self.interface = None
        self.subscribed = False

    async def start(self):
        if self.running:
            return

        self.interface = await self.loop.run_in_executor(
            None,
            lambda: SerialInterface(self.serial_port),
        )
        pub.subscribe(self._on_message, "meshtastic.receive.text")
        self.subscribed = True
        self.running = True

    async def stop(self):
        self.running = False

        if self.subscribed:
            try:
                pub.unsubscribe(self._on_message, "meshtastic.receive.text")
            except Exception:
                pass
            self.subscribed = False

        if self.interface is not None:
            interface = self.interface
            self.interface = None
            try:
                await self.loop.run_in_executor(None, interface.close)
            except Exception:
                pass

    def _on_message(self, packet, interface=None):
        if not self.running:
            return

        if interface is not None and self.interface is not None and interface is not self.interface:
            return

        raw_text = packet.get("decoded", {}).get("text", "")
        if raw_text:
            self.emit_message_threadsafe(
                raw_text,
                source=self.serial_port,
                transport="Meshtastic",
            )