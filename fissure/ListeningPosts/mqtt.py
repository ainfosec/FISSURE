import asyncio

import paho.mqtt.client as mqtt

from .base import BaseListeningPost


class MQTTListeningPost(BaseListeningPost):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.broker_address = str(self.parameters.get("broker_address", "localhost") or "localhost")
        self.port = int(self.parameters.get("port", 1883))
        self.topic = str(self.parameters.get("topic", "fissure/alerts") or "fissure/alerts")
        self.username = str(self.parameters.get("username", "") or "")
        self.password = str(self.parameters.get("password", "") or "")
        self.client = None

    async def start(self):
        if self.running:
            return

        self.client = mqtt.Client()
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect

        if self.username:
            self.client.username_pw_set(
                self.username,
                self.password or None,
            )

        result = await self.loop.run_in_executor(
            None,
            lambda: self.client.connect(self.broker_address, self.port, 60),
        )
        if result != mqtt.MQTT_ERR_SUCCESS:
            self.client = None
            raise RuntimeError(f"MQTT connect failed with code {result}.")

        self.running = True

        try:
            self.client.loop_start()
        except Exception:
            self.running = False
            self.client = None
            raise

    async def stop(self):
        self.running = False

        if self.client is not None:
            client = self.client
            self.client = None
            try:
                client.loop_stop()
            except Exception:
                pass
            try:
                await self.loop.run_in_executor(None, client.disconnect)
            except Exception:
                pass

    def _on_connect(self, client, userdata, flags, rc, *args):
        if int(rc) == 0:
            self.running = True
            client.subscribe(self.topic)
            self.report_activity_threadsafe(
                "INFO",
                f"Connected to MQTT broker and subscribed to {self.topic}.",
            )
        else:
            self.running = False
            self.report_activity_threadsafe(
                "ERROR",
                f"MQTT broker rejected connection with code {rc}.",
            )

    def _on_message(self, client, userdata, msg):
        message = msg.payload.decode("utf-8", errors="replace").strip()
        if message:
            self.emit_message_threadsafe(
                message,
                source=f"{self.broker_address}:{self.port}",
                transport="MQTT",
                topic=str(msg.topic or self.topic),
            )

    def _on_disconnect(self, client, userdata, rc, *args):
        if self.running and int(rc) != 0:
            self.running = False
            self.report_activity_threadsafe(
                "ERROR",
                f"MQTT connection lost with code {rc}.",
            )