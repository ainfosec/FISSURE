import asyncio
import zmq
import zmq.asyncio

from .base import BaseListeningPost


class ZMQSubscriberListeningPost(BaseListeningPost):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ip_address = str(self.parameters.get("ip_address", "localhost") or "localhost")
        self.port = str(self.parameters.get("port", "55555") or "55555")
        self.topic_filter = str(self.parameters.get("topic_filter", "alerts") or "")
        self.url = f"tcp://{self.ip_address}:{self.port}"
        self.context = None
        self.socket = None
        self.task = None

    async def start(self):
        if self.running:
            return

        self.context = zmq.asyncio.Context()
        self.socket = self.context.socket(zmq.SUB)
        self.socket.setsockopt_string(zmq.SUBSCRIBE, self.topic_filter)
        self.socket.connect(self.url)
        self.running = True
        self.task = asyncio.create_task(self._listen())

    async def stop(self):
        self.running = False

        if self.task is not None:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
            self.task = None

        if self.socket is not None:
            try:
                self.socket.disconnect(self.url)
            except Exception:
                pass
            self.socket.close(linger=0)
            self.socket = None

        if self.context is not None:
            self.context.term()
            self.context = None

    async def _listen(self):
        try:
            while self.running and self.socket is not None:
                raw = await self.socket.recv()
                message = raw.decode("utf-8", errors="replace").strip()
                payload = message

                if self.topic_filter:
                    prefix = self.topic_filter + " "
                    if message.startswith(prefix):
                        payload = message[len(prefix):].strip()

                if payload:
                    await self.emit_message(
                        payload,
                        source=self.url,
                        transport="ZMQ SUB",
                        topic=self.topic_filter,
                    )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if self.running:
                self.running = False
                await self.report_activity(
                    "ERROR",
                    f"ZMQ SUB listener stopped: {exc}",
                )
