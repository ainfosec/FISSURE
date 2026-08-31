import asyncio
from typing import Any, Awaitable, Callable, Dict, Optional


MessageCallback = Callable[[str, Dict[str, Any]], Awaitable[None]]
ActivityCallback = Callable[[str, str], Awaitable[None]]


class BaseListeningPost:
    """Common runtime interface for HIPRFISR-hosted Listening Posts."""

    def __init__(
        self,
        component,
        post_id: str,
        name: str,
        parameters: dict,
        loop,
        message_callback: MessageCallback,
        activity_callback: ActivityCallback,
    ):
        self.component = component
        self.post_id = post_id
        self.name = name
        self.parameters = dict(parameters or {})
        self.loop = loop
        self.message_callback = message_callback
        self.activity_callback = activity_callback
        self.running = False

    async def start(self):
        raise NotImplementedError

    async def stop(self):
        raise NotImplementedError

    def is_running(self) -> bool:
        return bool(self.running)

    async def emit_message(self, message: str, **metadata):
        await self.message_callback(
            str(message or ""),
            dict(metadata or {}),
        )

    def emit_message_threadsafe(self, message: str, **metadata):
        asyncio.run_coroutine_threadsafe(
            self.emit_message(message, **metadata),
            self.loop,
        )

    async def report_activity(self, level: str, message: str):
        await self.activity_callback(
            str(level or "INFO").upper(),
            str(message or ""),
        )

    def report_activity_threadsafe(self, level: str, message: str):
        asyncio.run_coroutine_threadsafe(
            self.report_activity(level, message),
            self.loop,
        )
