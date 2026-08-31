import asyncio
from collections import deque

import aiohttp

from .base import BaseListeningPost


MAX_SEEN_MESSAGES = 1000


class WebsitePollerListeningPost(BaseListeningPost):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.url = str(self.parameters.get("url", "") or "")
        self.check_interval = int(self.parameters.get("check_interval", 60))
        self.session = None
        self.task = None
        self.seen_messages = deque()
        self.seen_message_set = set()

    async def start(self):
        if self.running:
            return

        self.seen_messages.clear()
        self.seen_message_set.clear()
        self.session = aiohttp.ClientSession()
        self.running = True
        self.task = asyncio.create_task(self._poll())

    async def stop(self):
        self.running = False

        if self.task is not None:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
            self.task = None

        if self.session is not None:
            await self.session.close()
            self.session = None

    def _remember_message(self, message):
        if message in self.seen_message_set:
            return False

        if len(self.seen_messages) >= MAX_SEEN_MESSAGES:
            oldest = self.seen_messages.popleft()
            self.seen_message_set.discard(oldest)

        self.seen_messages.append(message)
        self.seen_message_set.add(message)
        return True

    async def _poll(self):
        try:
            while self.running:
                try:
                    async with self.session.get(self.url) as response:
                        if response.status != 200:
                            await self.report_activity(
                                "ERROR",
                                f"Website poll returned HTTP {response.status}.",
                            )
                        else:
                            content = await response.text()
                            messages = [
                                line.strip()
                                for line in content.splitlines()
                                if line.strip()
                            ][-MAX_SEEN_MESSAGES:]

                            for message in messages:
                                if not self._remember_message(message):
                                    continue

                                await self.emit_message(
                                    message,
                                    source=self.url,
                                    transport="Website Poller",
                                )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    await self.report_activity(
                        "ERROR",
                        f"Website poll failed: {exc}",
                    )

                await asyncio.sleep(self.check_interval)
        except asyncio.CancelledError:
            raise