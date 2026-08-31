import asyncio
import os
from fnmatch import fnmatch

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .base import BaseListeningPost


NEW_FILE_QUIET_SECONDS = 0.5


class _FilesystemHandler(FileSystemEventHandler):
    def __init__(self, post):
        super().__init__()
        self.post = post
        self.file_positions = {}
        self.new_files = set()

    def _queue_new_file(self, path):
        path = os.path.abspath(path)
        if not fnmatch(os.path.basename(path), self.post.file_pattern):
            return

        self.new_files.add(path)
        self.post.schedule_new_file_processing(path)

    def on_created(self, event):
        if event.is_directory or self.post.mode != "New Files":
            return
        self._queue_new_file(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return

        path = os.path.abspath(event.src_path)

        if self.post.mode == "New Files":
            if path in self.new_files:
                self.post.schedule_new_file_processing(path)
            return

        if os.path.abspath(self.post.filepath) == path:
            self.post.schedule_file_processing(path, read_all=False)

    def on_moved(self, event):
        if event.is_directory or self.post.mode != "New Files":
            return
        self._queue_new_file(event.dest_path)


class FilesystemListeningPost(BaseListeningPost):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mode = str(self.parameters.get("mode", "New Files") or "New Files")
        self.folder = str(self.parameters.get("folder", "") or "")
        self.file_pattern = str(self.parameters.get("file_pattern", "*.txt") or "*.txt")
        self.filepath = str(self.parameters.get("filepath", "") or "")
        self.observer = None
        self.handler = None
        self.pending_new_file_tasks = {}

        if self.mode == "File Changes":
            self.directory_path = os.path.dirname(self.filepath) or "."
        else:
            self.directory_path = self.folder

    async def start(self):
        if self.running:
            return

        if not os.path.isdir(self.directory_path):
            raise RuntimeError(f"Filesystem directory does not exist: {self.directory_path}")

        self.handler = _FilesystemHandler(self)
        if self.mode == "File Changes" and os.path.isfile(self.filepath):
            try:
                self.handler.file_positions[self.filepath] = os.path.getsize(self.filepath)
            except OSError:
                self.handler.file_positions[self.filepath] = 0

        self.observer = Observer()
        self.observer.schedule(
            self.handler,
            self.directory_path,
            recursive=False,
        )
        self.observer.start()
        self.running = True

    async def stop(self):
        self.running = False

        for task in list(self.pending_new_file_tasks.values()):
            task.cancel()
        self.pending_new_file_tasks.clear()

        if self.observer is not None:
            observer = self.observer
            self.observer = None
            observer.stop()
            await self.loop.run_in_executor(
                None,
                lambda: observer.join(timeout=3.0),
            )

        self.handler = None

    def schedule_new_file_processing(self, path):
        self.loop.call_soon_threadsafe(
            self._schedule_new_file_processing,
            os.path.abspath(path),
        )

    def _schedule_new_file_processing(self, path):
        if not self.running:
            return

        existing = self.pending_new_file_tasks.pop(path, None)
        if existing is not None:
            existing.cancel()

        self.pending_new_file_tasks[path] = asyncio.create_task(
            self._process_new_file_after_quiet(path)
        )

    async def _process_new_file_after_quiet(self, path):
        task = asyncio.current_task()

        try:
            await asyncio.sleep(NEW_FILE_QUIET_SECONDS)
            await self._process_file(path, read_all=True)

            if self.handler is not None:
                self.handler.new_files.discard(path)
        except asyncio.CancelledError:
            raise
        finally:
            if self.pending_new_file_tasks.get(path) is task:
                self.pending_new_file_tasks.pop(path, None)

    def schedule_file_processing(self, path, read_all):
        asyncio.run_coroutine_threadsafe(
            self._process_file(path, read_all),
            self.loop,
        )

    async def _process_file(self, path, read_all):
        try:
            if self.handler is None:
                return

            previous_position = self.handler.file_positions.get(path, 0)
            try:
                current_size = os.path.getsize(path)
                if previous_position > current_size:
                    previous_position = 0
            except OSError:
                pass

            with open(path, "r", encoding="utf-8", errors="replace") as stream:
                if read_all:
                    stream.seek(0)
                    lines = stream.readlines()
                    self.handler.file_positions[path] = stream.tell()
                else:
                    stream.seek(previous_position)
                    lines = stream.readlines()
                    self.handler.file_positions[path] = stream.tell()

            for line in lines:
                message = line.strip()
                if message:
                    await self.emit_message(
                        message,
                        source=path,
                        transport="Filesystem",
                    )

        except Exception as exc:
            await self.report_activity(
                "ERROR",
                f"Could not process {path}: {exc}",
            )