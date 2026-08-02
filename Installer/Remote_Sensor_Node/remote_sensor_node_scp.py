"""Human-readable progress reporting for AsyncSSH SCP transfers."""

import os
from pathlib import PurePath
import sys
from typing import Any, TextIO


class ScpProgressReporter:
    """Render compact terminal updates or throttled log milestones."""

    def __init__(self, stream: TextIO | None = None):
        self.stream = stream if stream is not None else sys.stdout
        self.interactive = bool(self.stream.isatty())
        self.current_file = ""
        self.last_marker = -1
        self.line_open = False

    def __call__(
        self,
        source: bytes,
        _destination: bytes,
        copied: int,
        total: int,
    ) -> None:
        filename = _display_name(source)
        percent = _completion_percent(copied, total)
        marker = percent if self.interactive else percent // 10
        completed = total <= 0 or copied >= total
        if not self._should_report(filename, marker, completed):
            return

        self.current_file = filename
        self.last_marker = marker
        self._write(filename, copied, total, percent, completed)

    def finish(self) -> None:
        """End an incomplete interactive line after a failed transfer."""
        if self.line_open:
            print(file=self.stream, flush=True)
            self.line_open = False

    def _should_report(
        self,
        filename: str,
        marker: int,
        completed: bool,
    ) -> bool:
        return (
            filename != self.current_file
            or marker != self.last_marker
            or completed
        )

    def _write(
        self,
        filename: str,
        copied: int,
        total: int,
        percent: int,
        completed: bool,
    ) -> None:
        sizes = f"{_format_bytes(copied)} / {_format_bytes(total)}"
        if self.interactive:
            end = "\n" if completed else ""
            print(
                f"\r    SCP {filename}: {percent:3d}% ({sizes})   ",
                end=end,
                file=self.stream,
                flush=True,
            )
            self.line_open = not completed
        else:
            print(
                f"[*] SCP {filename}: {percent}% ({sizes})",
                file=self.stream,
                flush=True,
            )


async def scp_with_progress(
    asyncssh: Any,
    source: str,
    destination: Any,
    stream: TextIO | None = None,
) -> None:
    """Copy one file and always leave terminal output on a complete line."""
    progress = ScpProgressReporter(stream)
    try:
        await asyncssh.scp(
            source,
            destination,
            progress_handler=progress,
        )
    finally:
        progress.finish()


def _display_name(path: bytes) -> str:
    decoded = os.fsdecode(path)
    return PurePath(decoded).name or decoded


def _completion_percent(copied: int, total: int) -> int:
    if total <= 0:
        return 100
    return max(0, min(100, copied * 100 // total))


def _format_bytes(value: int) -> str:
    amount = float(max(0, value))
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            precision = 0 if unit == "B" else 1
            return f"{amount:.{precision}f} {unit}"
        amount /= 1024
    raise AssertionError("unreachable")
