"""End-to-end heartbeat validation for remote Sensor Node deployment."""

from datetime import datetime
from pathlib import Path
from typing import Any, Protocol


MAX_LOG_TAIL_BYTES = 512 * 1024
CLOCK_TOLERANCE_SECONDS = 10
LOG_TIMESTAMP_FORMAT = "%m/%d/%Y %I:%M:%S %p"


class HealthOptions(Protocol):
    startup_only: bool
    health_timeout: int
    source_dir: Path


def heartbeat_is_ready(
    snapshot: dict[str, Any],
    remote_now: int,
    options: HealthOptions,
) -> bool:
    """Accept an inbound heartbeat or a fresh receipt recorded by HIPRFISR."""
    if options.startup_only or snapshot.get("network_type") != "IP":
        return True
    try:
        updated_at = float(snapshot.get("updated_at_epoch", 0))
        age = remote_now - updated_at
    except (TypeError, ValueError):
        return False
    if bool(snapshot.get("hiprfisr_connected")) and 0 <= age <= options.health_timeout:
        return True
    return hub_received_recent_heartbeat(
        options.source_dir / "Logs/event.log",
        str(snapshot.get("node_uuid", "")),
        updated_at,
    )


def hub_received_recent_heartbeat(
    log_path: Path,
    node_uuid: str,
    minimum_epoch: float,
) -> bool:
    """Check a bounded log tail for a heartbeat received after node startup."""
    if not node_uuid or minimum_epoch <= 0:
        return False
    marker = f"received sensor-node-{node_uuid}"
    for line in reversed(_read_log_tail(log_path).splitlines()):
        if marker not in line:
            continue
        timestamp = _line_timestamp(line)
        return bool(
            timestamp is not None
            and timestamp + CLOCK_TOLERANCE_SECONDS >= minimum_epoch
        )
    return False


def _read_log_tail(log_path: Path) -> str:
    try:
        with log_path.open("rb") as log_file:
            log_file.seek(0, 2)
            offset = max(0, log_file.tell() - MAX_LOG_TAIL_BYTES)
            log_file.seek(offset)
            content = log_file.read().decode(errors="replace")
    except OSError:
        return ""
    if offset:
        _, separator, content = content.partition("\n")
        return content if separator else ""
    return content


def _line_timestamp(line: str) -> float | None:
    timestamp_text, separator, _message = line.partition(" - ")
    if not separator:
        return None
    try:
        timestamp = datetime.strptime(timestamp_text, LOG_TIMESTAMP_FORMAT)
    except ValueError:
        return None
    return timestamp.astimezone().timestamp()
