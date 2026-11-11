"""External health checks for an Apptainer-managed remote Sensor Node."""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import time
from typing import Any, Protocol
from uuid import UUID

import yaml

from remote_sensor_node_privilege import PrivilegeContext, run_root_command


MAX_LOG_TAIL_BYTES = 512 * 1024
CLOCK_TOLERANCE_SECONDS = 2
LOG_TIMESTAMP_FORMAT = "%m/%d/%Y %I:%M:%S %p"


class HealthCheckError(RuntimeError):
    """Raised when the deployed service does not become ready."""


class HealthOptions(Protocol):
    health_timeout: int
    source_dir: Path
    remote_dir: str
    service_name: str


@dataclass(frozen=True)
class ServiceState:
    active: str
    substate: str
    main_pid: int

    @property
    def stopped(self) -> bool:
        return self.active in {"failed", "inactive", "not-found"}


async def wait_for_sensor_node_health(
    connection: Any,
    options: HealthOptions,
    privilege: PrivilegeContext,
    require_heartbeat: bool,
    minimum_heartbeat_epoch: float | None = None,
) -> None:
    """Wait for startup and optionally require an IP-node heartbeat."""
    minimum_epoch = minimum_heartbeat_epoch
    if minimum_epoch is None:
        minimum_epoch = time.time() - options.health_timeout
    probe = SensorNodeHealthProbe(
        connection,
        options,
        privilege,
        require_heartbeat,
        minimum_epoch,
    )
    await probe.wait()


class SensorNodeHealthProbe:
    """Read readiness from systemd and deployment-owned persistent files."""

    def __init__(
        self,
        connection: Any,
        options: HealthOptions,
        privilege: PrivilegeContext,
        require_heartbeat: bool,
        minimum_heartbeat_epoch: float,
    ) -> None:
        self.connection = connection
        self.options = options
        self.privilege = privilege
        self.require_heartbeat = require_heartbeat
        self.minimum_heartbeat_epoch = minimum_heartbeat_epoch

    async def wait(self) -> None:
        network_type = ""
        if self.require_heartbeat:
            network_type = await self._read_network_type()
        deadline = time.monotonic() + self.options.health_timeout
        last_state = ServiceState("unknown", "unknown", 0)
        while time.monotonic() < deadline:
            last_state = await self._read_service_state()
            if await self._is_ready(last_state, network_type):
                return
            if last_state.stopped:
                break
            await asyncio.sleep(2)
        await self._print_journal()
        raise HealthCheckError(
            "Sensor node failed its health check "
            f"(state={last_state.active}/{last_state.substate})"
        )

    async def _is_ready(self, state: ServiceState, network_type: str) -> bool:
        if state.active != "active" or state.main_pid <= 0:
            return False
        if not await self._is_sensor_process(state.main_pid):
            return False
        node_uuid = await self._read_node_uuid()
        if not node_uuid:
            return False
        if self.require_heartbeat and network_type == "IP":
            ready = hub_received_recent_heartbeat(
                self.options.source_dir / "Logs/event.log",
                node_uuid,
                self.minimum_heartbeat_epoch,
            )
            if not ready:
                return False
        has_heartbeat = self.require_heartbeat and network_type == "IP"
        status = "healthy" if has_heartbeat else "started"
        print(f"[✓] Sensor node {status}: pid={state.main_pid}, uuid={node_uuid}")
        return True

    async def _read_network_type(self) -> str:
        config_path = f"{self.options.remote_dir}/current/default.yaml"
        result = await run_root_command(
            self.connection,
            ["cat", config_path],
            self.privilege,
            check=False,
        )
        if result.exit_status:
            raise HealthCheckError(f"Unable to read remote config: {config_path}")
        try:
            config = yaml.safe_load(result.stdout)
            network_type = config["Sensor Node"]["network_type"]
        except (KeyError, TypeError, yaml.YAMLError) as exc:
            raise HealthCheckError("Remote Sensor Node config is invalid") from exc
        return str(network_type).strip()

    async def _read_service_state(self) -> ServiceState:
        result = await run_root_command(
            self.connection,
            [
                "systemctl",
                "show",
                self.options.service_name + ".service",
                "--property=ActiveState",
                "--property=SubState",
                "--property=MainPID",
            ],
            self.privilege,
            check=False,
        )
        if result.exit_status:
            return ServiceState("not-found", "not-found", 0)
        properties = _parse_properties(result.stdout)
        try:
            pid = int(properties.get("MainPID", "0"))
        except ValueError:
            pid = 0
        return ServiceState(
            properties.get("ActiveState", "unknown"),
            properties.get("SubState", "unknown"),
            pid,
        )

    async def _is_sensor_process(self, pid: int) -> bool:
        result = await run_root_command(
            self.connection,
            ["ps", "-p", str(pid), "-o", "args="],
            self.privilege,
            check=False,
        )
        command = result.stdout.strip()
        return not result.exit_status and bool(command) and (
            "SensorNode.py" in command or "fissure-sensor-node.sif" in command
        )

    async def _read_node_uuid(self) -> str:
        uuid_path = (
            f"{self.options.remote_dir}/state/home/.fissure/"
            "sensor_node_uuid.uuid"
        )
        result = await run_root_command(
            self.connection,
            ["cat", uuid_path],
            self.privilege,
            check=False,
        )
        value = result.stdout.strip()
        if result.exit_status:
            return ""
        try:
            return str(UUID(value))
        except ValueError:
            return ""

    async def _print_journal(self) -> None:
        journal = await run_root_command(
            self.connection,
            [
                "journalctl",
                "-u",
                self.options.service_name + ".service",
                "-n",
                "80",
                "--no-pager",
            ],
            self.privilege,
            check=False,
        )
        print(journal.stdout, end="")


def hub_received_recent_heartbeat(
    log_path: Path,
    node_uuid: str,
    minimum_epoch: float,
) -> bool:
    """Check a bounded log tail for a heartbeat received after startup."""
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


def _parse_properties(output: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for line in output.splitlines():
        name, separator, value = line.partition("=")
        if separator:
            properties[name] = value
    return properties


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
