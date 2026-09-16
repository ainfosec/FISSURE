#!/usr/bin/env python3
"""
Replay recorded CoT XML logs into a TAK server.

This tool replays Cursor-on-Target (CoT) events captured by the HIPRFISR
CoT logging system in FISSURE. It is primarily intended for debugging,
demonstrations, testing, and scenario playback.

Expected CoT Log Format
-----------------------
HIPRFISR logs each transmitted CoT message with a timestamp comment
followed by the XML event itself:

    <!-- logged_ts=2026-03-07T16:34:32.864417+00:00 -->
    <event ...>...</event>

The `logged_ts` timestamp represents when the message was originally
sent and is used to reproduce realistic timing during replay.

Replay Behavior
---------------
By default the tool will:

• Automatically locate the newest CoT logging session  
• Parse all `cot_*.xml` files in that session  
• Replay messages to the configured TAK server  
• Preserve the relative timing between messages  

Replay timing can be accelerated using the `--speed` argument.

Example:
    speed=1     → real-time playback  
    speed=10    → 10× faster  
    speed=1000  → as fast as allowed by min interval  

To prevent overwhelming the TAK server, the script enforces a minimum
delay between messages (`--min-interval`, default 0.05 seconds).

Time Refresh Behavior
---------------------
By default the script updates the following CoT fields before sending:

    time
    start
    stale

This ensures that replayed events appear **current** in TAK clients.

If you want the original timestamps preserved, use:

    --no-refresh-times

Session and File Selection
--------------------------
You can replay different sources:

Replay newest session automatically:

    python3 replay_cot_log.py

Replay a specific session directory:

    python3 replay_cot_log.py --session /home/user/FISSURE/Logs/CoT_Logs/2026-03-07_16-34-00

Replay a single CoT log file:

    python3 replay_cot_log.py --file cot_0001.xml

Speed Control
-------------
Adjust replay speed:

    python3 replay_cot_log.py --speed 10
    python3 replay_cot_log.py --speed 50

Limit maximum messages sent:

    python3 replay_cot_log.py --max-events 500

Prevent TAK flooding by increasing the send interval:

    python3 replay_cot_log.py --min-interval 0.1

TAK Server Configuration
------------------------
TAK connection settings are read from the FISSURE configuration file:

    /home/user/FISSURE/YAML/User Configs/default.yaml

The following values are used:

    tak.ip_addr
    tak.port
    tak.cert
    tak.key

These can be overridden using command-line arguments if needed.

TLS Behavior
------------
TLS verification is disabled by default to support local TAK servers
using self-signed certificates.

To enable strict TLS verification:

    python3 replay_cot_log.py --secure

If using a custom CA certificate:

    python3 replay_cot_log.py --secure --cafile ca.pem

Dry Run Mode
------------
The `--dry-run` option parses the logs and prints summary information
without connecting to TAK or sending any messages.

Example:

    python3 replay_cot_log.py --dry-run

This is useful for verifying:

• session discovery  
• event counts  
• replay ordering  

without generating TAK traffic.

Verbose Logging
---------------
Enable detailed debugging output:

    python3 replay_cot_log.py --verbose
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import copy
import logging
import re
import sys
import yaml
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Sequence, Tuple
import xml.etree.ElementTree as ET

import pytak


DEFAULT_CONFIG_PATH = Path("/home/user/FISSURE/YAML/User Configs/default.yaml")

LOG_PATTERN = re.compile(
    r"<!--\s*logged_ts=(?P<logged_ts>[^\s]+)\s*-->\s*(?P<event><event\b.*?</event>)",
    re.DOTALL,
)


@dataclass
class ReplayRecord:
    logged_ts: datetime
    event_elem: ET.Element
    source_path: Path
    index_in_file: int


def parse_args():
    p = argparse.ArgumentParser()

    p.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    p.add_argument("--session")
    p.add_argument("--file")
    p.add_argument("--base-dir")
    p.add_argument("--speed", type=float, default=1.0)
    p.add_argument("--min-interval", type=float, default=0.05)
    p.add_argument("--max-events", type=int)
    p.add_argument("--no-refresh-times", action="store_true")
    p.add_argument(
        "--dashboard",
        action="store_true",
        help="Mark replay events so HIPRFISR forwards them into the current Dashboard Tactical parser.",
    )

    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--cert")
    p.add_argument("--key")
    p.add_argument("--cafile")

    p.add_argument("--secure", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--verbose", action="store_true")

    return p.parse_args()


def setup_logger(verbose):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        force=True,
    )
    return logging.getLogger("replay_cot_log")


def install_asyncio_exception_filter(loop, logger):
    default_handler = loop.get_exception_handler()

    def handler(loop, context):
        exc = context.get("exception")
        msg = context.get("message", "")
        text = f"{msg} {exc}".lower()

        benign = [
            "fatal error on ssl transport",
            "bad file descriptor",
            "event loop is closed",
        ]

        if any(p in text for p in benign):
            logger.debug("Suppressed asyncio shutdown noise")
            return

        if default_handler:
            default_handler(loop, context)
        else:
            loop.default_exception_handler(context)

    loop.set_exception_handler(handler)


def load_yaml_config(path):
    path = Path(path).expanduser()
    if not path.exists():
        raise FileNotFoundError(path)

    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def parse_iso(ts):
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def format_cot_time(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def resolve_fissure_root(config_path):
    return Path(config_path).expanduser().resolve().parents[2]


def resolve_base_dir(cli_base, config, root):
    if cli_base:
        path = Path(cli_base)
    else:
        cot_cfg = config.get("cot_logging", {})
        path = Path(cot_cfg.get("cot_log_directory", "./Logs/CoT_Logs"))

    if not path.is_absolute():
        path = root / path

    return path.resolve()


def latest_session_dir(base_dir):
    sessions = [p for p in base_dir.iterdir() if p.is_dir()]
    sessions.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return sessions[0]


def resolve_input_paths(args, config, root):

    if args.file:
        p = Path(args.file).resolve()
        return None, [p]

    if args.session:
        session = Path(args.session)
    else:
        base = resolve_base_dir(args.base_dir, config, root)
        session = latest_session_dir(base)

    files = sorted(session.glob("cot_*.xml"))
    return session, files


def parse_records_from_file(path):

    text = path.read_text()

    records = []

    for idx, m in enumerate(LOG_PATTERN.finditer(text), start=1):
        ts = parse_iso(m.group("logged_ts"))
        xml = m.group("event")

        elem = ET.fromstring(xml)

        records.append(
            ReplayRecord(
                ts,
                elem,
                path,
                idx,
            )
        )

    return records


def load_records(paths, max_events):

    rec = []

    for p in paths:
        rec.extend(parse_records_from_file(p))

    rec.sort(key=lambda r: r.logged_ts)

    if max_events:
        rec = rec[:max_events]

    return rec


def refresh_event_times(event):

    new = copy.deepcopy(event)

    now = datetime.now(timezone.utc)

    stale_delta = timedelta(seconds=60)

    try:
        t = parse_iso(new.get("time"))
        s = parse_iso(new.get("stale"))
        stale_delta = s - t
    except Exception:
        pass

    new.set("time", format_cot_time(now))
    new.set("start", format_cot_time(now))
    new.set("stale", format_cot_time(now + stale_delta))

    return new


def mark_dashboard_replay(event, replay_id):

    new = copy.deepcopy(event)

    detail = new.find("detail")
    if detail is None:
        detail = ET.SubElement(new, "detail")

    fissure_detail = detail.find("fissure")
    if fissure_detail is None:
        fissure_detail = ET.SubElement(detail, "fissure")

    replay_elem = fissure_detail.find("replay_dashboard")
    if replay_elem is None:
        replay_elem = ET.SubElement(fissure_detail, "replay_dashboard")
    replay_elem.text = "true"

    replay_id_elem = fissure_detail.find("replay_id")
    if replay_id_elem is None:
        replay_id_elem = ET.SubElement(fissure_detail, "replay_id")
    replay_id_elem.text = str(replay_id)

    return new


def build_pytak_config(args, config):

    tak = config.get("tak", {})

    host = args.host or tak.get("ip_addr", "127.0.0.1")
    port = args.port or tak.get("port", 8089)

    cert = args.cert or tak.get("cert")
    key = args.key or tak.get("key")

    cfg = {
        "COT_URL": f"tls://{host}:{port}",
        "PYTAK_TLS_CLIENT_CERT": cert,
        "PYTAK_TLS_CLIENT_KEY": key,
    }

    if not args.secure:
        cfg["PYTAK_TLS_DONT_VERIFY"] = "1"
        cfg["PYTAK_TLS_DONT_CHECK_HOSTNAME"] = "1"

    return cfg


async def replay_records(records, args, tx_queue, logger):

    speed = args.speed
    min_interval = args.min_interval

    first_ts = records[0].logged_ts

    for idx, r in enumerate(records, start=1):

        if idx == 1:
            sleep = 0
        else:
            raw = (r.logged_ts - records[idx - 2].logged_ts).total_seconds()
            sleep = max(raw / speed, min_interval)

        if sleep:
            await asyncio.sleep(sleep)

        elem = (
            copy.deepcopy(r.event_elem)
            if args.no_refresh_times
            else refresh_event_times(r.event_elem)
        )

        if args.dashboard:
            replay_id = (
                f"{r.source_path.parent.name}/"
                f"{r.source_path.name}:{r.index_in_file}:"
                f"{int(r.logged_ts.timestamp() * 1_000_000)}"
            )
            elem = mark_dashboard_replay(elem, replay_id)

        data = ET.tostring(elem, encoding="utf-8")

        await tx_queue.put(data)

        logger.info(
            "[%d/%d] queued %s",
            idx,
            len(records),
            elem.get("uid"),
        )


async def wait_for_tx_queue_drain(queue, logger, timeout=10):

    start = asyncio.get_running_loop().time()

    while not queue.empty():

        if asyncio.get_running_loop().time() - start > timeout:
            logger.warning("TX queue drain timeout")
            return

        await asyncio.sleep(0.1)

    logger.info("TX queue drained")


async def shutdown_clitool(task, logger):

    task.cancel()

    with contextlib.suppress(asyncio.CancelledError):
        await task

    await asyncio.sleep(1)

    logger.info("TAK client shutdown complete")


async def main_async(args):

    logger = setup_logger(args.verbose)

    loop = asyncio.get_running_loop()
    install_asyncio_exception_filter(loop, logger)

    config = load_yaml_config(args.config)
    root = resolve_fissure_root(args.config)

    session, paths = resolve_input_paths(args, config, root)
    records = load_records(paths, args.max_events)

    replay_source = str(session) if session else str(paths[0])

    if args.dry_run:
        print(f"Replay source: {replay_source}")
        print(f"CoT files discovered: {len(paths)}")
        print(f"Total CoT events: {len(records)}")

        if records:
            first = records[0]
            last = records[-1]

            print(
                "First event: "
                f"uid={first.event_elem.get('uid')} "
                f"type={first.event_elem.get('type')} "
                f"logged_ts={first.logged_ts.isoformat()}"
            )
            print(
                "Last event: "
                f"uid={last.event_elem.get('uid')} "
                f"type={last.event_elem.get('type')} "
                f"logged_ts={last.logged_ts.isoformat()}"
            )
        else:
            print("No CoT events found.")

        print(f"Dashboard replay marker: {'enabled' if args.dashboard else 'disabled'}")
        print("Dry run mode enabled — no messages were sent.")
        return 0

    logger.info("Replay source: %s", replay_source)
    logger.info("CoT files discovered: %d", len(paths))
    logger.info("Total CoT events: %d", len(records))
    if args.dashboard:
        logger.info("Dashboard replay marker enabled.")

    pytak_config = build_pytak_config(args, config)

    logger.info("Connecting to %s", pytak_config["COT_URL"])

    if args.secure:
        logger.info("TLS verification enabled.")
    else:
        logger.warning("TLS verification disabled by default for replay tool.")

    clitool = pytak.CLITool(pytak_config)
    await clitool.setup()

    task = asyncio.create_task(clitool.run())

    try:
        await replay_records(records, args, clitool.tx_queue, logger)
        await wait_for_tx_queue_drain(clitool.tx_queue, logger)
        await asyncio.sleep(1)
        logger.info("Replay complete")
        return 0
    finally:
        await shutdown_clitool(task, logger)


def main():

    args = parse_args()

    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())