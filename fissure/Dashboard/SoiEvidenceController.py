"""Build disposable, user-facing evidence folders for Tactical SOIs."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess

from typing import Dict, Iterable, List


def _clean_identifier(value: object) -> str:
    text = str(value or "").strip()

    if not text:
        return "unknown-soi"

    text = text.replace(os.sep, "_")

    if os.altsep:
        text = text.replace(os.altsep, "_")

    return text


def _append_unique(
    values: List[str],
    seen: set,
    candidate: object,
) -> None:
    candidate_text = str(candidate or "").strip()

    if (
        not candidate_text
        or candidate_text in seen
    ):
        return

    seen.add(candidate_text)
    values.append(candidate_text)


def collect_soi_artifact_ids(
    soi: Dict[str, object],
) -> List[str]:
    """
    Return every artifact explicitly associated with the SOI.

    This intentionally does not categorize artifacts. It preserves the
    cumulative SOI relationship and accepts current and legacy record shapes.
    """
    artifact_ids: List[str] = []
    seen = set()

    for artifact_id in (
        soi.get("artifact_ids", [])
        if isinstance(
            soi.get("artifact_ids"),
            (list, tuple, set),
        )
        else []
    ):
        _append_unique(
            artifact_ids,
            seen,
            artifact_id,
        )

    artifact_links = soi.get("artifact_links", [])

    if isinstance(artifact_links, dict):
        artifact_links = [artifact_links]

    if isinstance(
        artifact_links,
        (list, tuple),
    ):
        for link in artifact_links:
            if isinstance(link, dict):
                _append_unique(
                    artifact_ids,
                    seen,
                    link.get("artifact_id"),
                )
            else:
                _append_unique(
                    artifact_ids,
                    seen,
                    link,
                )

    analysis_history = soi.get(
        "analysis_history",
        [],
    )

    if isinstance(analysis_history, dict):
        analysis_history = [analysis_history]

    if isinstance(
        analysis_history,
        (list, tuple),
    ):
        for entry in analysis_history:
            if not isinstance(entry, dict):
                continue

            _append_unique(
                artifact_ids,
                seen,
                entry.get("artifact_id"),
            )

            entry_artifact_ids = entry.get(
                "artifact_ids",
                [],
            )

            if isinstance(
                entry_artifact_ids,
                (list, tuple, set),
            ):
                for artifact_id in entry_artifact_ids:
                    _append_unique(
                        artifact_ids,
                        seen,
                        artifact_id,
                    )

    _append_unique(
        artifact_ids,
        seen,
        soi.get("artifact_id"),
    )

    return artifact_ids


def _render_text_value(
    value: object,
    indent: int = 0,
) -> List[str]:
    prefix = " " * indent

    if isinstance(value, dict):
        lines: List[str] = []

        for key, child_value in value.items():
            if isinstance(
                child_value,
                (dict, list, tuple),
            ):
                lines.append(
                    f"{prefix}{key}:"
                )
                lines.extend(
                    _render_text_value(
                        child_value,
                        indent + 2,
                    )
                )
            else:
                lines.append(
                    f"{prefix}{key}: {child_value}"
                )

        return lines

    if isinstance(value, (list, tuple)):
        lines = []

        for index, child_value in enumerate(value):
            if isinstance(
                child_value,
                (dict, list, tuple),
            ):
                lines.append(
                    f"{prefix}[{index}]"
                )
                lines.extend(
                    _render_text_value(
                        child_value,
                        indent + 2,
                    )
                )
            else:
                lines.append(
                    f"{prefix}[{index}] {child_value}"
                )

        return lines

    return [f"{prefix}{value}"]


def _write_soi_snapshot(
    soi_root: str,
    soi: Dict[str, object],
) -> None:
    json_path = os.path.join(
        soi_root,
        "soi_details.json",
    )
    text_path = os.path.join(
        soi_root,
        "soi_details.txt",
    )

    with open(
        json_path,
        "w",
        encoding="utf-8",
    ) as json_file:
        json.dump(
            soi,
            json_file,
            indent=2,
            sort_keys=False,
            default=str,
        )

    text_lines = _render_text_value(soi)

    with open(
        text_path,
        "w",
        encoding="utf-8",
    ) as text_file:
        text_file.write(
            "\n".join(text_lines)
        )
        text_file.write("\n")


async def _wait_for_artifact(
    controller,
    transfer_id: str,
    artifact_id: str,
    timeout_seconds: float = 45.0,
) -> str:
    """
    Wait until the existing transfer controller commits the artifact cache.

    The transfer controller already owns checksum validation, timeout handling,
    partial-file cleanup, and atomic completion. This helper only waits for the
    verified cache entry to become available.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds

    while loop.time() < deadline:
        local_path = controller.get_local_path(
            artifact_id
        )

        if local_path:
            return local_path

        transfer_known = (
            transfer_id
            in controller.pending_requests
            or transfer_id
            in controller.active_downloads
        )

        if not transfer_known:
            raise RuntimeError(
                "Artifact transfer ended without "
                f"a verified cache entry: {artifact_id}"
            )

        await asyncio.sleep(0.1)

    raise TimeoutError(
        f"Timed out waiting for artifact {artifact_id}"
    )


async def ensure_artifacts_cached(
    dashboard,
    artifact_ids: Iterable[str],
) -> None:
    """
    Reuse verified cached artifacts and download only missing artifact IDs.

    Downloads are requested sequentially so the existing Dashboard progress
    controls continue to represent one transfer clearly.
    """
    controller = (
        dashboard.backend
        .artifact_transfer_controller
    )

    for artifact_id in artifact_ids:
        artifact_id = str(
            artifact_id or ""
        ).strip()

        if not artifact_id:
            continue

        if controller.get_local_path(
            artifact_id
        ):
            continue

        transfer_id = (
            await dashboard.backend
            .requestDashboardArtifactDownload(
                artifact_id,
                open_when_complete=False,
            )
        )

        await _wait_for_artifact(
            controller,
            transfer_id,
            artifact_id,
        )


def _copy_cached_artifact(
    controller,
    artifact_id: str,
    destination_root: str,
) -> None:
    """
    Copy one verified cached artifact while preserving its natural hierarchy.
    """
    cache_record = controller.local_cache.get(
        artifact_id,
        {},
    )

    if not isinstance(cache_record, dict):
        raise RuntimeError(
            "Cached artifact record is missing: "
            f"{artifact_id}"
        )

    artifact_destination = os.path.join(
        destination_root,
        artifact_id,
    )

    artifact_root = str(
        cache_record.get("artifact_root", "")
        or ""
    ).strip()

    if (
        artifact_root
        and os.path.isdir(artifact_root)
    ):
        shutil.copytree(
            artifact_root,
            artifact_destination,
        )
        return

    local_path = controller.get_local_path(
        artifact_id
    )

    if not local_path:
        raise RuntimeError(
            "Cached artifact path is missing: "
            f"{artifact_id}"
        )

    if os.path.isdir(local_path):
        shutil.copytree(
            local_path,
            artifact_destination,
        )
        return

    os.makedirs(
        artifact_destination,
        exist_ok=True,
    )

    shutil.copy2(
        local_path,
        os.path.join(
            artifact_destination,
            os.path.basename(local_path),
        ),
    )


async def build_soi_evidence_folder(
    dashboard,
    soi: Dict[str, object],
) -> str:
    """
    Build and open a fresh SOI evidence folder.

    The managed artifact cache remains authoritative for downloaded artifact
    data. The SOI folder is a disposable convenience view that is deleted and
    rebuilt from the current SOI record on every request.
    """
    if not isinstance(soi, dict) or not soi:
        raise ValueError(
            "A valid SOI record is required"
        )

    soi_id = (
        soi.get("soi_id")
        or soi.get("uid")
        or soi.get("id")
    )

    if not soi_id:
        raise ValueError(
            "The SOI record does not contain an ID"
        )

    artifact_ids = collect_soi_artifact_ids(
        soi
    )

    await ensure_artifacts_cached(
        dashboard,
        artifact_ids,
    )

    controller = (
        dashboard.backend
        .artifact_transfer_controller
    )

    soi_root = os.path.join(
        controller.cache_root,
        "sois",
        _clean_identifier(soi_id),
    )

    if os.path.isdir(soi_root):
        shutil.rmtree(soi_root)

    os.makedirs(
        soi_root,
        exist_ok=True,
    )

    _write_soi_snapshot(
        soi_root,
        soi,
    )

    if artifact_ids:
        artifacts_root = os.path.join(
            soi_root,
            "artifacts",
        )

        os.makedirs(
            artifacts_root,
            exist_ok=True,
        )

        for artifact_id in artifact_ids:
            _copy_cached_artifact(
                controller,
                artifact_id,
                artifacts_root,
            )

    subprocess.Popen(
        [
            "xdg-open",
            soi_root,
        ]
    )

    return soi_root
