"""Build disposable, user-facing data folders for Tactical Targets."""

from __future__ import annotations

import json
import os
import shutil
import subprocess

from typing import Dict, List

from fissure.Dashboard.SoiEvidenceController import (
    ensure_artifacts_cached,
)


def _clean_identifier(
    value: object,
) -> str:
    text = str(
        value or ""
    ).strip()

    if not text:
        return "unknown-target"

    text = text.replace(
        os.sep,
        "_",
    )

    if os.altsep:
        text = text.replace(
            os.altsep,
            "_",
        )

    return text


def _append_unique(
    values: List[str],
    seen: set,
    candidate: object,
) -> None:
    candidate_text = str(
        candidate or ""
    ).strip()

    if (
        not candidate_text
        or candidate_text in seen
    ):
        return

    seen.add(
        candidate_text
    )
    values.append(
        candidate_text
    )


def collect_target_artifact_ids(
    target: Dict[str, object],
) -> List[str]:
    """
    Return only artifacts explicitly owned by the Target.

    SOI artifacts are intentionally excluded. Investigative evidence remains
    reachable through source_soi_id and the SOI Download Evidence workflow.
    """
    artifact_ids: List[str] = []
    seen = set()

    target_artifact_ids = (
        target.get(
            "artifact_ids",
            [],
        )
    )

    if isinstance(
        target_artifact_ids,
        (list, tuple, set),
    ):
        for artifact_id in (
            target_artifact_ids
        ):
            _append_unique(
                artifact_ids,
                seen,
                artifact_id,
            )

    artifact_links = target.get(
        "artifact_links",
        [],
    )

    if isinstance(
        artifact_links,
        dict,
    ):
        artifact_links = [
            artifact_links
        ]

    if isinstance(
        artifact_links,
        (list, tuple),
    ):
        for link in artifact_links:
            if isinstance(
                link,
                dict,
            ):
                _append_unique(
                    artifact_ids,
                    seen,
                    link.get(
                        "artifact_id"
                    ),
                )
            else:
                _append_unique(
                    artifact_ids,
                    seen,
                    link,
                )

    history = target.get(
        "history",
        [],
    )

    if isinstance(
        history,
        dict,
    ):
        history = [history]

    if isinstance(
        history,
        (list, tuple),
    ):
        for entry in history:
            if not isinstance(
                entry,
                dict,
            ):
                continue

            _append_unique(
                artifact_ids,
                seen,
                entry.get(
                    "artifact_id"
                ),
            )

            entry_artifact_ids = (
                entry.get(
                    "artifact_ids",
                    [],
                )
            )

            if isinstance(
                entry_artifact_ids,
                (list, tuple, set),
            ):
                for artifact_id in (
                    entry_artifact_ids
                ):
                    _append_unique(
                        artifact_ids,
                        seen,
                        artifact_id,
                    )

    _append_unique(
        artifact_ids,
        seen,
        target.get(
            "artifact_id"
        ),
    )

    return artifact_ids


def _render_text_value(
    value: object,
    indent: int = 0,
) -> List[str]:
    prefix = " " * indent

    if isinstance(
        value,
        dict,
    ):
        lines: List[str] = []

        for (
            key,
            child_value,
        ) in value.items():
            if isinstance(
                child_value,
                (
                    dict,
                    list,
                    tuple,
                ),
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
                    f"{prefix}{key}: "
                    f"{child_value}"
                )

        return lines

    if isinstance(
        value,
        (list, tuple),
    ):
        lines = []

        for (
            index,
            child_value,
        ) in enumerate(value):
            if isinstance(
                child_value,
                (
                    dict,
                    list,
                    tuple,
                ),
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
                    f"{prefix}[{index}] "
                    f"{child_value}"
                )

        return lines

    return [
        f"{prefix}{value}"
    ]


def _write_target_snapshot(
    target_root: str,
    target: Dict[str, object],
) -> None:
    json_path = os.path.join(
        target_root,
        "target_details.json",
    )
    text_path = os.path.join(
        target_root,
        "target_details.txt",
    )

    with open(
        json_path,
        "w",
        encoding="utf-8",
    ) as json_file:
        json.dump(
            target,
            json_file,
            indent=2,
            sort_keys=False,
            default=str,
        )

    text_lines = (
        _render_text_value(
            target
        )
    )

    with open(
        text_path,
        "w",
        encoding="utf-8",
    ) as text_file:
        text_file.write(
            "\n".join(
                text_lines
            )
        )
        text_file.write("\n")


def _copy_cached_artifact(
    controller,
    artifact_id: str,
    destination_root: str,
) -> None:
    cache_record = (
        controller.local_cache.get(
            artifact_id,
            {},
        )
    )

    if not isinstance(
        cache_record,
        dict,
    ):
        raise RuntimeError(
            "Cached artifact record is missing: "
            f"{artifact_id}"
        )

    artifact_destination = (
        os.path.join(
            destination_root,
            artifact_id,
        )
    )

    artifact_root = str(
        cache_record.get(
            "artifact_root",
            "",
        )
        or ""
    ).strip()

    if (
        artifact_root
        and os.path.isdir(
            artifact_root
        )
    ):
        shutil.copytree(
            artifact_root,
            artifact_destination,
        )
        return

    local_path = (
        controller.get_local_path(
            artifact_id
        )
    )

    if not local_path:
        raise RuntimeError(
            "Cached artifact path is missing: "
            f"{artifact_id}"
        )

    if os.path.isdir(
        local_path
    ):
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
            os.path.basename(
                local_path
            ),
        ),
    )


async def build_target_data_folder(
    dashboard,
    target: Dict[str, object],
) -> str:
    """
    Build and open a fresh Target data folder.

    The folder contains the current complete Target record and only artifacts
    explicitly associated with Target operations. SOI evidence is not copied.
    """
    if (
        not isinstance(
            target,
            dict,
        )
        or not target
    ):
        raise ValueError(
            "A valid Target record is required"
        )

    target_id = (
        target.get(
            "target_id"
        )
        or target.get("uid")
        or target.get("id")
    )

    if not target_id:
        raise ValueError(
            "The Target record does not contain an ID"
        )

    artifact_ids = (
        collect_target_artifact_ids(
            target
        )
    )

    await ensure_artifacts_cached(
        dashboard,
        artifact_ids,
    )

    controller = (
        dashboard.backend
        .artifact_transfer_controller
    )

    target_root = os.path.join(
        controller.cache_root,
        "targets",
        _clean_identifier(
            target_id
        ),
    )

    if os.path.isdir(
        target_root
    ):
        shutil.rmtree(
            target_root
        )

    os.makedirs(
        target_root,
        exist_ok=True,
    )

    _write_target_snapshot(
        target_root,
        target,
    )

    if artifact_ids:
        artifacts_root = (
            os.path.join(
                target_root,
                "artifacts",
            )
        )

        os.makedirs(
            artifacts_root,
            exist_ok=True,
        )

        for artifact_id in (
            artifact_ids
        ):
            _copy_cached_artifact(
                controller,
                artifact_id,
                artifacts_root,
            )

    subprocess.Popen(
        [
            "xdg-open",
            target_root,
        ]
    )

    return target_root