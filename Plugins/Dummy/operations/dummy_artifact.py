#! /usr/bin/env python3
"""Dummy Artifact Operation

Creates dummy files, registers them as a zip artifact via ArtifactManager,
and optionally emits an alert containing the artifact_id.
"""

import asyncio
import logging
import os
import sys
import time
import uuid
import json
from typing import Any, Callable, Dict, Union

try:
    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT
except ImportError:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT


class OperationMain(Operation):
    """Dummy Artifact Operation"""

    def __init__(
        self,
        file_count: int = 3,
        file_size_kb: int = 64,
        description: str = "Create a dummy zip artifact",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        status_callback: Union[Callable, None] = None,
        target_callback: Union[Callable, None] = None,
        artifact_manager=None,
    ) -> None:

        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            status_callback=status_callback,
            target_callback=target_callback,
            artifact_manager=artifact_manager,
        )

        # UI values often arrive as strings
        self.file_count = int(float(file_count))
        self.file_size_kb = int(float(file_size_kb))
        self.description = description or "Create a dummy zip artifact"

        self.logger.info(
            f"dummy_artifact init params: "
            f"file_count={self.file_count}, "
            f"file_size_kb={self.file_size_kb}, "
            f"description={self.description}"
        )

    async def run(self) -> None:

        if not self.artifact_manager:
            raise RuntimeError("dummy_artifact requires artifact_manager to be passed in")

        operation_id = str(uuid.uuid4())
        name = "Dummy Artifact evidence"

        file_count = self.file_count
        file_size_kb = self.file_size_kb
        include_json = True

        _, folder = self.artifact_manager.create_operation_dir(operation_id)

        if self.status_callback:
            await self.status_callback("Running: Dummy Artifact")

        bytes_total = file_size_kb * 1024
        chunk = 256 * 1024  # 256KB

        # Create dummy binary files
        for i in range(file_count):
            if getattr(self, "_stop", False):
                break

            p = os.path.join(folder, f"dummy_blob_{i:03d}.bin")
            with open(p, "wb") as f:
                remaining = bytes_total
                while remaining > 0:
                    if getattr(self, "_stop", False):
                        break
                    n = min(chunk, remaining)
                    f.write(os.urandom(n))
                    remaining -= n

            await asyncio.sleep(0)

        if getattr(self, "_stop", False):
            if self.status_callback:
                await self.status_callback("Idle")
            return

        # Optional JSON metadata file
        if include_json:
            meta_path = os.path.join(folder, "dummy_metadata.json")
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "node_uid": self.node_uid,
                        "operation_id": operation_id,
                        "created_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "note": "dummy artifact payload",
                    },
                    f,
                    indent=2,
                )

        if getattr(self, "_stop", False):
            if self.status_callback:
                await self.status_callback("Idle")
            return

        # Register artifact
        artifact_id = self.artifact_manager.create_zip_artifact_from_folder(
            source_id="",
            operation_id=operation_id,
            folder=folder,
            name=name,
            metadata={
                "role": "dummy_artifact_v1",
                "operation_id": operation_id,
                "node_uid": self.node_uid,
                "file_count": file_count,
                "file_size_kb": file_size_kb,
            },
            arc_prefix=f"dummy_{operation_id}",
        )

        self.logger.info(
            f"Dummy Artifact registered: artifact_id={artifact_id}, opid={operation_id}"
        )

        # Optional alert so you see it immediately
        if self.alert_callback:
            try:
                payload = {
                    "type": "artifact_ready",
                    "artifact_id": artifact_id,
                    "operation_id": operation_id,
                    "name": name,
                }
                await asyncio.wait_for(
                    self.alert_callback(
                        self.node_uid,
                        self.opid,
                        json.dumps(payload),
                        self.logger,
                    ),
                    timeout=2.0,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception("alert_callback failed while reporting artifact_ready")

        if self.status_callback:
            await self.status_callback("Idle")


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})