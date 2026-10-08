import json
import logging
import sys
from pathlib import Path
from typing import Callable, Union

from fissure.utils.plugins.operations import Operation


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PLUGIN_ROOT / "scripts"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from radar_analyzer import (  # noqa: E402
    analyze_file,
    inspection_payload,
    write_markdown,
    write_plots,
)


class OperationMain(Operation):
    def __init__(
        self,
        operation_id: str = "",
        filepath: str = "",
        representation: str = "auto",
        sample_rate_hz: float = 0.0,
        center_frequency_hz: float = 0.0,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        inspection_callback: Union[Callable, None] = None,
        artifact_manager=None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            inspection_callback=inspection_callback,
            artifact_manager=artifact_manager,
        )

        requested_operation_id = str(
            operation_id or ""
        ).strip()
        if requested_operation_id:
            self.opid = requested_operation_id

        self.filepath = str(filepath or "").strip()
        self.representation = str(
            representation or "auto"
        ).strip()
        self.sample_rate_hz = float(
            sample_rate_hz or 0.0
        )
        self.center_frequency_hz = float(
            center_frequency_hz or 0.0
        )

    @staticmethod
    def get_resources():
        return {}

    def _managed_output_directory(self) -> Path:
        if self.artifact_manager is None:
            raise RuntimeError(
                "Radar analysis requires FISSURE managed Artifact storage."
            )

        _, files_dir = self.artifact_manager.create_operation_dir(
            self.opid
        )
        return Path(files_dir)

    async def run(self) -> None:
        try:
            result = analyze_file(
                self.filepath,
                self.representation,
                self.sample_rate_hz,
                self.center_frequency_hz,
            )

            output_directory = self._managed_output_directory()
            stem = Path(self.filepath).stem

            json_path = output_directory / (
                f"{stem}.radar_analysis.json"
            )
            markdown_path = output_directory / (
                f"{stem}.radar_analysis.md"
            )

            json_path.write_text(
                json.dumps(
                    result,
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            write_markdown(
                result,
                markdown_path,
            )

            plot_paths = write_plots(
                result,
                output_directory,
                raw_path=self.filepath,
                sample_rate_hz=self.sample_rate_hz,
            )

            artifact_files = [
                str(json_path),
                str(markdown_path),
                *[
                    str(path)
                    for path in plot_paths
                ],
            ]

            artifact_id = self.create_artifact(
                files=artifact_files,
                name=(
                    "Radar analysis: "
                    f"{Path(self.filepath).name}"
                ),
                artifact_type="analysis",
                metadata={
                    "workflow": "sa.inspection",
                    "analysis_type": "radar",
                    "source_file": self.filepath,
                    "representation": result["representation"],
                },
            )

            artifact_ids = (
                [artifact_id]
                if artifact_id
                else []
            )

            await self.inspection_callback(
                self.node_uid,
                self.opid,
                inspection_payload(
                    result,
                    artifact_ids,
                ),
                True,
            )

        except Exception as error:
            await self.inspection_callback(
                self.node_uid,
                self.opid,
                {
                    "title": "Radar Pulse Analysis",
                    "error": str(error),
                    "values": {
                        "Source File": self.filepath,
                    },
                },
                True,
            )
            raise
