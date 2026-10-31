#!/usr/bin/env python3
"""Expose the single Audio Transcription Action to FISSURE."""
from typing import Any, Dict

from fissure.Sensor_Node.SensorNode import SensorNode


PLUGIN_NAME = "Audio Transcription"
ACTION_TAGS = {
    "transcribe_audio_file": ["All"],
}

transcribe_audio_file_schema = {
    "params": [
        {
            "name": "audio_file_path",
            "label": "Local Audio File Path",
            "type": "string",
            "default": "",
            "description": (
                "Absolute path to a previously recorded audio file accessible "
                "on the Sensor Node executing this Action (WAV supported)."
            ),
        },
    ]
}


async def transcribe_audio_file(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    """Transcribe an existing local recording on the selected Sensor Node."""
    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "transcribe_audio_file.py",
        parameters,
        node_uid,
    )
