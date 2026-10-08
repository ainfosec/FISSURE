from typing import Any, Dict

from fissure.Sensor_Node.SensorNode import SensorNode


PLUGIN_NAME = "RadarAnalysis"

ACTION_TAGS = {
    "radar_analysis": [
        "All",
        "sa.inspection",
        "client.dashboard",
        "node.local",
    ],
}

radar_analysis_schema = {
    "params": [
        {
            "name": "representation",
            "label": "Representation",
            "type": "string",
            "default": "auto",
            "options": [
                "auto",
                "pdw_csv",
                "log_video_f32",
                "iq_cf32",
            ],
        },
        {
            "name": "sample_rate_hz",
            "label": "Sample Rate (S/s)",
            "type": "number",
            "default": 0.0,
            "min": 0.0,
            "max": 1e12,
            "step": 1.0,
            "decimals": 0,
            "description": (
                "Fallback sample rate for raw log-video/IQ files when the "
                "active Inspection evidence does not provide sample-rate "
                "metadata. A positive value is required for raw samples."
            ),
        },
        {
            "name": "center_frequency_hz",
            "label": "Nominal Center Frequency (Hz)",
            "type": "number",
            "default": 0.0,
            "min": 0.0,
            "max": 1e12,
            "step": 1.0,
            "decimals": 0,
            "description": (
                "Optional fallback center frequency when the active "
                "Inspection evidence does not provide center-frequency "
                "metadata. Leave at zero when unknown."
            ),
        },
    ]
}
async def radar_analysis(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    """Analyze the file currently loaded in the Inspection tab."""
    parameters = dict(parameters or {})
    context = parameters.get(
        "_fissure_inspection_context",
        {},
    )

    if not isinstance(context, dict):
        context = {}

    filepath = str(
        context.get("filepath")
        or parameters.get("filepath")
        or ""
    ).strip()

    if not filepath:
        raise ValueError(
            "Inspection context did not provide an input filepath. Load a "
            "local file or prepared Artifact in the Inspection tab first."
        )

    sample_rate_hz = float(
        parameters.get("sample_rate_hz")
        or 0.0
    )
    center_frequency_hz = float(
        parameters.get("center_frequency_hz")
        or 0.0
    )

    context_sample_rate = float(
        context.get("sample_rate_hz")
        or 0.0
    )
    if context_sample_rate > 0.0:
        sample_rate_hz = context_sample_rate

    context_center_frequency = float(
        context.get("center_frequency_hz")
        or 0.0
    )
    if context_center_frequency > 0.0:
        center_frequency_hz = context_center_frequency

    operation_parameters = {
        "operation_id": str(
            parameters.get("operation_id")
            or ""
        ).strip(),
        "filepath": filepath,
        "representation": str(
            parameters.get("representation")
            or "auto"
        ).strip(),
        "sample_rate_hz": sample_rate_hz,
        "center_frequency_hz": center_frequency_hz,
    }

    component.logger.info(
        "RadarAnalysis Inspection action for %s",
        filepath,
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "radar_analysis.py",
        operation_parameters,
        node_uid,
    )
