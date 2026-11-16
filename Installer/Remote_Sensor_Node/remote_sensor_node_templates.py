"""Render deployment configuration from the bundle's Jinja2 templates."""

from pathlib import Path
from typing import Any, Mapping

import yaml


TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
SENSOR_NODE_TEMPLATE = TEMPLATE_DIR / "sensor-node.yml.j2"
SERVICE_UNIT_TEMPLATE = TEMPLATE_DIR / "fissure-sensor-node.service.j2"
APPTAINER_TEMPLATE = TEMPLATE_DIR / "remote_sensor_node_apptainer.def.j2"


class TemplateRenderError(RuntimeError):
    """Raised when deployment configuration cannot be rendered safely."""


def render_sensor_node_config(
    destination: Path,
    configuration: Mapping[str, Any],
    address_source: str,
) -> Path:
    """Render a complete Sensor Node YAML file from installed configuration."""
    return _render_to_file(
        SENSOR_NODE_TEMPLATE.name,
        destination,
        {
            "configuration": configuration,
            "hiprfisr_address_source": address_source,
        },
        mode=0o600,
    )


def render_service_unit(
    destination: Path,
    remote_dir: str,
    user: str,
    group: str,
    apptainer: str,
) -> Path:
    """Render the systemd unit installed on the remote node."""
    return _render_to_file(
        SERVICE_UNIT_TEMPLATE.name,
        destination,
        {
            "remote_dir": remote_dir,
            "user": user,
            "group": group,
            "apptainer": apptainer,
        },
        mode=0o600,
    )


def render_apptainer_definition(source: Path, destination: Path) -> Path:
    """Render the Apptainer definition with its temporary build context."""
    return _render_to_file(
        APPTAINER_TEMPLATE.name,
        destination,
        {"fissure_source": str(source)},
        mode=0o600,
    )


def _render_to_file(
    template_name: str,
    destination: Path,
    context: Mapping[str, Any],
    mode: int,
) -> Path:
    try:
        rendered = _render(template_name, context)
        destination.write_text(rendered, encoding="utf-8")
        destination.chmod(mode)
    except OSError as exc:
        raise TemplateRenderError(
            f"Unable to write rendered template {destination}: {exc}"
        ) from exc
    return destination


def _render(template_name: str, context: Mapping[str, Any]) -> str:
    try:
        import jinja2
    except ImportError as exc:
        raise TemplateRenderError(
            "Jinja2 is required; install the deployment requirements"
        ) from exc

    environment = jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
        undefined=jinja2.StrictUndefined,
        autoescape=False,
        keep_trailing_newline=True,
    )
    environment.filters["to_yaml"] = _to_yaml
    try:
        return environment.get_template(template_name).render(**context)
    except jinja2.TemplateError as exc:
        raise TemplateRenderError(
            f"Unable to render {template_name}: {exc}"
        ) from exc


def _to_yaml(value: Any) -> str:
    """Serialize once; values containing Jinja syntax are not evaluated again."""
    return yaml.safe_dump(value, sort_keys=False, allow_unicode=True).rstrip()
