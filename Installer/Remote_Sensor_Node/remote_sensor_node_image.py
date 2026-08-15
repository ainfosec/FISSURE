"""Select or build the Sensor Node image used for deployment."""

import asyncio
from pathlib import Path
import shlex
import shutil

from remote_sensor_node_local_apptainer import ensure_local_apptainer
from remote_sensor_node_options import DeployOptions, DeploymentError
from remote_sensor_node_templates import (
    APPTAINER_TEMPLATE,
    render_apptainer_definition,
)


async def get_image(options: DeployOptions, temp_dir: Path) -> Path:
    if options.image_file:
        return options.image_file.resolve()
    if options.output_image.is_file():
        print(f"[✓] Using existing image {options.output_image}")
        return options.output_image.resolve()

    apptainer = await ensure_local_apptainer(options.install_apptainer)
    source = temp_dir / "source"
    await asyncio.to_thread(copy_build_context, options.source_dir, source)
    definition = render_apptainer_definition(
        source,
        temp_dir / APPTAINER_TEMPLATE.stem,
    )
    options.output_image.parent.mkdir(parents=True, exist_ok=True)
    command = [apptainer, "build", "--force"]
    if not options.build_with_sudo:
        command.append("--fakeroot")
    command.extend([str(options.output_image), str(definition)])
    if options.build_with_sudo:
        command.insert(0, "sudo")

    print(f"[*] Building {options.output_image}")
    process = await asyncio.create_subprocess_exec(*command)
    if await process.wait():
        raise DeploymentError(f"Build failed: {shlex.join(command)}")
    return options.output_image.resolve()


def copy_build_context(source: Path, destination: Path) -> None:
    root_exclusions = {
        ".agents",
        ".codex",
        ".env",
        ".git",
        ".idea",
        ".venv",
        "Logs",
        "artifacts",
        "artifacts_node",
        "artifacts_system",
        "build",
        "certificates",
        "logs",
    }

    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored = {
            name
            for name in names
            if name in {".git", ".pytest_cache", "__pycache__"}
        }
        if Path(directory).resolve() == source.resolve():
            ignored.update(root_exclusions.intersection(names))
        ignored.update(name for name in names if name.endswith(".key_secret"))
        return ignored

    shutil.copytree(source.resolve(), destination, symlinks=True, ignore=ignore)
