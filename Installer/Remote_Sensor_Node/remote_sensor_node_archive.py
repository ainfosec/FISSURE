"""Create safe transfer archives for remote directory synchronization."""

from pathlib import Path, PurePosixPath
import tarfile


IGNORED_DIRECTORIES = {".git", ".pytest_cache", "__pycache__"}
IGNORED_FILES = {".DS_Store", ".env"}
IGNORED_SUFFIXES = {".pyc", ".pyo", ".key_secret"}


class DirectoryArchiveError(RuntimeError):
    """Raised when a directory cannot be prepared for transfer."""


def create_directory_archive(
    source: Path,
    destination: Path,
    ignored_root_entries: frozenset[str] = frozenset(),
    ignored_paths: frozenset[PurePosixPath] = frozenset(),
    allow_links: bool = True,
) -> Path:
    """Archive a directory while omitting caches and selected local state."""
    try:
        with tarfile.open(destination, "w") as archive:
            for entry in sorted(source.iterdir(), key=lambda path: path.name):
                archive.add(
                    entry,
                    arcname=entry.name,
                    recursive=True,
                    filter=lambda member: _filter_member(
                        member,
                        ignored_root_entries,
                        ignored_paths,
                        allow_links,
                    ),
                )
    except (OSError, tarfile.TarError) as exc:
        raise DirectoryArchiveError(str(exc)) from exc
    return destination


def _filter_member(
    member: tarfile.TarInfo,
    ignored_root_entries: frozenset[str],
    ignored_paths: frozenset[PurePosixPath],
    allow_links: bool,
) -> tarfile.TarInfo | None:
    path = PurePosixPath(member.name)
    if _is_ignored(path, ignored_root_entries, ignored_paths):
        return None
    is_link = member.issym() or member.islnk()
    if not (member.isfile() or member.isdir() or (allow_links and is_link)):
        return None
    # The remote apply step assigns ownership after extraction.
    member.uid = member.gid = 0
    member.uname = member.gname = ""
    return member


def _is_ignored(
    path: PurePosixPath,
    ignored_root_entries: frozenset[str],
    ignored_paths: frozenset[PurePosixPath],
) -> bool:
    if any(part in IGNORED_DIRECTORIES for part in path.parts):
        return True
    if path.parts and path.parts[0] in ignored_root_entries:
        return True
    if any(path == ignored or ignored in path.parents for ignored in ignored_paths):
        return True
    return path.name in IGNORED_FILES or path.suffix in IGNORED_SUFFIXES
