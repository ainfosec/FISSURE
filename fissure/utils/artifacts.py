#!/usr/bin/env python3
"""Artifact Management for FISSURE Operations
"""
import json
import os
import uuid
import hashlib
import logging
import mimetypes
import zipfile

from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union, Tuple, Iterable


ARTIFACT_NODE_DIR = (
    os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    + "/artifacts_node"
)
ARTIFACT_SYSTEM_DIR = (
    os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    + "/artifacts_system"
)


def calculate_file_checksum(file_path: str) -> str:
    """Calculate SHA256 checksum of a file.
    
    Parameters
    ----------
    file_path : str
        Path to the file

    Returns
    -------
    str
        SHA256 checksum of the file
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


@dataclass
class ArtifactFile:
    """
    One physical file belonging to a logical artifact.

    relative_path is always relative to:
        <artifact_manager.base_dir>/<operation_id>/files/

    Absolute node paths are never persisted or sent as artifact metadata.
    """
    id: str
    name: str
    relative_path: str
    size: int
    sha256: str
    role: str = "payload"
    content_type: str = "application/octet-stream"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        required_text = {
            "id": self.id,
            "name": self.name,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "role": self.role,
            "content_type": self.content_type,
        }

        for field_name, value in required_text.items():
            if not str(value or "").strip():
                raise ValueError(
                    f"ArtifactFile field '{field_name}' cannot be blank"
                )

        self.size = int(self.size)
        if self.size < 0:
            raise ValueError("ArtifactFile size cannot be negative")

        normalized = os.path.normpath(self.relative_path)

        if os.path.isabs(normalized):
            raise ValueError(
                "ArtifactFile relative_path must not be absolute"
            )

        if normalized == ".." or normalized.startswith(f"..{os.sep}"):
            raise ValueError(
                "ArtifactFile relative_path escapes the operation files directory"
            )

        self.relative_path = normalized
        self.name = str(self.name)
        self.role = str(self.role)
        self.content_type = str(self.content_type)
        self.metadata = dict(self.metadata or {})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "relative_path": self.relative_path,
            "size": self.size,
            "sha256": self.sha256,
            "role": self.role,
            "content_type": self.content_type,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ArtifactFile":
        if not isinstance(data, dict):
            raise TypeError("Artifact file record must be a dictionary")

        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            relative_path=str(data["relative_path"]),
            size=int(data["size"]),
            sha256=str(data["sha256"]),
            role=str(data.get("role", "payload") or "payload"),
            content_type=str(
                data.get("content_type", "application/octet-stream")
                or "application/octet-stream"
            ),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass
class ArtifactRelation:
    """
    A typed relation between an artifact and another FISSURE entity.

    Examples:
        target / target_id / exploit_evidence
        soi / soi_id / supporting_capture
        detection / detection_id / source_detection
    """
    entity_type: str
    entity_id: str
    role: str = "related"

    def __post_init__(self) -> None:
        self.entity_type = str(self.entity_type or "").strip().lower()
        self.entity_id = str(self.entity_id or "").strip()
        self.role = str(self.role or "related").strip()

        if not self.entity_type:
            raise ValueError("ArtifactRelation entity_type cannot be blank")

        if not self.entity_id:
            raise ValueError("ArtifactRelation entity_id cannot be blank")

        if not self.role:
            raise ValueError("ArtifactRelation role cannot be blank")

    def to_dict(self) -> Dict[str, str]:
        return {
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "role": self.role,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ArtifactRelation":
        if not isinstance(data, dict):
            raise TypeError("Artifact relation record must be a dictionary")

        return cls(
            entity_type=str(data["entity_type"]),
            entity_id=str(data["entity_id"]),
            role=str(data.get("role", "related") or "related"),
        )


@dataclass
class Artifact:
    """
    One logical artifact produced by an operation.

    An artifact contains zero or more declared files. There is no top-level
    file_path, file_size, or checksum. Those values belong to ArtifactFile.
    """
    id: str
    source_id: str
    operation_id: str
    name: str
    artifact_type: str
    created_at: str
    modified_at: str
    files: List[ArtifactFile] = field(default_factory=list)
    relations: List[ArtifactRelation] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        required_text = {
            "id": self.id,
            "source_id": self.source_id,
            "operation_id": self.operation_id,
            "name": self.name,
            "artifact_type": self.artifact_type,
            "created_at": self.created_at,
            "modified_at": self.modified_at,
        }

        for field_name, value in required_text.items():
            if not str(value or "").strip():
                raise ValueError(
                    f"Artifact field '{field_name}' cannot be blank"
                )

        self.files = [
            item if isinstance(item, ArtifactFile)
            else ArtifactFile.from_dict(item)
            for item in (self.files or [])
        ]

        self.relations = [
            item if isinstance(item, ArtifactRelation)
            else ArtifactRelation.from_dict(item)
            for item in (self.relations or [])
        ]

        self.metadata = dict(self.metadata or {})

        file_ids = [item.id for item in self.files]
        if len(file_ids) != len(set(file_ids)):
            raise ValueError(
                f"Artifact {self.id} contains duplicate file IDs"
            )

        relative_paths = [item.relative_path for item in self.files]
        if len(relative_paths) != len(set(relative_paths)):
            raise ValueError(
                f"Artifact {self.id} contains duplicate relative paths"
            )

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def total_size(self) -> int:
        return sum(int(item.size) for item in self.files)

    def get_file(self, file_id: str) -> Optional[ArtifactFile]:
        file_id = str(file_id or "").strip()

        for item in self.files:
            if item.id == file_id:
                return item

        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "operation_id": self.operation_id,
            "name": self.name,
            "artifact_type": self.artifact_type,
            "created_at": self.created_at,
            "modified_at": self.modified_at,
            "file_count": self.file_count,
            "total_size": self.total_size,
            "files": [item.to_dict() for item in self.files],
            "relations": [
                relation.to_dict()
                for relation in self.relations
            ],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Artifact":
        """
        Load only the new manifest-only schema.

        Legacy records are deliberately rejected. Delete old index.json files
        before starting the migrated system.
        """
        if not isinstance(data, dict):
            raise TypeError("Artifact record must be a dictionary")

        legacy_fields = {
            "file_path",
            "file_size",
            "checksum",
        }

        present_legacy = sorted(
            field_name
            for field_name in legacy_fields
            if field_name in data
        )

        if present_legacy:
            raise ValueError(
                "Legacy artifact record is not supported. "
                f"Remove the old artifact index. Fields found: "
                f"{', '.join(present_legacy)}"
            )

        required = {
            "id",
            "source_id",
            "operation_id",
            "name",
            "artifact_type",
            "created_at",
            "modified_at",
            "files",
            "relations",
            "metadata",
        }

        missing = sorted(required.difference(data))
        if missing:
            raise ValueError(
                "Artifact record is missing required fields: "
                + ", ".join(missing)
            )

        return cls(
            id=str(data["id"]),
            source_id=str(data["source_id"]),
            operation_id=str(data["operation_id"]),
            name=str(data["name"]),
            artifact_type=str(data["artifact_type"]),
            created_at=str(data["created_at"]),
            modified_at=str(data["modified_at"]),
            files=[
                ArtifactFile.from_dict(item)
                for item in (data.get("files") or [])
            ],
            relations=[
                ArtifactRelation.from_dict(item)
                for item in (data.get("relations") or [])
            ],
            metadata=dict(data.get("metadata") or {}),
        )


class ArtifactManager:
    """
    Owns artifact storage and the authoritative Sensor Node artifact index.

    Plugin operations provide domain meaning. The manager owns:
        managed paths
        file enumeration
        file IDs
        relative paths
        sizes
        checksums
        content types
        totals
        validation
        persistence
    """

    def __init__(
        self,
        base_dir: str = ARTIFACT_NODE_DIR,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.base_dir = os.path.realpath(os.path.abspath(base_dir))
        os.makedirs(self.base_dir, exist_ok=True)

        self.logger = logger or logging.getLogger(__name__)
        self.index_file = os.path.join(self.base_dir, "index.json")
        self._artifacts = self._load_index()

    def _load_index(self) -> Dict[str, Artifact]:
        if not os.path.exists(self.index_file):
            return {}

        with open(self.index_file, "r", encoding="utf-8") as handle:
            data = json.load(handle)

        if not isinstance(data, dict):
            raise ValueError(
                f"Artifact index must contain an object: {self.index_file}"
            )

        try:
            return {
                str(artifact_id): Artifact.from_dict(record)
                for artifact_id, record in data.items()
            }
        except Exception as exc:
            raise RuntimeError(
                "Failed to load the artifact index using the new manifest-only "
                f"schema. Delete the old index file and restart: "
                f"{self.index_file}. Error: {exc}"
            ) from exc

    def _save_index(self) -> None:
        data = {
            artifact_id: artifact.to_dict()
            for artifact_id, artifact in self._artifacts.items()
        }

        temporary_path = f"{self.index_file}.tmp"

        with open(temporary_path, "w", encoding="utf-8") as handle:
            json.dump(
                data,
                handle,
                indent=2,
                sort_keys=True,
            )
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary_path, self.index_file)

    def _get_operation_dir(self, operation_id: str) -> str:
        operation_id = str(operation_id or "").strip()

        if not operation_id:
            raise ValueError("operation_id cannot be blank")

        return os.path.join(self.base_dir, operation_id)

    def create_operation_dir(
        self,
        operation_id: str,
    ) -> Tuple[str, str]:
        op_dir = self._get_operation_dir(operation_id)
        files_dir = os.path.join(op_dir, "files")

        os.makedirs(files_dir, exist_ok=True)

        return op_dir, files_dir

    def get_filename_for_artifact(
        self,
        operation_id: str,
        ext: str,
    ) -> str:
        _, files_dir = self.create_operation_dir(operation_id)

        extension = str(ext or "").strip()
        if extension and not extension.startswith("."):
            extension = f".{extension}"

        return os.path.join(
            files_dir,
            f"{uuid.uuid4()}{extension}",
        )

    def _operation_files_dir(self, operation_id: str) -> str:
        _, files_dir = self.create_operation_dir(operation_id)
        return os.path.realpath(files_dir)

    def _validate_managed_file(
        self,
        operation_id: str,
        file_path: str,
    ) -> Tuple[str, str]:
        """
        Validate a regular file and return:
            absolute real path
            path relative to the operation files directory
        """
        absolute_path = os.path.realpath(
            os.path.abspath(
                os.path.expanduser(
                    str(file_path or "").strip()
                )
            )
        )

        if not absolute_path:
            raise ValueError("Artifact file path cannot be blank")

        if not os.path.isfile(absolute_path):
            raise FileNotFoundError(
                f"Artifact file does not exist: {absolute_path}"
            )

        files_dir = self._operation_files_dir(operation_id)

        try:
            common = os.path.commonpath(
                [files_dir, absolute_path]
            )
        except ValueError as exc:
            raise ValueError(
                f"Artifact file is not under the operation files directory: "
                f"{absolute_path}"
            ) from exc

        if common != files_dir:
            raise ValueError(
                "Artifact files must be written directly into managed "
                f"operation storage. File: {absolute_path}; "
                f"expected root: {files_dir}"
            )

        relative_path = os.path.relpath(
            absolute_path,
            files_dir,
        )

        return absolute_path, relative_path

    def _normalize_relations(
        self,
        relations: Optional[
            Iterable[
                Union[
                    ArtifactRelation,
                    Dict[str, Any],
                    Tuple[str, str],
                    Tuple[str, str, str],
                ]
            ]
        ],
    ) -> List[ArtifactRelation]:
        normalized: List[ArtifactRelation] = []

        for relation in relations or []:
            if isinstance(relation, ArtifactRelation):
                item = relation

            elif isinstance(relation, dict):
                item = ArtifactRelation.from_dict(relation)

            elif isinstance(relation, (tuple, list)):
                if len(relation) == 2:
                    item = ArtifactRelation(
                        entity_type=relation[0],
                        entity_id=relation[1],
                    )
                elif len(relation) == 3:
                    item = ArtifactRelation(
                        entity_type=relation[0],
                        entity_id=relation[1],
                        role=relation[2],
                    )
                else:
                    raise ValueError(
                        "Artifact relation tuples must contain "
                        "2 or 3 values"
                    )
            else:
                raise TypeError(
                    f"Unsupported artifact relation type: "
                    f"{type(relation).__name__}"
                )

            if item.to_dict() not in [
                existing.to_dict()
                for existing in normalized
            ]:
                normalized.append(item)

        return normalized

    def _metadata_for_path(
        self,
        absolute_path: str,
        relative_path: str,
        file_metadata: Optional[Dict[str, Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """
        Match optional per-file metadata using, in order:
            absolute path
            relative path
            basename
        """
        if not file_metadata:
            return {}

        for key in (
            absolute_path,
            relative_path,
            os.path.basename(relative_path),
        ):
            value = file_metadata.get(key)
            if isinstance(value, dict):
                return dict(value)

        return {}

    def _build_artifact_file(
        self,
        operation_id: str,
        file_path: str,
        file_metadata: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> ArtifactFile:
        absolute_path, relative_path = self._validate_managed_file(
            operation_id,
            file_path,
        )

        supplied = self._metadata_for_path(
            absolute_path,
            relative_path,
            file_metadata,
        )

        role = str(
            supplied.pop("role", "payload")
            or "payload"
        ).strip()

        content_type = str(
            supplied.pop("content_type", "")
            or mimetypes.guess_type(absolute_path)[0]
            or "application/octet-stream"
        ).strip()

        return ArtifactFile(
            id=str(uuid.uuid4()),
            name=os.path.basename(relative_path),
            relative_path=relative_path,
            size=os.path.getsize(absolute_path),
            sha256=calculate_file_checksum(absolute_path),
            role=role,
            content_type=content_type,
            metadata=supplied,
        )

    def _normalize_files_argument(
        self,
        files: Union[
            str,
            os.PathLike,
            Iterable[Union[str, os.PathLike]],
        ],
    ) -> List[str]:
        if isinstance(files, (str, os.PathLike)):
            values = [files]
        else:
            values = list(files or [])

        normalized = [
            str(value)
            for value in values
            if str(value or "").strip()
        ]

        if not normalized:
            raise ValueError(
                "At least one artifact file is required"
            )

        return normalized

    def create_artifact(
        self,
        source_id: str,
        operation_id: str,
        files: Union[
            str,
            os.PathLike,
            Iterable[Union[str, os.PathLike]],
        ],
        name: str,
        artifact_type: str,
        metadata: Optional[Dict[str, Any]] = None,
        relations: Optional[Iterable[Any]] = None,
        file_metadata: Optional[Dict[str, Dict[str, Any]]] = None,
        artifact_id: str = "",
    ) -> str:
        """
        Register one logical artifact containing one or more managed files.

        Plugin authors pass file paths and optional domain metadata. This
        method creates the complete canonical file manifest.
        """
        source_id = str(source_id or "").strip()
        operation_id = str(operation_id or "").strip()
        name = str(name or "").strip()
        artifact_type = str(artifact_type or "").strip()

        if not source_id:
            raise ValueError("source_id cannot be blank")

        if not operation_id:
            raise ValueError("operation_id cannot be blank")

        if not name:
            raise ValueError("artifact name cannot be blank")

        if not artifact_type:
            raise ValueError("artifact_type cannot be blank")

        file_paths = self._normalize_files_argument(files)

        artifact_files = [
            self._build_artifact_file(
                operation_id=operation_id,
                file_path=file_path,
                file_metadata=file_metadata,
            )
            for file_path in file_paths
        ]

        created_at = datetime.now().isoformat()

        artifact = Artifact(
            id=str(artifact_id or uuid.uuid4()),
            source_id=source_id,
            operation_id=operation_id,
            name=name,
            artifact_type=artifact_type,
            created_at=created_at,
            modified_at=created_at,
            files=artifact_files,
            relations=self._normalize_relations(relations),
            metadata=dict(metadata or {}),
        )

        self._artifacts[artifact.id] = artifact
        self._save_index()

        self.logger.info(
            "Created artifact %s: %s (%s), files=%s total_size=%s",
            artifact.id,
            artifact.name,
            artifact.artifact_type,
            artifact.file_count,
            artifact.total_size,
        )

        return artifact.id

    def register_operation_artifact(
        self,
        source_id: str,
        operation_id: str,
        name: str,
        artifact_type: str,
        metadata: Optional[Dict[str, Any]] = None,
        relations: Optional[Iterable[Any]] = None,
        file_metadata: Optional[Dict[str, Dict[str, Any]]] = None,
        include_hidden: bool = False,
    ) -> str:
        """
        Register every completed regular file under one operation files
        directory as one logical artifact.
        """
        _, files_dir = self.create_operation_dir(operation_id)

        discovered: List[str] = []

        for root, directory_names, filenames in os.walk(files_dir):
            directory_names.sort()
            filenames.sort()

            for filename in filenames:
                if filename.endswith(".part"):
                    continue

                if not include_hidden and filename.startswith("."):
                    continue

                file_path = os.path.join(root, filename)

                if os.path.isfile(file_path):
                    discovered.append(file_path)

        if not discovered:
            raise ValueError(
                f"No completed files were found for operation "
                f"{operation_id}"
            )

        return self.create_artifact(
            source_id=source_id,
            operation_id=operation_id,
            files=discovered,
            name=name,
            artifact_type=artifact_type,
            metadata=metadata,
            relations=relations,
            file_metadata=file_metadata,
        )

    def get_artifact(
        self,
        artifact_id: str,
    ) -> Optional[Artifact]:
        return self._artifacts.get(
            str(artifact_id or "").strip()
        )

    def get_artifact_file(
        self,
        artifact_id: str,
        file_id: str,
    ) -> Optional[ArtifactFile]:
        artifact = self.get_artifact(artifact_id)

        if artifact is None:
            return None

        return artifact.get_file(file_id)

    def resolve_artifact_file_path(
        self,
        artifact_id: str,
        file_id: str,
    ) -> str:
        """
        Resolve a declared artifact file ID to a validated local path.
        """
        artifact = self.get_artifact(artifact_id)

        if artifact is None:
            raise KeyError(
                f"Artifact not found: {artifact_id}"
            )

        artifact_file = artifact.get_file(file_id)

        if artifact_file is None:
            raise KeyError(
                f"Artifact file not found: "
                f"artifact_id={artifact_id} file_id={file_id}"
            )

        _, files_dir = self.create_operation_dir(
            artifact.operation_id
        )

        candidate = os.path.realpath(
            os.path.join(
                files_dir,
                artifact_file.relative_path,
            )
        )

        validated_path, validated_relative_path = (
            self._validate_managed_file(
                artifact.operation_id,
                candidate,
            )
        )

        if validated_relative_path != artifact_file.relative_path:
            raise ValueError(
                "Artifact file resolved to an unexpected relative path"
            )

        return validated_path

    def get_artifacts_by_operation(
        self,
        operation_id: str,
    ) -> List[Artifact]:
        operation_id = str(operation_id or "").strip()

        return [
            artifact
            for artifact in self._artifacts.values()
            if artifact.operation_id == operation_id
        ]

    def get_all_artifacts(self) -> List[Artifact]:
        return list(self._artifacts.values())

    def update_artifact(
        self,
        artifact_id: str,
        *,
        files: Optional[
            Union[
                str,
                os.PathLike,
                Iterable[Union[str, os.PathLike]],
            ]
        ] = None,
        name: Optional[str] = None,
        artifact_type: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        relations: Optional[Iterable[Any]] = None,
        file_metadata: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> bool:
        artifact = self.get_artifact(artifact_id)

        if artifact is None:
            self.logger.error(
                "Artifact not found: %s",
                artifact_id,
            )
            return False

        if files is not None:
            artifact.files = [
                self._build_artifact_file(
                    operation_id=artifact.operation_id,
                    file_path=file_path,
                    file_metadata=file_metadata,
                )
                for file_path in self._normalize_files_argument(files)
            ]

        if name is not None:
            name_text = str(name or "").strip()
            if not name_text:
                raise ValueError("artifact name cannot be blank")
            artifact.name = name_text

        if artifact_type is not None:
            type_text = str(artifact_type or "").strip()
            if not type_text:
                raise ValueError("artifact_type cannot be blank")
            artifact.artifact_type = type_text

        if metadata:
            artifact.metadata.update(
                dict(metadata)
            )

        if relations is not None:
            artifact.relations = self._normalize_relations(
                relations
            )

        artifact.modified_at = datetime.now().isoformat()
        artifact.__post_init__()

        self._save_index()

        self.logger.info(
            "Updated artifact %s: %s",
            artifact.id,
            artifact.name,
        )

        return True

    def _file_referenced_by_other_artifact(
        self,
        artifact_id: str,
        operation_id: str,
        relative_path: str,
    ) -> bool:
        for other in self._artifacts.values():
            if other.id == artifact_id:
                continue

            if other.operation_id != operation_id:
                continue

            if any(
                item.relative_path == relative_path
                for item in other.files
            ):
                return True

        return False

    def delete_artifact(
        self,
        artifact_id: str,
        delete_files: bool = True,
    ) -> bool:
        artifact = self.get_artifact(artifact_id)

        if artifact is None:
            self.logger.error(
                "Artifact not found: %s",
                artifact_id,
            )
            return False

        if delete_files:
            for item in artifact.files:
                if self._file_referenced_by_other_artifact(
                    artifact.id,
                    artifact.operation_id,
                    item.relative_path,
                ):
                    continue

                try:
                    file_path = self.resolve_artifact_file_path(
                        artifact.id,
                        item.id,
                    )
                except FileNotFoundError:
                    continue
                except Exception as exc:
                    self.logger.error(
                        "Refusing to delete artifact file "
                        "artifact_id=%s file_id=%s: %s",
                        artifact.id,
                        item.id,
                        exc,
                    )
                    return False

                try:
                    os.remove(file_path)
                except FileNotFoundError:
                    pass
                except Exception as exc:
                    self.logger.error(
                        "Failed deleting artifact file %s: %s",
                        file_path,
                        exc,
                    )
                    return False

        del self._artifacts[artifact.id]
        self._save_index()

        self.logger.info(
            "Deleted artifact %s: %s",
            artifact.id,
            artifact.name,
        )

        return True

    def cleanup_operation(
        self,
        operation_id: str,
    ) -> int:
        artifacts = list(
            self.get_artifacts_by_operation(operation_id)
        )

        deleted_count = 0

        for artifact in artifacts:
            if self.delete_artifact(artifact.id):
                deleted_count += 1

        op_dir = self._get_operation_dir(operation_id)

        if os.path.isdir(op_dir):
            for root, directory_names, filenames in os.walk(
                op_dir,
                topdown=False,
            ):
                if filenames:
                    continue

                for directory_name in directory_names:
                    directory_path = os.path.join(
                        root,
                        directory_name,
                    )
                    try:
                        os.rmdir(directory_path)
                    except OSError:
                        pass

            try:
                os.rmdir(op_dir)
            except OSError:
                pass

        return deleted_count

    def create_zip_artifact_from_folder(
        self,
        source_id: str,
        operation_id: str,
        folder: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
        arc_prefix: Optional[str] = None,
        relations: Optional[Iterable[Any]] = None,
    ) -> str:
        """
        Create one persistent ZIP output and register that ZIP as the artifact.

        If folder is the managed operation files directory, the destination ZIP
        is skipped while walking so it is not added to itself.
        """
        source_folder = os.path.realpath(
            os.path.abspath(folder)
        )

        if not os.path.isdir(source_folder):
            raise NotADirectoryError(
                f"Artifact source folder does not exist: {source_folder}"
            )

        zip_path = self.get_filename_for_artifact(
            operation_id,
            ".zip",
        )
        zip_real = os.path.realpath(zip_path)

        with zipfile.ZipFile(
            zip_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as zip_handle:
            for root, directory_names, filenames in os.walk(
                source_folder
            ):
                directory_names.sort()
                filenames.sort()

                for filename in filenames:
                    full_path = os.path.realpath(
                        os.path.join(root, filename)
                    )

                    if full_path == zip_real:
                        continue

                    if filename.endswith(".part"):
                        continue

                    relative = os.path.relpath(
                        full_path,
                        source_folder,
                    )

                    archive_name = os.path.join(
                        arc_prefix or "",
                        relative,
                    )

                    zip_handle.write(
                        full_path,
                        arcname=archive_name,
                    )

        return self.create_artifact(
            source_id=source_id,
            operation_id=operation_id,
            files=[zip_path],
            name=name,
            artifact_type="application/zip",
            metadata=metadata,
            relations=relations,
            file_metadata={
                zip_path: {
                    "role": "bundle",
                    "content_type": "application/zip",
                }
            },
        )


class ArtifactTracker:
    """
    HIPRFISR's system-wide artifact metadata catalog.

    The tracker stores the same manifest-only Artifact records reported by
    Sensor Nodes. It does not read or write artifact payload bytes.
    """

    def __init__(
        self,
        base_dir: str = ARTIFACT_SYSTEM_DIR,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.base_dir = os.path.realpath(
            os.path.abspath(base_dir)
        )
        self.logger = logger or logging.getLogger(__name__)
        self.index_file = os.path.join(
            self.base_dir,
            "index.json",
        )

        os.makedirs(self.base_dir, exist_ok=True)

        self._artifacts = self._load_index()

    def _load_index(self) -> Dict[str, Artifact]:
        if not os.path.exists(self.index_file):
            return {}

        with open(self.index_file, "r", encoding="utf-8") as handle:
            data = json.load(handle)

        if not isinstance(data, dict):
            raise ValueError(
                f"Artifact tracker index must contain an object: "
                f"{self.index_file}"
            )

        try:
            return {
                str(artifact_id): Artifact.from_dict(record)
                for artifact_id, record in data.items()
            }
        except Exception as exc:
            raise RuntimeError(
                "Failed to load the artifact tracker using the new "
                "manifest-only schema. Delete the old index file and restart: "
                f"{self.index_file}. Error: {exc}"
            ) from exc

    def _save_index(self) -> None:
        data = {
            artifact_id: artifact.to_dict()
            for artifact_id, artifact in self._artifacts.items()
        }

        temporary_path = f"{self.index_file}.tmp"

        with open(temporary_path, "w", encoding="utf-8") as handle:
            json.dump(
                data,
                handle,
                indent=2,
                sort_keys=True,
            )
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary_path, self.index_file)

    def sync_index(
        self,
        artifacts: List[Union[Artifact, Dict[str, Any]]],
    ) -> None:
        for artifact in artifacts:
            self.add_artifact(
                artifact,
                update_index=False,
            )

        self._save_index()

    def add_artifact(
        self,
        artifact: Union[Artifact, Dict[str, Any]],
        update_index: bool = True,
    ) -> None:
        if isinstance(artifact, dict):
            artifact = Artifact.from_dict(artifact)

        existing = self._artifacts.get(artifact.id)

        if (
            existing is not None
            and existing.to_dict() == artifact.to_dict()
        ):
            return

        self._artifacts[artifact.id] = artifact

        if update_index:
            self._save_index()

        self.logger.info(
            "Artifact %s added to tracker",
            artifact.id,
        )

    def get_artifact(
        self,
        artifact_id: str,
    ) -> Optional[Artifact]:
        return self._artifacts.get(
            str(artifact_id or "").strip()
        )

    def get_all_artifacts(self) -> List[Artifact]:
        return list(self._artifacts.values())

    def update_artifact(
        self,
        artifact: Union[Artifact, Dict[str, Any]],
    ) -> bool:
        if isinstance(artifact, dict):
            artifact = Artifact.from_dict(artifact)

        self._artifacts[artifact.id] = artifact
        self._save_index()

        self.logger.info(
            "Updated artifact %s: %s",
            artifact.id,
            artifact.name,
        )

        return True

    def delete_artifact(
        self,
        artifact_id: str,
    ) -> bool:
        artifact_id = str(artifact_id or "").strip()

        if artifact_id not in self._artifacts:
            return False

        del self._artifacts[artifact_id]
        self._save_index()

        self.logger.info(
            "Deleted artifact %s from tracker",
            artifact_id,
        )

        return True

    def get_artifacts_source_id(
        self,
        source_id: str,
        sortby: Optional[str] = None,
    ) -> List[Artifact]:
        artifacts = [
            artifact
            for artifact in self._artifacts.values()
            if artifact.source_id == source_id
        ]

        if sortby is not None:
            artifacts = sorted(
                artifacts,
                key=lambda artifact: getattr(
                    artifact,
                    sortby,
                ),
            )

        return artifacts
    
    
# Global artifact manager instance
_artifact_manager = None

def get_artifact_manager() -> ArtifactManager:
    """Get the global artifact manager instance.
    
    Returns
    -------
    ArtifactManager
        The global artifact manager instance
    """
    global _artifact_manager
    if _artifact_manager is None:
        _artifact_manager = ArtifactManager()
    return _artifact_manager

