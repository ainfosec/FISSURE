#!/usr/bin/env python3
"""
TSI Feature Extractor Operation (headless)

Given a folder of IQ artifacts, or an explicit file list, compute a set of
selected time-domain and frequency-domain features per file.

Stop semantics
--------------
- If stop is requested, exit promptly and DO NOT write tsi_features.json.
  This prevents downstream stages from running on partial output.
"""

import asyncio
import hashlib
import inspect
import json
import logging
import os
import shutil
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

try:
    from scipy import stats
    from scipy.fft import fft, next_fast_len
except Exception:  # pragma: no cover
    stats = None
    fft = None
    next_fast_len = None


# -------------------------------------------------------------------
# Plugin/repo import bootstrap
# -------------------------------------------------------------------

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

try:
    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT
except ImportError:
    if FISSURE_REPO_ROOT not in sys.path:
        sys.path.insert(0, FISSURE_REPO_ROOT)
    if PLUGIN_ROOT not in sys.path:
        sys.path.insert(0, PLUGIN_ROOT)

    from fissure.utils.plugins.operations import Operation
    from fissure.utils import FISSURE_ROOT


# -------------------------------------------------------------------
# Defaults
# -------------------------------------------------------------------

TIME_DOMAIN_FEATURES = [
    "Mean",
    "Max",
    "Peak",
    "Peak to Peak",
    "RMS",
    "Variance",
    "Standard Deviation",
    "Power",
    "Crest Factor",
    "Pulse Indicator",
    "Margin",
    "Kurtosis",
    "Skewness",
    "Zero Crossings",
    "Samples",
]


FREQUENCY_DOMAIN_FEATURES = [
    "Mean of Band Power Spectrum",
    "Max of Band Power Spectrum",
    "Sum of Total Band Power",
    "Peak of Band Power",
    "Variance of Band Power",
    "Standard Deviation of Band Power",
    "Skewness of Band Power",
    "Kurtosis of Band Power",
    "Relative Spectral Peak per Band",
]


ALL_FEATURES = TIME_DOMAIN_FEATURES + FREQUENCY_DOMAIN_FEATURES


FEATURE_PROFILE_PRESETS = {
    "time_domain": {
        "core": [
            "Mean",
            "Max",
            "Peak",
            "RMS",
            "Variance",
            "Standard Deviation",
            "Power",
            "Samples",
        ],
        "statistical": [
            "Mean",
            "Variance",
            "Standard Deviation",
            "Kurtosis",
            "Skewness",
            "Zero Crossings",
            "Samples",
        ],
        "all": TIME_DOMAIN_FEATURES,
    },
    "frequency_domain": {
        "core": [
            "Mean of Band Power Spectrum",
            "Max of Band Power Spectrum",
            "Sum of Total Band Power",
            "Peak of Band Power",
            "Relative Spectral Peak per Band",
        ],
        "statistical": [
            "Mean of Band Power Spectrum",
            "Variance of Band Power",
            "Standard Deviation of Band Power",
            "Skewness of Band Power",
            "Kurtosis of Band Power",
        ],
        "all": FREQUENCY_DOMAIN_FEATURES,
    },
    "time_frequency": {
        "balanced": [
            "Mean",
            "Max",
            "Peak",
            "RMS",
            "Variance",
            "Standard Deviation",
            "Power",
            "Samples",
            "Mean of Band Power Spectrum",
            "Max of Band Power Spectrum",
            "Sum of Total Band Power",
            "Peak of Band Power",
            "Relative Spectral Peak per Band",
        ],
        "statistical": [
            "Mean",
            "Variance",
            "Standard Deviation",
            "Kurtosis",
            "Skewness",
            "Zero Crossings",
            "Samples",
            "Mean of Band Power Spectrum",
            "Variance of Band Power",
            "Standard Deviation of Band Power",
            "Skewness of Band Power",
            "Kurtosis of Band Power",
        ],
        "all": ALL_FEATURES,
    },
}


DEFAULTS: Dict[str, Any] = {
    "profile": "all",
    "preset": "all",
    "checkboxes": None,
    "features": "",
    "data_type": "Complex Float 32",
    "extensions": [".iq", ".bin", ".raw", ".dat"],
    "selection_sidecar": "selected_files.json",
}


FFT_FEATURES = set(FREQUENCY_DOMAIN_FEATURES)


# -------------------------------------------------------------------
# Generic helpers
# -------------------------------------------------------------------

def _json_safe(value: Any) -> Any:
    """
    Convert numpy/scipy scalar values into JSON-safe Python values.
    Non-finite floats are represented as None so downstream JSON parsers do not
    have to accept NaN/Infinity extensions.
    """
    if isinstance(value, np.generic):
        value = value.item()

    if isinstance(value, complex):
        value = float(np.real(value))

    if isinstance(value, float) and not np.isfinite(value):
        return None

    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}

    if isinstance(value, list):
        return [_json_safe(v) for v in value]

    return value


def _sha256_file(path: str, block_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(block_size)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _infer_artifact_id(folder: Optional[str], explicit_artifact_id: Optional[str] = None) -> str:
    if explicit_artifact_id:
        return str(explicit_artifact_id)

    if not folder:
        return ""

    folder_abs = os.path.abspath(folder)
    parts = folder_abs.split(os.sep)

    # Expected artifact file folder:
    #   <FISSURE_ROOT>/artifacts/<artifact_id>/files
    try:
        idx = parts.index("artifacts")
        if len(parts) > idx + 1:
            return parts[idx + 1]
    except ValueError:
        pass

    if os.path.basename(folder_abs) == "files":
        return os.path.basename(os.path.dirname(folder_abs))

    return ""


async def _set_status(callback, value: str, logger: logging.Logger) -> None:
    if callback is None:
        return

    try:
        result = callback(value)
        if inspect.isawaitable(result):
            await asyncio.wait_for(result, timeout=2.0)
    except Exception:
        logger.exception("status_callback failed")


def _normalize_profile_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = text.replace("+", " ")
    text = text.replace("-", " ")
    text = text.replace("_", " ")
    text = " ".join(text.split())

    aliases = {
        "time domain": "time_domain",
        "frequency domain": "frequency_domain",
        "time frequency": "time_frequency",
        "time and frequency": "time_frequency",
        "all": "all",
        "all available": "all",
        "custom": "custom",
    }

    return aliases.get(text, text.replace(" ", "_"))


def _normalize_preset_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = text.replace("+", " ")
    text = text.replace("-", " ")
    text = text.replace("_", " ")
    return "_".join(text.split())


def _parse_custom_features(value: Any) -> List[str]:
    if isinstance(value, list):
        requested = [
            str(item or "").strip()
            for item in value
            if str(item or "").strip()
        ]
    else:
        requested = [
            item.strip()
            for item in str(value or "").split(",")
            if item.strip()
        ]

    canonical_by_lower = {
        feature.lower(): feature
        for feature in ALL_FEATURES
    }

    selected: List[str] = []

    for requested_name in requested:
        canonical_name = canonical_by_lower.get(requested_name.lower())

        if canonical_name and canonical_name not in selected:
            selected.append(canonical_name)

    return selected


def resolve_feature_selection(
    profile: Any = DEFAULTS["profile"],
    preset: Any = DEFAULTS["preset"],
    checkboxes: Optional[List[str]] = None,
    features: Any = DEFAULTS["features"],
) -> List[str]:
    """
    Resolve the final operation feature list.

    Resolution priority:
        1. Explicit checkboxes supplied by an orchestrating action/workflow.
        2. Custom features supplied as a list or comma-separated string.
        3. Operation-owned profile/preset definitions.
        4. All supported features for legacy callers.
    """
    if checkboxes is not None:
        selected = _parse_custom_features(checkboxes)

        if not selected:
            raise ValueError(
                "No supported features were found in the explicit checkboxes list."
            )

        return selected

    normalized_profile = _normalize_profile_name(profile)

    if normalized_profile == "custom":
        selected = _parse_custom_features(features)

        if not selected:
            raise ValueError(
                "The custom Feature Extractor profile requires at least one "
                "supported feature name."
            )

        return selected

    if normalized_profile in {"", "all"}:
        return list(ALL_FEATURES)

    profile_presets = FEATURE_PROFILE_PRESETS.get(normalized_profile)

    if profile_presets is None:
        raise ValueError(
            f"Unsupported Feature Extractor profile: {profile!r}"
        )

    normalized_preset = _normalize_preset_name(preset)

    preset_aliases = {
        "all_time_domain": "all",
        "all_frequency_domain": "all",
        "all_time_frequency": "all",
        "all_available": "all",
        "core": "core",
        "balanced": "balanced",
        "statistical": "statistical",
        "all": "all",
    }

    normalized_preset = preset_aliases.get(
        normalized_preset,
        normalized_preset,
    )

    if normalized_preset not in profile_presets:
        normalized_preset = next(iter(profile_presets))

    return list(profile_presets[normalized_preset])


# -------------------------------------------------------------------
# IQ reading helpers
# -------------------------------------------------------------------

def _dtype_info(data_type: str) -> Tuple[np.dtype, bool]:
    """
    Returns (base_dtype, is_complex_interleaved).

    For complex interleaved formats, file is [I0, Q0, I1, Q1, ...] in base_dtype.
    """
    dt = (data_type or "").strip()

    if dt == "Complex Float 32":
        return (np.float32, True)
    if dt == "Complex Float 64":
        return (np.float64, True)
    if dt in ("Complex Int 16", "Short/Int 16"):
        return (np.int16, True)
    if dt in ("Complex Int 8", "Byte/Int 8"):
        return (np.int8, True)
    if dt == "Complex Int 64":
        return (np.int64, True)

    if dt == "Float/Float 32":
        return (np.float32, False)
    if dt == "Int/Int 32":
        return (np.int32, False)

    raise ValueError(f"Unsupported data_type: {data_type!r}")


def read_iq_file(path: str, data_type: str) -> np.ndarray:
    """
    Read an IQ artifact file into a numpy array.

    - If complex interleaved: returns complex array (complex64/complex128)
    - If real-only: returns real array
    """
    base_dtype, is_complex = _dtype_info(data_type)

    raw = np.fromfile(path, dtype=base_dtype)
    if raw.size == 0:
        return raw

    if is_complex:
        if raw.size < 2:
            return np.array([], dtype=np.complex64)

        if (raw.size % 2) != 0:
            raw = raw[:-1]

        if base_dtype == np.float64:
            return (raw[0::2] + 1j * raw[1::2]).astype(np.complex128, copy=False)

        i = raw[0::2].astype(np.float32, copy=False)
        q = raw[1::2].astype(np.float32, copy=False)
        return i + 1j * q

    return raw


# -------------------------------------------------------------------
# Feature extraction
# -------------------------------------------------------------------

def compute_features(
    x: np.ndarray,
    data_type: str,
    checkboxes: List[str],
) -> Dict[str, Union[int, float, None]]:
    """
    Compute selected features over x (complex or real).
    Returns {feature_name: value}.
    """
    out: Dict[str, Union[int, float, None]] = {}

    if x.size == 0:
        return out

    is_complex = np.iscomplexobj(x)

    need_fft = any(f in FFT_FEATURES for f in checkboxes)
    S = None
    if need_fft:
        if fft is None or next_fast_len is None:
            raise RuntimeError("scipy is required for FFT-based features (scipy.fft).")
        nfft = next_fast_len(len(x))
        ft = fft(x, nfft)
        S = (np.abs(ft) ** 2) / max(len(x), 1)

    def _as_float(v: Any) -> Optional[float]:
        if np.isscalar(v):
            if isinstance(v, (np.complex64, np.complex128, complex)):
                v = np.real(v)
            v = float(v)
            return v if np.isfinite(v) else None
        v = float(v)
        return v if np.isfinite(v) else None

    # Time Domain
    if "Mean" in checkboxes:
        out["Mean"] = _as_float(np.mean(x))

    if "Max" in checkboxes:
        out["Max"] = _as_float(np.max(np.abs(x)) if is_complex else np.max(x))

    if "Peak" in checkboxes:
        out["Peak"] = _as_float(np.max(np.abs(x)))

    if "Peak to Peak" in checkboxes:
        out["Peak to Peak"] = _as_float(np.ptp(np.abs(x)) if is_complex else np.ptp(x))

    if "RMS" in checkboxes:
        out["RMS"] = _as_float(np.sqrt(np.mean((np.abs(x) ** 2) if is_complex else (x ** 2))))

    if "Variance" in checkboxes:
        out["Variance"] = _as_float(np.var(x))

    if "Standard Deviation" in checkboxes:
        out["Standard Deviation"] = _as_float(np.std(x))

    if "Power" in checkboxes:
        out["Power"] = _as_float(np.mean((np.abs(x) ** 2) if is_complex else (x ** 2)))

    if "Crest Factor" in checkboxes:
        denom = np.sqrt(np.mean((np.abs(x) ** 2) if is_complex else (x ** 2)))
        out["Crest Factor"] = _as_float((np.max(np.abs(x)) / denom) if denom != 0 else 0.0)

    if "Pulse Indicator" in checkboxes:
        denom = np.mean(np.abs(x)) if is_complex else np.mean(x)
        out["Pulse Indicator"] = _as_float((np.max(np.abs(x)) / denom) if denom != 0 else 0.0)

    if "Margin" in checkboxes:
        denom = (np.abs(np.mean(np.sqrt(np.abs(x)))) ** 2) if is_complex else (abs(np.mean(np.sqrt(np.abs(x)))) ** 2)
        out["Margin"] = _as_float((np.max(np.abs(x)) / denom) if denom != 0 else 0.0)

    if "Kurtosis" in checkboxes:
        if stats is None:
            raise RuntimeError("scipy is required for kurtosis/skew features (scipy.stats).")
        v = np.abs(x) if is_complex else x
        out["Kurtosis"] = _as_float(stats.kurtosis(v))

    if "Skewness" in checkboxes:
        if stats is None:
            raise RuntimeError("scipy is required for kurtosis/skew features (scipy.stats).")
        v = np.abs(x) if is_complex else x
        out["Skewness"] = _as_float(stats.skew(v))

    if "Zero Crossings" in checkboxes:
        if is_complex:
            i = np.real(x)
            q = np.imag(x)
            zc_i = int(np.where(np.diff(np.sign(i)))[0].shape[0])
            zc_q = int(np.where(np.diff(np.sign(q)))[0].shape[0])
            out["Zero Crossings"] = zc_i + zc_q
        else:
            out["Zero Crossings"] = int(np.where(np.diff(np.sign(x)))[0].shape[0])

    if "Samples" in checkboxes:
        out["Samples"] = int(len(x))

    # Frequency Domain
    if S is not None:
        if "Mean of Band Power Spectrum" in checkboxes:
            out["Mean of Band Power Spectrum"] = _as_float(np.mean(S))
        if "Max of Band Power Spectrum" in checkboxes:
            out["Max of Band Power Spectrum"] = _as_float(np.max(S))
        if "Sum of Total Band Power" in checkboxes:
            out["Sum of Total Band Power"] = _as_float(np.sum(S))
        if "Peak of Band Power" in checkboxes:
            out["Peak of Band Power"] = _as_float(np.max(np.abs(S)))
        if "Variance of Band Power" in checkboxes:
            out["Variance of Band Power"] = _as_float(np.var(S))
        if "Standard Deviation of Band Power" in checkboxes:
            out["Standard Deviation of Band Power"] = _as_float(np.std(S))
        if "Skewness of Band Power" in checkboxes:
            if stats is None:
                raise RuntimeError("scipy is required for skew features (scipy.stats).")
            out["Skewness of Band Power"] = _as_float(stats.skew(S))
        if "Kurtosis of Band Power" in checkboxes:
            if stats is None:
                raise RuntimeError("scipy is required for kurtosis features (scipy.stats).")
            out["Kurtosis of Band Power"] = _as_float(stats.kurtosis(S))
        if "Relative Spectral Peak per Band" in checkboxes:
            denom = np.mean(S)
            out["Relative Spectral Peak per Band"] = _as_float((np.max(S) / denom) if denom != 0 else 0.0)

    return out


def resolve_files_from_folder(folder: str, extensions: List[str]) -> List[str]:
    out: List[str] = []
    try:
        for name in os.listdir(folder):
            p = os.path.join(folder, name)
            if os.path.isfile(p) and any(name.lower().endswith(ext) for ext in extensions):
                out.append(p)
    except FileNotFoundError:
        return []
    return sorted(out)


def _resolve_sidecar_files(sidecar_path: str) -> List[str]:
    with open(sidecar_path, "r", encoding="utf-8") as f:
        blob = json.load(f)

    selected = blob.get("selected", [])
    if not isinstance(selected, list):
        return []

    base_dir = os.path.dirname(sidecar_path)
    out: List[str] = []
    for item in selected:
        if not isinstance(item, str):
            continue
        p = item if os.path.isabs(item) else os.path.join(base_dir, item)
        if os.path.isfile(p):
            out.append(os.path.abspath(p))
    return out


# -------------------------------------------------------------------
# Operation Implementation
# -------------------------------------------------------------------

class OperationMain(Operation):
    def __init__(
        self,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback=None,
        tak_cot_callback=None,
        status_callback=None,
        soi_callback=None,
        artifact_manager=None,
        source_id: Optional[str] = None,
        artifact_id: Optional[str] = None,

        operation_id: str = "",
        source_operation_id: str = "",
        destination: str = "Local Results",
        description: str = "",
        soi_id: str = "",
        soi_key: str = "",
        frequency_mhz: Any = None,
        managed_input: Optional[Dict[str, Any]] = None,

        folder: Optional[str] = None,
        files: Optional[List[str]] = None,
        data_type: str = DEFAULTS["data_type"],
        profile: str = DEFAULTS["profile"],
        preset: str = DEFAULTS["preset"],
        checkboxes: Optional[List[str]] = DEFAULTS["checkboxes"],
        features: Any = DEFAULTS["features"],
        extensions: Optional[List[str]] = None,
        selection_sidecar: str = DEFAULTS["selection_sidecar"],
    ):
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            status_callback=status_callback,
            soi_callback=soi_callback,
            artifact_manager=artifact_manager,
        )


        if operation_id:
            self.opid = str(operation_id)

        self.source_id = source_id or node_uid or "sensor_node"
        self.artifact_id = str(artifact_id or "").strip()
        self.source_operation_id = str(source_operation_id or "").strip()

        self.destination = str(destination or "Local Results").strip()
        self.description = str(description or "").strip()
        self.soi_id = str(soi_id or "").strip()
        self.soi_key = str(soi_key or "").strip()
        self.frequency_mhz = frequency_mhz
        self.managed_input = (
            dict(managed_input)
            if isinstance(managed_input, dict)
            else {}
        )

        self.folder = folder
        self.files = files
        self.data_type = data_type
        self.profile = profile
        self.preset = preset
        self.checkboxes = checkboxes
        self.features = features
        self.extensions = (
            extensions
            if extensions is not None
            else list(DEFAULTS["extensions"])
        )
        self.selection_sidecar = selection_sidecar

        self.output_path: str = ""
        self.report_path: str = ""
        self.feature_results: List[Dict[str, Any]] = []
        self.report_payload: Dict[str, Any] = {}

    @staticmethod
    def _artifact_id_value(artifact: Any) -> str:
        """
        Normalizes ArtifactManager return values.

        ArtifactManager implementations may return an artifact object or the
        artifact ID directly.
        """
        if not artifact:
            return ""

        return str(
            getattr(
                artifact,
                "id",
                artifact,
            )
            or ""
        ).strip()

    @staticmethod
    def _safe_extract_zip(
        archive_path: str,
        extraction_folder: str,
    ) -> None:
        """
        Extracts one node-local Artifact ZIP while rejecting path traversal.
        """
        import zipfile

        archive_path = os.path.abspath(archive_path)
        extraction_folder = os.path.abspath(extraction_folder)
        os.makedirs(extraction_folder, exist_ok=True)

        extraction_root = extraction_folder + os.sep

        with zipfile.ZipFile(archive_path, "r") as archive:
            for member in archive.infolist():
                member_path = os.path.abspath(
                    os.path.join(
                        extraction_folder,
                        member.filename,
                    )
                )

                if not (
                    member_path == extraction_folder
                    or member_path.startswith(extraction_root)
                ):
                    raise ValueError(
                        "Artifact ZIP contains an unsafe path: "
                        f"{member.filename!r}"
                    )

            archive.extractall(extraction_folder)


    @staticmethod
    def _managed_artifact_candidate_roots(
        self,
        artifact_id: str,
        operation_id: str,
    ) -> List[str]:
        """
        Legacy directory guessing is intentionally removed.

        Managed Artifact input is resolved only through ArtifactManager and the
        artifact's declared files manifest.
        """
        return []


    @staticmethod
    def _managed_selected_names(
        artifact_record: Dict[str, Any],
    ) -> List[str]:
        """
        Returns the requested Artifact member names from the control payload.
        """
        selected_names: List[str] = []

        selected_files = artifact_record.get(
            "selected_files",
            [],
        )

        if not isinstance(selected_files, list):
            selected_files = []

        for file_record in selected_files:
            if isinstance(file_record, dict):
                name = str(
                    file_record.get("name")
                    or file_record.get("filename")
                    or file_record.get("file_name")
                    or ""
                ).strip()
            else:
                name = str(file_record or "").strip()

            if name and name not in selected_names:
                selected_names.append(name)

        return selected_names


    def _resolve_node_local_managed_input(
        self,
        managed_input: Dict[str, Any],
    ) -> Tuple[List[str], Optional[str]]:
        """
        Resolve selected Artifact/SOI files through ArtifactManager.

        The request contains artifact IDs and optional selected file IDs/names.
        No filesystem guessing, Dashboard path, or remote absolute path is used.
        """
        if not isinstance(managed_input, dict) or not managed_input:
            return [], None

        if self.artifact_manager is None:
            raise RuntimeError(
                "Managed Artifact input requires artifact_manager."
            )

        artifact_records = managed_input.get("artifacts", [])

        if not isinstance(artifact_records, list):
            artifact_records = []

        if not artifact_records:
            artifact_ids = managed_input.get("artifact_ids", [])

            if not isinstance(artifact_ids, list):
                artifact_ids = [artifact_ids]

            artifact_records = [
                {
                    "artifact_id": artifact_id,
                    "selected_files": [],
                }
                for artifact_id in artifact_ids
                if str(artifact_id or "").strip()
            ]

        resolved_files: List[str] = []
        resolved_seen = set()
        first_parent: Optional[str] = None
        missing_artifacts: List[str] = []
        missing_members: List[str] = []

        for artifact_record in artifact_records:
            if not isinstance(artifact_record, dict):
                continue

            artifact_id = str(
                artifact_record.get("artifact_id", "")
                or artifact_record.get("id", "")
                or ""
            ).strip()

            if not artifact_id:
                continue

            artifact = self.artifact_manager.get_artifact(artifact_id)

            if artifact is None:
                missing_artifacts.append(artifact_id)
                continue

            selected_files = artifact_record.get("selected_files", [])

            if not isinstance(selected_files, list):
                selected_files = []

            selected_ids = set()
            selected_names = set()

            for selected in selected_files:
                if isinstance(selected, dict):
                    file_id = str(
                        selected.get("file_id")
                        or selected.get("id")
                        or ""
                    ).strip()
                    file_name = str(
                        selected.get("name")
                        or selected.get("filename")
                        or selected.get("file_name")
                        or ""
                    ).strip()
                else:
                    file_id = ""
                    file_name = str(selected or "").strip()

                if file_id:
                    selected_ids.add(file_id)

                if file_name:
                    selected_names.add(file_name)

            matched_ids = set()
            matched_names = set()

            for artifact_file in artifact.files:
                if selected_ids or selected_names:
                    if (
                        artifact_file.id not in selected_ids
                        and artifact_file.name not in selected_names
                        and artifact_file.relative_path not in selected_names
                    ):
                        continue

                try:
                    file_path = self.artifact_manager.resolve_artifact_file_path(
                        artifact.id,
                        artifact_file.id,
                    )
                except Exception as exc:
                    self.logger.warning(
                        "Unable to resolve Artifact file "
                        "artifact_id=%s file_id=%s: %s",
                        artifact.id,
                        artifact_file.id,
                        exc,
                    )
                    continue

                if not os.path.isfile(file_path):
                    continue

                if artifact_file.id in selected_ids:
                    matched_ids.add(artifact_file.id)

                if artifact_file.name in selected_names:
                    matched_names.add(artifact_file.name)

                if artifact_file.relative_path in selected_names:
                    matched_names.add(artifact_file.relative_path)

                if file_path not in resolved_seen:
                    resolved_seen.add(file_path)
                    resolved_files.append(file_path)

                    if first_parent is None:
                        first_parent = os.path.dirname(file_path)

            missing_members.extend(
                f"{artifact_id}:{file_id}"
                for file_id in sorted(selected_ids - matched_ids)
            )
            missing_members.extend(
                f"{artifact_id}:{name}"
                for name in sorted(selected_names - matched_names)
            )

        if missing_artifacts:
            raise RuntimeError(
                "Artifact metadata is not available on the selected Sensor Node: "
                + ", ".join(missing_artifacts)
            )

        if missing_members:
            raise RuntimeError(
                "Selected Artifact files are not available on the selected "
                "Sensor Node: "
                + ", ".join(missing_members)
            )

        if not resolved_files:
            raise RuntimeError(
                "No node-local files resolved from the selected Artifact/SOI input."
            )

        return resolved_files, first_parent


    def _copy_source_iq_files(
        self,
        resolved_files: List[str],
        source_folder: str,
    ) -> List[Dict[str, Any]]:
        """
        Copies selected IQ files into managed source-artifact storage.

        A matching SigMF metadata sidecar is copied automatically whenever a
        selected input ends in .sigmf-data.
        """
        os.makedirs(source_folder, exist_ok=True)

        copied_records: List[Dict[str, Any]] = []
        copied_paths = set()

        def _copy_one(source_path: str, role: str) -> None:
            source_path = os.path.abspath(source_path)

            if (
                not os.path.isfile(source_path)
                or source_path in copied_paths
            ):
                return

            basename = os.path.basename(source_path)
            destination_path = os.path.join(
                source_folder,
                basename,
            )

            if (
                os.path.exists(destination_path)
                and os.path.abspath(destination_path) != source_path
            ):
                root, extension = os.path.splitext(basename)
                destination_path = os.path.join(
                    source_folder,
                    f"{root}_{uuid.uuid4().hex[:8]}{extension}",
                )

            shutil.copy2(source_path, destination_path)
            copied_paths.add(source_path)

            copied_records.append(
                {
                    "role": role,
                    "name": os.path.basename(destination_path),
                    "path": destination_path,
                    "source_path": source_path,
                    "size_bytes": os.path.getsize(destination_path),
                    "sha256": _sha256_file(destination_path),
                }
            )

        for input_path in resolved_files:
            _copy_one(input_path, "source_iq")

            if str(input_path).endswith(".sigmf-data"):
                sidecar_path = (
                    str(input_path)[:-len(".sigmf-data")]
                    + ".sigmf-meta"
                )
                _copy_one(
                    sidecar_path,
                    "sigmf_metadata",
                )

        return copied_records

    async def _attach_artifacts_to_soi(
        self,
        *,
        node_uid: str,
        soi_id: str,
        frequency_mhz: Any,
        source_artifact_id: str,
        analysis_artifact_id: str,
        report_payload: Dict[str, Any],
    ) -> None:
        """
        Publishes one SOI update containing both durable artifact relationships.
        """
        callback = getattr(self, "soi_callback", None)

        if not callback:
            raise RuntimeError(
                "Attach to Existing SOI requires soi_callback."
            )

        try:
            frequency_value = (
                float(frequency_mhz)
                if frequency_mhz not in [None, "", "None"]
                else 0.0
            )
        except Exception:
            frequency_value = 0.0

        artifact_links = [
            {
                "artifact_id": source_artifact_id,
                "role": "source_iq",
                "operation_id": self.source_operation_id,
            },
            {
                "artifact_id": analysis_artifact_id,
                "role": "feature_analysis",
                "operation_id": self.opid,
                "source_artifact_id": source_artifact_id,
            },
        ]

        result = callback(
            node_uid=node_uid,
            soi_id=soi_id,
            frequency_mhz=frequency_value,
            status="ANALYSIS_ATTACHED",
            operation_id=self.opid,
            artifact_id=analysis_artifact_id,
            summary={
                "stage": "feature_analysis_attached",
                "stage_order": 60,
                "artifact_links": artifact_links,
                "source_artifact_id": source_artifact_id,
                "analysis_artifact_id": analysis_artifact_id,
                "feature_profile": report_payload.get("profile", ""),
                "feature_preset": report_payload.get("preset", ""),
                "feature_count": report_payload.get("feature_count", 0),
                "result_count": report_payload.get("result_count", 0),
                "description": report_payload.get("description", ""),
            },
            lat=True,
            lon=True,
            alt=True,
            observation_time=True,
        )

        if inspect.isawaitable(result):
            await asyncio.wait_for(result, timeout=2.0)

    async def _create_soi_with_artifacts(
        self,
        *,
        node_uid: str,
        frequency_mhz: Any,
        source_artifact_id: str,
        analysis_artifact_id: str,
        report_payload: Dict[str, Any],
    ) -> str:
        """
        Creates a new SOI after both managed artifacts have been registered.

        Returns:
            The generated SOI ID.
        """
        callback = getattr(
            self,
            "soi_callback",
            None,
        )

        if not callback:
            raise RuntimeError(
                "Create New SOI from Input requires soi_callback."
            )

        try:
            frequency_value = float(frequency_mhz)
        except Exception as error:
            raise ValueError(
                "Create New SOI from Input requires a valid frequency."
            ) from error

        if frequency_value <= 0:
            raise ValueError(
                "Create New SOI from Input requires a frequency "
                "greater than 0 MHz."
            )

        new_soi_id = str(uuid.uuid4())

        artifact_links = [
            {
                "artifact_id": source_artifact_id,
                "role": "source_iq",
                "operation_id": self.source_operation_id,
            },
            {
                "artifact_id": analysis_artifact_id,
                "role": "feature_analysis",
                "operation_id": self.opid,
                "source_artifact_id": source_artifact_id,
            },
        ]

        result = callback(
            node_uid=node_uid,
            soi_id=new_soi_id,
            frequency_mhz=frequency_value,
            status="ANALYSIS_ATTACHED",
            operation_id=self.opid,
            artifact_id=analysis_artifact_id,
            summary={
                "stage": "feature_analysis_attached",
                "stage_order": 60,
                "created_by": "feature_extractor",
                "artifact_links": artifact_links,
                "source_artifact_id": source_artifact_id,
                "analysis_artifact_id": analysis_artifact_id,
                "feature_profile": report_payload.get(
                    "profile",
                    "",
                ),
                "feature_preset": report_payload.get(
                    "preset",
                    "",
                ),
                "feature_count": report_payload.get(
                    "feature_count",
                    0,
                ),
                "result_count": report_payload.get(
                    "result_count",
                    0,
                ),
                "description": report_payload.get(
                    "description",
                    "",
                ),
            },
            lat=True,
            lon=True,
            alt=True,
            observation_time=True,
        )

        if inspect.isawaitable(result):
            await asyncio.wait_for(
                result,
                timeout=2.0,
            )

        return new_soi_id

    async def run(self) -> None:
        status_callback = getattr(self, "status_callback", None)
        params: Dict[str, Any] = getattr(self, "parameters", {}) or {}
        started_at = time.time()

        node_uid = str(
            params.get("node_uid", self.node_uid)
            or self.node_uid
            or ""
        )

        source_id = str(
            params.get("source_id", self.source_id)
            or node_uid
            or "sensor_node"
        )


        input_folder = params.get("folder", self.folder)
        files = params.get("files", self.files)
        data_type = params.get("data_type", self.data_type)
        profile = params.get("profile", self.profile)
        preset = params.get("preset", self.preset)
        checkboxes = params.get("checkboxes", self.checkboxes)
        features = params.get("features", self.features)
        extensions = params.get("extensions", self.extensions)
        sidecar_name = params.get(
            "selection_sidecar",
            self.selection_sidecar,
        )

        destination = str(
            params.get("destination", self.destination)
            or "Local Results"
        ).strip()

        description = str(
            params.get("description", self.description)
            or ""
        ).strip()

        soi_id = str(
            params.get("soi_id", self.soi_id)
            or ""
        ).strip()

        soi_key = str(
            params.get("soi_key", self.soi_key)
            or ""
        ).strip()

        frequency_mhz = params.get(
            "frequency_mhz",
            self.frequency_mhz,
        )

        managed_input = params.get(
            "managed_input",
            self.managed_input,
        )

        if not isinstance(managed_input, dict):
            managed_input = {}
        
        requested_operation_id = str(
            params.get("operation_id", "")
            or ""
        ).strip()

        if requested_operation_id:
            self.opid = requested_operation_id

        source_operation_id = str(
            params.get(
                "source_operation_id",
                self.source_operation_id,
            )
            or ""
        ).strip()

        if source_operation_id:
            self.source_operation_id = source_operation_id

        artifact_id = str(
            params.get("artifact_id", self.artifact_id)
            or ""
        ).strip()

        checkboxes = resolve_feature_selection(
            profile=profile,
            preset=preset,
            checkboxes=checkboxes,
            features=features,
        )

        if extensions is None:
            extensions = list(DEFAULTS["extensions"])

        input_folder = (
            os.path.abspath(input_folder)
            if isinstance(input_folder, str) and input_folder
            else None
        )

        resolved_files: List[str] = []
        wrote_features = False

        try:
            await _set_status(
                status_callback,
                "Running: Feature Extraction",
                self.logger,
            )

            if managed_input:
                (
                    resolved_files,
                    managed_parent,
                ) = self._resolve_node_local_managed_input(
                    managed_input
                )

                if managed_parent:
                    input_folder = managed_parent

                self.logger.info(
                    "Resolved managed %s input on Sensor Node: "
                    "artifacts=%r files=%d",
                    managed_input.get("source", "Artifact"),
                    managed_input.get("artifact_ids", []),
                    len(resolved_files),
                )

            elif files and isinstance(files, list):
                for filepath in files:
                    if not isinstance(filepath, str):
                        continue

                    path = os.path.abspath(filepath)

                    if os.path.isfile(path):
                        resolved_files.append(path)

                if not input_folder and resolved_files:
                    input_folder = os.path.dirname(
                        resolved_files[0]
                    )

            elif input_folder and isinstance(input_folder, str):
                sidecar_path = os.path.join(
                    input_folder,
                    sidecar_name,
                )

                if os.path.isfile(sidecar_path):
                    try:
                        resolved_files = _resolve_sidecar_files(
                            sidecar_path
                        )
                    except Exception as e:
                        self.logger.warning(
                            "Failed reading sidecar %s: %r",
                            sidecar_path,
                            e,
                        )

                if not resolved_files:
                    resolved_files = resolve_files_from_folder(
                        input_folder,
                        extensions,
                    )

            else:
                if self.artifact_manager is None:
                    raise RuntimeError(
                        "Managed Feature Extractor input requires artifact_manager."
                    )

                _, input_folder = self.artifact_manager.create_operation_dir(
                    self.opid
                )

                resolved_files = resolve_files_from_folder(
                    input_folder,
                    extensions,
                )

            if not resolved_files:
                self.logger.warning(
                    "No input files resolved "
                    "(input_folder=%r).",
                    input_folder,
                )
                return
            
            input_source = str(
                params.get("input_source")
                or managed_input.get("source")
                or (
                    "Folder"
                    if len(resolved_files) > 1
                    else "File"
                )
            ).strip()

            source_artifact_ids = (
                params.get("source_artifact_ids")
                or managed_input.get("artifact_ids")
                or []
            )

            if not isinstance(source_artifact_ids, list):
                source_artifact_ids = [
                    source_artifact_ids
                ]

            source_artifact_ids = [
                str(artifact_id or "").strip()
                for artifact_id in source_artifact_ids
                if str(artifact_id or "").strip()
            ]

            source_artifact_id = str(
                params.get("source_artifact_id")
                or (
                    source_artifact_ids[0]
                    if len(source_artifact_ids) == 1
                    else ""
                )
                or ""
            ).strip()

            input_soi_id = str(
                params.get("input_soi_id")
                or managed_input.get("input_soi_id")
                or ""
            ).strip()

            input_soi_key = str(
                params.get("input_soi_key")
                or managed_input.get("input_soi_key")
                or ""
            ).strip()

            managed_analysis_destinations = {
                "New Analysis Artifact",
                "Attach to Existing SOI",
                "Create New SOI from Input",
            }

            if destination in managed_analysis_destinations:
                if not getattr(self, "artifact_manager", None):
                    raise RuntimeError(
                        f"{destination} requires artifact_manager."
                    )

                _, output_folder = self.artifact_manager.create_operation_dir(
                    self.opid
                )

                artifact_id = ""
            else:
                output_folder = input_folder

                if not artifact_id:
                    artifact_id = _infer_artifact_id(
                        input_folder
                    )

            self.artifact_id = artifact_id

            source_artifact_id = ""
            analysis_artifact_id = ""

            self.logger.info(
                "TSI FE: destination=%r, profile=%r, preset=%r, "
                "data_type=%r, features=%d, files=%d, "
                "input_folder=%r, output_folder=%r, operation_id=%r",
                destination,
                profile,
                preset,
                data_type,
                len(checkboxes),
                len(resolved_files),
                input_folder,
                output_folder,
                self.opid,
            )

            await _set_status(
                status_callback,
                f"Running: Feature Extraction ({len(resolved_files)} files)",
                self.logger,
            )

            results: List[Dict[str, Any]] = []

            for index, path in enumerate(
                resolved_files,
                start=1,
            ):
                if self._stop:
                    self.logger.info(
                        "Stop requested; terminating feature extraction early."
                    )
                    return

                try:
                    st = os.stat(path)
                    iq_data = read_iq_file(
                        path,
                        data_type=data_type,
                    )
                    extracted_features = compute_features(
                        iq_data,
                        data_type=data_type,
                        checkboxes=checkboxes,
                    )

                    results.append(
                        {
                            "file": os.path.basename(path),
                            "path": path,
                            "data_type": data_type,
                            "size_bytes": int(st.st_size),
                            "mtime": float(st.st_mtime),
                            "sha256": _sha256_file(path),
                            "features": _json_safe(
                                extracted_features
                            ),
                        }
                    )

                except Exception as e:
                    self.logger.error(
                        "Feature extraction failed for %s: %r",
                        path,
                        e,
                    )

                    results.append(
                        {
                            "file": os.path.basename(path),
                            "path": path,
                            "data_type": data_type,
                            "error": repr(e),
                        }
                    )

                if index < len(resolved_files):
                    await asyncio.sleep(0)

            if self._stop:
                self.logger.info(
                    "Stop requested; skipping tsi_features.json write."
                )
                return

            self.feature_results = results

            if not output_folder:
                raise RuntimeError(
                    "Feature Extractor output folder could not be resolved."
                )

            os.makedirs(output_folder, exist_ok=True)

            out_path = os.path.join(
                output_folder,
                "tsi_features.json",
            )

            with open(
                out_path,
                "w",
                encoding="utf-8",
            ) as feature_file:
                json.dump(
                    _json_safe(results),
                    feature_file,
                    indent=2,
                    allow_nan=False,
                )

            self.output_path = out_path
            wrote_features = True

            self.logger.info(
                "Wrote feature output: %s",
                out_path,
            )

            source_file_records: List[Dict[str, Any]] = []

            if destination in {
                "Attach to Existing SOI",
                "Create New SOI from Input",
            }:
                if (
                    destination == "Attach to Existing SOI"
                    and not soi_id
                ):
                    raise ValueError(
                        "Attach to Existing SOI requires soi_id."
                    )

                if not self.source_operation_id:
                    self.source_operation_id = str(uuid.uuid4())

                _, source_folder = self.artifact_manager.create_operation_dir(
                    self.source_operation_id
                )

                source_file_records = self._copy_source_iq_files(
                    resolved_files,
                    source_folder,
                )

                if not source_file_records:
                    raise RuntimeError(
                        "No source IQ files were copied into "
                        "managed artifact storage."
                    )

                source_metadata = {
                    "kind": "artifact",
                    "event_type": "artifact",
                    "role": "source_iq_v1",
                    "node_uid": node_uid,
                    "source_id": source_id,
                    "operation_id": self.source_operation_id,
                    "target_soi_id": soi_id,
                    "target_soi_key": soi_key,
                    "creates_new_soi": (
                        destination
                        == "Create New SOI from Input"
                    ),
                    "frequency_mhz": frequency_mhz,
                    "description": (
                        description
                        or "Feature Extractor source IQ"
                    ),
                    "data_type": data_type,
                    "file_count": len(source_file_records),
                    "files": source_file_records,
                }

                source_artifact = (
                    self.artifact_manager
                    .create_zip_artifact_from_folder(
                        source_id=source_id,
                        operation_id=self.source_operation_id,
                        folder=source_folder,
                        name=(
                            "SOI Source IQ"
                            + (
                                f" - {description}"
                                if description
                                else ""
                            )
                        ),
                        metadata=_json_safe(source_metadata),
                        relations=(
                            [
                                (
                                    "soi",
                                    soi_id,
                                    "source_iq",
                                )
                            ]
                            if soi_id
                            else []
                        ),
                        arc_prefix=(
                            "source_iq_"
                            f"{self.source_operation_id}"
                        ),
                    )
                )

                source_artifact_id = self._artifact_id_value(
                    source_artifact
                )

                if not source_artifact_id:
                    raise RuntimeError(
                        "Source IQ artifact registration did not "
                        "return an artifact ID."
                    )

            report_payload = {
                "kind": "feature_analysis",
                "event_type": "feature_extraction",
                "role": "feature_analysis_v1",
                "node_uid": node_uid,
                "source_id": source_id,
                "operation_id": self.opid,
                "artifact_id": artifact_id,
                "destination": destination,
                "description": description,
                "input_folder": input_folder,
                "managed_input_source": str(
                    managed_input.get("source", "")
                    or ""
                ).strip(),
                "source_artifact_ids": list(
                    managed_input.get("artifact_ids", [])
                    if isinstance(
                        managed_input.get("artifact_ids", []),
                        list,
                    )
                    else []
                ),
                "input_soi_id": str(
                    managed_input.get("input_soi_id", "")
                    or params.get("input_soi_id", "")
                    or ""
                ).strip(),
                "input_soi_key": str(
                    managed_input.get("input_soi_key", "")
                    or params.get("input_soi_key", "")
                    or ""
                ).strip(),
                "folder": output_folder,
                "feature_file": out_path,
                "data_type": data_type,
                "profile": _normalize_profile_name(profile),
                "preset": _normalize_preset_name(preset),
                "features": list(checkboxes),
                "feature_count": len(checkboxes),
                "input_count": len(resolved_files),
                "result_count": len(results),
                "error_count": len(
                    [
                        result
                        for result in results
                        if "error" in result
                    ]
                ),
                "errors": [
                    result
                    for result in results
                    if "error" in result
                ],
                "target_soi_id": soi_id,
                "target_soi_key": soi_key,
                "source_operation_id": self.source_operation_id,
                "source_artifact_id": source_artifact_id,
                "source_files": source_file_records,
                "artifact_links": (
                    [
                        {
                            "artifact_id": source_artifact_id,
                            "role": "source_iq",
                            "operation_id": self.source_operation_id,
                        }
                    ]
                    if source_artifact_id
                    else []
                ),
                "creates_new_soi": (
                    destination
                    == "Create New SOI from Input"
                ),
                "started_at": started_at,
                "completed_at": None,
                "duration_s": None,
            }

            report_path = os.path.join(
                output_folder,
                "feature_extraction_report.json",
            )

            with open(
                report_path,
                "w",
                encoding="utf-8",
            ) as report_file:
                json.dump(
                    _json_safe(report_payload),
                    report_file,
                    indent=2,
                    allow_nan=False,
                )

            self.report_path = report_path

            if destination in managed_analysis_destinations:
                artifact_name = (
                    description
                    or "Feature Extraction Analysis"
                )

                analysis_artifact = (
                    self.artifact_manager
                    .create_zip_artifact_from_folder(
                        source_id=source_id,
                        operation_id=self.opid,
                        folder=output_folder,
                        name=artifact_name,
                        metadata=_json_safe({
                            "workflow": "feature_extractor",
                            "status": "completed",
                            "operation_id": self.opid,
                            "destination": destination,
                            "profile": _normalize_profile_name(profile),
                            "preset": _normalize_preset_name(preset),
                            "input_source": input_source,
                            "source_artifact_id": source_artifact_id,
                            "source_artifact_ids": source_artifact_ids,
                            "input_soi_id": input_soi_id,
                            "input_soi_key": input_soi_key,
                            "target_soi_id": soi_id,
                            "result_count": len(results),
                            "error_count": len([
                                result
                                for result in results
                                if "error" in result
                            ]),
                            "feature_count": len(checkboxes),
                            "feature_file": "tsi_features.json",
                            "report_file": "feature_extraction_report.json",
                            "started_at": started_at,
                            "completed_at": time.time(),
                        }),
                        arc_prefix=(
                            "feature_analysis_"
                            f"{self.opid}"
                        ),
                    )
                )

                analysis_artifact_id = self._artifact_id_value(
                    analysis_artifact
                )

                if not analysis_artifact_id:
                    analysis_artifact_id = self.opid

                self.artifact_id = analysis_artifact_id
                report_payload["artifact_id"] = analysis_artifact_id

                if destination in {
                    "Attach to Existing SOI",
                    "Create New SOI from Input",
                }:
                    report_payload[
                        "analysis_artifact_id"
                    ] = analysis_artifact_id

                    report_payload[
                        "artifact_links"
                    ].append(
                        {
                            "artifact_id":
                                analysis_artifact_id,
                            "role":
                                "feature_analysis",
                            "operation_id":
                                self.opid,
                            "source_artifact_id":
                                source_artifact_id,
                        }
                    )

                with open(
                    report_path,
                    "w",
                    encoding="utf-8",
                ) as report_file:
                    json.dump(
                        _json_safe(report_payload),
                        report_file,
                        indent=2,
                        allow_nan=False,
                    )

                self.logger.info(
                    "Registered Feature Analysis artifact: "
                    "artifact_id=%r, operation_id=%r, folder=%r",
                    analysis_artifact_id,
                    self.opid,
                    output_folder,
                )

                if destination == "Attach to Existing SOI":
                    await self._attach_artifacts_to_soi(
                        node_uid=node_uid,
                        soi_id=soi_id,
                        frequency_mhz=frequency_mhz,
                        source_artifact_id=source_artifact_id,
                        analysis_artifact_id=analysis_artifact_id,
                        report_payload=report_payload,
                    )

                elif destination == "Create New SOI from Input":
                    soi_id = await self._create_soi_with_artifacts(
                        node_uid=node_uid,
                        frequency_mhz=frequency_mhz,
                        source_artifact_id=source_artifact_id,
                        analysis_artifact_id=analysis_artifact_id,
                        report_payload=report_payload,
                    )

                    report_payload["target_soi_id"] = soi_id
                    report_payload["created_soi_id"] = soi_id

                    with open(
                        report_path,
                        "w",
                        encoding="utf-8",
                    ) as report_file:
                        json.dump(
                            _json_safe(report_payload),
                            report_file,
                            indent=2,
                            allow_nan=False,
                        )

                    self.logger.info(
                        "Created SOI from Feature Extractor input: "
                        "soi_id=%r, frequency_mhz=%r, "
                        "source_artifact_id=%r, "
                        "analysis_artifact_id=%r",
                        soi_id,
                        frequency_mhz,
                        source_artifact_id,
                        analysis_artifact_id,
                    )

            completed_at = time.time()
            report_payload["completed_at"] = completed_at
            report_payload["duration_s"] = max(
                0.0,
                completed_at - started_at,
            )
            report_payload["target_soi_id"] = soi_id

            with open(
                report_path,
                "w",
                encoding="utf-8",
            ) as report_file:
                json.dump(
                    _json_safe(report_payload),
                    report_file,
                    indent=2,
                    allow_nan=False,
                )

            self.report_payload = report_payload

            self.logger.info(
                "Wrote feature extraction report: %s",
                report_path,
            )


            return

        finally:
            if self._stop and not wrote_features:
                self.logger.info(
                    "Feature extraction stopped before output was written."
                )

            await _set_status(
                status_callback,
                "Idle",
                self.logger,
            )




if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    async def _main():
        op = OperationMain(node_uid="test-node", logger=logging.getLogger("tsi_fe_test"))
        op.parameters = {
            "folder": "/tmp/some_artifact_folder",
            "data_type": "Complex Float 32",
        }
        await op.run()

    asyncio.run(_main())