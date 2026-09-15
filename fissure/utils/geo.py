from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
from pyproj import Transformer


@dataclass(frozen=True)
class Sample:
    lat: float
    lon: float
    rssi_db: float
    t: float = 0.0
    node_uid: str = ""


class PathLossModel:
    def __init__(
        self,
        *,
        n: float = 2.2,
        p0_db: float = -40.0,
        d_clip: Tuple[float, float] = (1.0, 1500.0),
    ) -> None:
        if n <= 0:
            raise ValueError("n must be > 0")
        self.n = float(n)
        self.p0_db = float(p0_db)
        self.d_clip = (float(d_clip[0]), float(d_clip[1]))

    def distance_m(self, rssi_db: float) -> float:
        d = 10.0 ** ((self.p0_db - float(rssi_db)) / (10.0 * self.n))
        return float(np.clip(d, self.d_clip[0], self.d_clip[1]))

    def calibrate_p0_from_reference(self, rssi_db: float, d_ref_m: float) -> float:
        if d_ref_m <= 0:
            raise ValueError("d_ref_m must be > 0")
        self.p0_db = float(rssi_db) + 10.0 * self.n * np.log10(float(d_ref_m))
        return self.p0_db

    def calibrate_p0_from_samples(
        self,
        rssi_db_values: Sequence[float],
        d_ref_m: float,
        *,
        robust: bool = True,
    ) -> float:
        if not rssi_db_values:
            raise ValueError("Need at least one RSSI value")
        ref = float(np.median(rssi_db_values) if robust else np.mean(rssi_db_values))
        return self.calibrate_p0_from_reference(ref, d_ref_m)


class _LocalProjector:
    def __init__(self, lat0: float, lon0: float) -> None:
        aeqd = (
            f"+proj=aeqd +lat_0={float(lat0)} +lon_0={float(lon0)} "
            "+datum=WGS84 +units=m +no_defs"
        )
        self._fwd = Transformer.from_crs("EPSG:4326", aeqd, always_xy=True)
        self._inv = Transformer.from_crs(aeqd, "EPSG:4326", always_xy=True)

    def to_xy(self, lat: float, lon: float) -> Tuple[float, float]:
        x, y = self._fwd.transform(float(lon), float(lat))
        return float(x), float(y)

    def to_latlon(self, x: float, y: float) -> Tuple[float, float]:
        lon, lat = self._inv.transform(float(x), float(y))
        return float(lat), float(lon)


def _aggregate_samples_by_position(
    samples: Sequence[Sample],
    *,
    min_position_separation_m: float = 8.0,
) -> List[Sample]:
    """Collapse repeated observations from effectively the same receiver position."""
    if not samples:
        return []

    source = list(samples)
    proj = _LocalProjector(source[0].lat, source[0].lon)
    clusters: List[dict] = []
    min_sep = max(0.1, float(min_position_separation_m))

    for sample in source:
        x, y = proj.to_xy(sample.lat, sample.lon)
        match = None
        match_distance = None

        for cluster in clusters:
            cx = float(np.mean(cluster["xs"]))
            cy = float(np.mean(cluster["ys"]))
            distance = math.hypot(x - cx, y - cy)
            if distance < min_sep and (match_distance is None or distance < match_distance):
                match = cluster
                match_distance = distance

        if match is None:
            clusters.append({"xs": [x], "ys": [y], "samples": [sample]})
        else:
            match["xs"].append(x)
            match["ys"].append(y)
            match["samples"].append(sample)

    aggregated: List[Sample] = []
    for cluster in clusters:
        members = cluster["samples"]
        lat = float(np.mean([sample.lat for sample in members]))
        lon = float(np.mean([sample.lon for sample in members]))
        rssi_db = float(np.median([sample.rssi_db for sample in members]))
        t = float(max(sample.t for sample in members))
        node_uids = sorted({sample.node_uid for sample in members if sample.node_uid})
        aggregated.append(Sample(lat, lon, rssi_db, t, ",".join(node_uids)))

    return aggregated


def geometry_stats(
    samples: Sequence[Sample],
    *,
    min_position_separation_m: float = 8.0,
    min_spread_m: float = 20.0,
    min_shape_ratio: float = 0.03,
) -> Dict[str, object]:
    """Summarize whether observation positions provide usable 2D geometry."""
    source = list(samples)
    aggregated = _aggregate_samples_by_position(
        source,
        min_position_separation_m=min_position_separation_m,
    )
    node_uids = {sample.node_uid for sample in source if sample.node_uid}

    result: Dict[str, object] = {
        "sample_count": len(source),
        "unique_node_count": len(node_uids),
        "unique_position_count": len(aggregated),
        "spread_m": 0.0,
        "shape_ratio": 0.0,
        "quality": "insufficient_positions",
        "usable": False,
    }

    if len(aggregated) < 3:
        return result

    proj = _LocalProjector(aggregated[0].lat, aggregated[0].lon)
    xy = np.asarray([proj.to_xy(sample.lat, sample.lon) for sample in aggregated], dtype=np.float64)

    max_distance = 0.0
    for index in range(len(xy)):
        delta = xy[index + 1:] - xy[index]
        if len(delta):
            max_distance = max(max_distance, float(np.max(np.hypot(delta[:, 0], delta[:, 1]))))
    result["spread_m"] = max_distance

    centered = xy - np.mean(xy, axis=0)
    try:
        singular_values = np.linalg.svd(centered, compute_uv=False)
        if len(singular_values) >= 2 and singular_values[0] > 1e-9:
            shape_ratio = float(singular_values[1] / singular_values[0])
        else:
            shape_ratio = 0.0
    except np.linalg.LinAlgError:
        shape_ratio = 0.0
    result["shape_ratio"] = shape_ratio

    if max_distance < float(min_spread_m):
        result["quality"] = "insufficient_spread"
        return result

    if shape_ratio < float(min_shape_ratio):
        result["quality"] = "collinear"
        return result

    if shape_ratio < 0.10:
        quality = "poor"
    elif shape_ratio < 0.25:
        quality = "fair"
    else:
        quality = "good"

    result["quality"] = quality
    result["usable"] = True
    return result


def multilaterate_wls_xy(
    xy_d: Sequence[Tuple[float, float, float]],
    *,
    weights: Optional[Sequence[float]] = None,
) -> Optional[Tuple[float, float]]:
    if len(xy_d) < 3:
        return None

    xs = np.asarray([p[0] for p in xy_d], dtype=np.float64)
    ys = np.asarray([p[1] for p in xy_d], dtype=np.float64)
    ds = np.asarray([p[2] for p in xy_d], dtype=np.float64)

    x1, y1, d1 = xs[0], ys[0], ds[0]
    A = np.column_stack((2.0 * (xs[1:] - x1), 2.0 * (ys[1:] - y1)))
    b = (d1**2 - ds[1:]**2) + (xs[1:]**2 - x1**2) + (ys[1:]**2 - y1**2)

    if np.linalg.matrix_rank(A) < 2:
        return None

    if weights is None:
        w = 1.0 / np.clip(ds[1:], 10.0, 2000.0)
    else:
        w = np.asarray(list(weights), dtype=np.float64)
        if w.shape[0] != A.shape[0]:
            raise ValueError("weights must have length len(xy_d)-1")

    W = np.diag(w)
    try:
        AtW = A.T @ W
        sol = np.linalg.lstsq(AtW @ A, AtW @ b, rcond=None)[0]
        return float(sol[0]), float(sol[1])
    except np.linalg.LinAlgError:
        return None


def estimate_latlon_from_samples(
    samples: Sequence[Sample],
    model: PathLossModel,
    *,
    max_samples: int = 80,
    weights: Optional[Sequence[float]] = None,
    min_position_separation_m: float = 8.0,
    min_spread_m: float = 20.0,
) -> Optional[Tuple[float, float]]:
    source = list(samples)[-int(max_samples):]
    if len(source) < 3:
        return None

    stats = geometry_stats(
        source,
        min_position_separation_m=min_position_separation_m,
        min_spread_m=min_spread_m,
    )
    if not bool(stats["usable"]):
        return None

    s = _aggregate_samples_by_position(
        source,
        min_position_separation_m=min_position_separation_m,
    )
    proj = _LocalProjector(s[0].lat, s[0].lon)
    xy_d: List[Tuple[float, float, float]] = []

    for sample in s:
        x, y = proj.to_xy(sample.lat, sample.lon)
        d = model.distance_m(sample.rssi_db)
        xy_d.append((x, y, d))

    sol = multilaterate_wls_xy(xy_d, weights=weights)
    if sol is None:
        return None

    return proj.to_latlon(sol[0], sol[1])


def _solve_covariance_xy(
    xy_d: Sequence[Tuple[float, float, float]],
    x_hat: float,
    y_hat: float,
    *,
    weights: Optional[Sequence[float]] = None,
    min_range_m: float = 1e-3,
) -> Optional[np.ndarray]:
    if len(xy_d) < 3:
        return None

    xs = np.asarray([p[0] for p in xy_d], dtype=np.float64)
    ys = np.asarray([p[1] for p in xy_d], dtype=np.float64)
    ds = np.asarray([p[2] for p in xy_d], dtype=np.float64)

    dx = float(x_hat) - xs
    dy = float(y_hat) - ys
    ranges = np.sqrt(dx * dx + dy * dy)
    ranges = np.clip(ranges, min_range_m, None)

    residuals = ranges - ds
    J = np.column_stack((dx / ranges, dy / ranges))

    if weights is None:
        w = 1.0 / np.clip(ds, 10.0, 2000.0)
    else:
        w = np.asarray(list(weights), dtype=np.float64)
        if w.shape[0] != J.shape[0]:
            raise ValueError("weights must have length len(xy_d)")

    W = np.diag(w)

    try:
        dof = max(1, len(residuals) - 2)
        sigma2 = float((residuals.T @ W @ residuals) / dof)
        H = J.T @ W @ J
        cov = np.linalg.inv(H) * sigma2
        return cov
    except np.linalg.LinAlgError:
        return None


def estimate_ce_from_samples(
    samples: Sequence[Sample],
    model: PathLossModel,
    *,
    max_samples: int = 80,
    confidence: float = 0.90,
    min_position_separation_m: float = 8.0,
    min_spread_m: float = 20.0,
) -> Optional[float]:
    est = estimate_latlon_from_samples(
        samples,
        model,
        max_samples=max_samples,
        min_position_separation_m=min_position_separation_m,
        min_spread_m=min_spread_m,
    )
    if est is None:
        return None

    source = list(samples)[-int(max_samples):]
    s = _aggregate_samples_by_position(
        source,
        min_position_separation_m=min_position_separation_m,
    )
    if len(s) < 3:
        return None

    lat_hat, lon_hat = est
    proj = _LocalProjector(s[0].lat, s[0].lon)
    x_hat, y_hat = proj.to_xy(lat_hat, lon_hat)

    xy_d: List[Tuple[float, float, float]] = []
    for sample in s:
        x, y = proj.to_xy(sample.lat, sample.lon)
        d = model.distance_m(sample.rssi_db)
        xy_d.append((x, y, d))

    cov = _solve_covariance_xy(xy_d, x_hat, y_hat)
    if cov is None:
        return None

    var_x = float(cov[0, 0])
    var_y = float(cov[1, 1])
    if var_x < 0.0 or var_y < 0.0:
        return None

    sigma = math.sqrt(max(1e-9, 0.5 * (var_x + var_y)))
    p = min(max(float(confidence), 1e-6), 1.0 - 1e-9)
    return float(sigma * math.sqrt(-2.0 * math.log(1.0 - p)))


class MultilaterationEstimator:
    def __init__(
        self,
        *,
        smooth_alpha: float = 0.35,
        max_samples: int = 80,
        min_position_separation_m: float = 8.0,
        min_spread_m: float = 20.0,
    ) -> None:
        if not (0.0 <= smooth_alpha <= 1.0):
            raise ValueError("smooth_alpha must be in [0,1]")
        self.smooth_alpha = float(smooth_alpha)
        self.max_samples = int(max_samples)
        self.min_position_separation_m = float(min_position_separation_m)
        self.min_spread_m = float(min_spread_m)
        self._samples: List[Sample] = []
        self._est: Optional[Tuple[float, float]] = None

    @property
    def ready(self) -> bool:
        return bool(self.geometry["usable"])

    @property
    def geometry(self) -> Dict[str, object]:
        return geometry_stats(
            self._samples,
            min_position_separation_m=self.min_position_separation_m,
            min_spread_m=self.min_spread_m,
        )

    @property
    def samples(self) -> List[Sample]:
        return list(self._samples)

    @property
    def estimate(self) -> Optional[Tuple[float, float]]:
        return self._est

    def clear(self) -> None:
        self._samples.clear()
        self._est = None

    def add_sample(self, sample: Sample) -> None:
        self._samples.append(sample)
        if len(self._samples) > self.max_samples:
            self._samples = self._samples[-self.max_samples:]

    def add_measurement(
        self,
        *,
        lat: float,
        lon: float,
        rssi_db: float,
        t: float = 0.0,
        node_uid: str = "",
        model: Optional[PathLossModel] = None,
        auto_calibrate: bool = False,
        d_ref_m: Optional[float] = None,
        cal_min_samples: int = 20,
    ) -> None:
        self.add_sample(Sample(float(lat), float(lon), float(rssi_db), float(t), str(node_uid or "")))

        if auto_calibrate and model is not None and d_ref_m is not None:
            if len(self._samples) == int(cal_min_samples):
                vals = [sample.rssi_db for sample in self._samples[-cal_min_samples:]]
                model.calibrate_p0_from_samples(vals, float(d_ref_m), robust=True)

    def estimate_latlon(self, model: PathLossModel) -> Optional[Tuple[float, float]]:
        est = estimate_latlon_from_samples(
            self._samples,
            model,
            max_samples=self.max_samples,
            min_position_separation_m=self.min_position_separation_m,
            min_spread_m=self.min_spread_m,
        )
        if est is None:
            return self._est

        if self._est is None:
            self._est = est
        else:
            a = self.smooth_alpha
            lat_new, lon_new = est
            lat_old, lon_old = self._est
            self._est = (
                a * lat_new + (1.0 - a) * lat_old,
                a * lon_new + (1.0 - a) * lon_old,
            )
        return self._est

    def estimate_latlon_and_ce(
        self,
        model: PathLossModel,
        *,
        confidence: float = 0.90,
    ) -> Tuple[Optional[Tuple[float, float]], Optional[float]]:
        est = self.estimate_latlon(model)
        if est is None:
            return None, None
        ce = estimate_ce_from_samples(
            self._samples,
            model,
            max_samples=self.max_samples,
            confidence=confidence,
            min_position_separation_m=self.min_position_separation_m,
            min_spread_m=self.min_spread_m,
        )
        return est, ce