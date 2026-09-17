"""fissure_geo.multilateration

Radio-agnostic RSSI/power multilateration utilities.

Goal:
- Any radio produces measurements: (receiver_lat, receiver_lon, rssi_db_or_power_db)
- Feed them to this library
- Get an estimated emitter location (lat, lon)
- Also estimate CE (circular error) for TAK-style uncertainty

Approach:
- Convert RSSI/power to an approximate range using a log-distance path loss model
- Solve multilateration in a local metric plane (meters) using weighted least squares
- Estimate covariance from the Jacobian at the solution and convert to a radial CE

Dependencies:
  - numpy
  - pyproj
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

import numpy as np
from pyproj import Transformer


@dataclass(frozen=True)
class Sample:
    """A receiver measurement.

    lat/lon: receiver position (WGS84 degrees)
    rssi_db: received power proxy in dB (dBm, dBFS, relative dB) - must be consistent
    t: optional timestamp (seconds)
    """
    lat: float
    lon: float
    rssi_db: float
    t: float = 0.0


class PathLossModel:
    """Log-distance model to map RSSI/power to range.

    rssi_db ~= p0_db - 10*n*log10(d_m)

    d_m = 10^((p0_db - rssi_db)/(10*n))

    Notes:
    - For radios that output relative power (e.g., dBFS), use calibration:
      calibrate_p0_from_samples(..., d_ref_m=...) to set p0_db so early samples match a rough distance scale.
    """

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
    """Local AEQD projection centered at an origin lat/lon, producing meters."""

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


def multilaterate_wls_xy(
    xy_d: Sequence[Tuple[float, float, float]],
    *,
    weights: Optional[Sequence[float]] = None,
) -> Optional[Tuple[float, float]]:
    """Weighted least-squares multilateration in 2D.

    Args:
      xy_d: sequence of (x_m, y_m, d_m). Recommend >= 4 points.
      weights: optional weights for each equation (len = len(xy_d)-1). If None, uses 1/d heuristic.

    Returns:
      (x_hat, y_hat) in meters, or None.
    """
    if len(xy_d) < 4:
        return None

    xs = np.asarray([p[0] for p in xy_d], dtype=np.float64)
    ys = np.asarray([p[1] for p in xy_d], dtype=np.float64)
    ds = np.asarray([p[2] for p in xy_d], dtype=np.float64)

    x1, y1, d1 = xs[0], ys[0], ds[0]
    A = np.column_stack((2.0 * (xs[1:] - x1), 2.0 * (ys[1:] - y1)))
    b = (d1**2 - ds[1:]**2) + (xs[1:]**2 - x1**2) + (ys[1:]**2 - y1**2)

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
) -> Optional[Tuple[float, float]]:
    """Estimate emitter/AP lat/lon from receiver samples."""
    if not samples:
        return None
    s = list(samples)[-int(max_samples):]
    if len(s) < 4:
        return None

    proj = _LocalProjector(s[0].lat, s[0].lon)
    xy_d: List[Tuple[float, float, float]] = []
    for sm in s:
        x, y = proj.to_xy(sm.lat, sm.lon)
        d = model.distance_m(sm.rssi_db)
        xy_d.append((x, y, d))

    sol = multilaterate_wls_xy(xy_d, weights=weights)
    if sol is None:
        return None
    x_hat, y_hat = sol
    return proj.to_latlon(x_hat, y_hat)


def _solve_covariance_xy(
    xy_d: Sequence[Tuple[float, float, float]],
    x_hat: float,
    y_hat: float,
    *,
    weights: Optional[Sequence[float]] = None,
    min_range_m: float = 1e-3,
) -> Optional[np.ndarray]:
    """Estimate 2x2 covariance for a multilateration solution in meters.

    Uses a linearized (Gauss-Newton) approximation with range residuals:
        r_i = sqrt((x-xi)^2 + (y-yi)^2) - d_i

    Cov ≈ σ_r^2 * (Jᵀ W J)⁻¹
    where σ_r^2 is estimated from the (weighted) residual RMS.
    """
    if len(xy_d) < 4:
        return None

    xs = np.asarray([p[0] for p in xy_d], dtype=np.float64)
    ys = np.asarray([p[1] for p in xy_d], dtype=np.float64)
    ds = np.asarray([p[2] for p in xy_d], dtype=np.float64)

    dx = float(x_hat) - xs
    dy = float(y_hat) - ys
    ranges = np.sqrt(dx * dx + dy * dy)
    ranges = np.clip(ranges, min_range_m, None)

    residuals = ranges - ds  # meters

    # Jacobian (N x 2)
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
) -> Optional[float]:
    """Estimate circular error (CE) radius in meters for the multilateration result.

    Steps:
      1) Solve for (lat, lon)
      2) Compute local covariance in meters
      3) Convert covariance -> radial error at desired confidence

    For an (approximately) isotropic 2D Gaussian, radial error at confidence p is:
        CE_p = σ * sqrt(-2 ln(1-p))
    where σ is the per-axis std. For anisotropic covariance, σ is approximated
    using the average of x/y variances.

    Returns:
      CE in meters (radius) or None.
    """
    est = estimate_latlon_from_samples(samples, model, max_samples=max_samples)
    if est is None:
        return None
    lat_hat, lon_hat = est

    s = list(samples)[-int(max_samples):]
    if len(s) < 4:
        return None

    proj = _LocalProjector(s[0].lat, s[0].lon)
    x_hat, y_hat = proj.to_xy(lat_hat, lon_hat)

    xy_d: List[Tuple[float, float, float]] = []
    for sm in s:
        x, y = proj.to_xy(sm.lat, sm.lon)
        d = model.distance_m(sm.rssi_db)
        xy_d.append((x, y, d))

    cov = _solve_covariance_xy(xy_d, x_hat, y_hat)
    if cov is None:
        return None

    var_x = float(cov[0, 0])
    var_y = float(cov[1, 1])
    if var_x < 0.0 or var_y < 0.0:
        return None

    sigma = math.sqrt(max(1e-9, 0.5 * (var_x + var_y)))

    p = float(confidence)
    p = min(max(p, 1e-6), 1.0 - 1e-9)
    ce = sigma * math.sqrt(-2.0 * math.log(1.0 - p))
    return float(ce)


class MultilaterationEstimator:
    """Streaming estimator: add measurements, then ask for an estimate.

    This is radio-agnostic. Your radio code just needs to produce (lat, lon, rssi_db).
    """

    def __init__(self, *, smooth_alpha: float = 0.35, max_samples: int = 80) -> None:
        if not (0.0 <= smooth_alpha <= 1.0):
            raise ValueError("smooth_alpha must be in [0,1]")
        self.smooth_alpha = float(smooth_alpha)
        self.max_samples = int(max_samples)
        self._samples: List[Sample] = []
        self._est: Optional[Tuple[float, float]] = None

    @property
    def ready(self) -> bool:
        return len(self._samples) >= 4

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
        model: Optional[PathLossModel] = None,
        auto_calibrate: bool = False,
        d_ref_m: Optional[float] = None,
        cal_min_samples: int = 20,
    ) -> None:
        """Add a new measurement.

        If auto_calibrate=True and model+d_ref_m are provided, when cal_min_samples are present
        the model's p0_db will be set so the median RSSI implies distance ~ d_ref_m.
        """
        self.add_sample(Sample(float(lat), float(lon), float(rssi_db), float(t)))

        if auto_calibrate and model is not None and d_ref_m is not None:
            if len(self._samples) == int(cal_min_samples):
                vals = [s.rssi_db for s in self._samples[-cal_min_samples:]]
                model.calibrate_p0_from_samples(vals, float(d_ref_m), robust=True)

    def estimate_latlon(self, model: PathLossModel) -> Optional[Tuple[float, float]]:
        """Compute and store a smoothed estimate."""
        est = estimate_latlon_from_samples(self._samples, model, max_samples=self.max_samples)
        if est is None:
            return self._est

        if self._est is None:
            self._est = est
        else:
            a = self.smooth_alpha
            lat_new, lon_new = est
            lat_old, lon_old = self._est
            self._est = (a * lat_new + (1.0 - a) * lat_old, a * lon_new + (1.0 - a) * lon_old)
        return self._est

    def estimate_latlon_and_ce(
        self,
        model: PathLossModel,
        *,
        confidence: float = 0.90,
    ) -> Tuple[Optional[Tuple[float, float]], Optional[float]]:
        """Return (estimate_latlon, ce_m) using current samples.

        CE is computed at the requested confidence (default CE90).
        """
        est = self.estimate_latlon(model)
        if est is None:
            return None, None
        ce = estimate_ce_from_samples(self._samples, model, max_samples=self.max_samples, confidence=confidence)
        return est, ce
