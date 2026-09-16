"""OOK pulse-width analysis for the Signal Analysis Inspection workspace."""

import logging
import os
from collections import Counter
from typing import Callable, Union

import numpy as np

from fissure.utils.plugins.operations import Operation


_SIGMF_TYPES = {
    "cf32_le": (np.dtype("<c8"), False),
    "cf32_be": (np.dtype(">c8"), False),
    "cf64_le": (np.dtype("<c16"), False),
    "cf64_be": (np.dtype(">c16"), False),
    "ci16_le": (np.dtype("<i2"), True),
    "ci16_be": (np.dtype(">i2"), True),
    "cu16_le": (np.dtype("<u2"), True),
    "cu16_be": (np.dtype(">u2"), True),
    "ci32_le": (np.dtype("<i4"), True),
    "ci32_be": (np.dtype(">i4"), True),
    "cu32_le": (np.dtype("<u4"), True),
    "cu32_be": (np.dtype(">u4"), True),
    "ci8": (np.dtype("i1"), True),
    "cu8": (np.dtype("u1"), True),
    "rf32_le": (np.dtype("<f4"), False),
    "rf32_be": (np.dtype(">f4"), False),
    "rf64_le": (np.dtype("<f8"), False),
    "rf64_be": (np.dtype(">f8"), False),
    "ri16_le": (np.dtype("<i2"), False),
    "ri16_be": (np.dtype(">i2"), False),
    "ru16_le": (np.dtype("<u2"), False),
    "ru16_be": (np.dtype(">u2"), False),
    "ri32_le": (np.dtype("<i4"), False),
    "ri32_be": (np.dtype(">i4"), False),
    "ru32_le": (np.dtype("<u4"), False),
    "ru32_be": (np.dtype(">u4"), False),
    "ri8": (np.dtype("i1"), False),
    "ru8": (np.dtype("u1"), False),
}

_FISSURE_TYPES = {
    "Complex Float 32": (np.dtype("<c8"), False),
    "Complex Float 64": (np.dtype("<c16"), False),
    "Complex Int 16": (np.dtype("<i2"), True),
    "Complex Unsigned Int 16": (np.dtype("<u2"), True),
    "Complex Int 32": (np.dtype("<i4"), True),
    "Complex Unsigned Int 32": (np.dtype("<u4"), True),
    "Complex Int 64": (np.dtype("<i8"), True),
    "Complex Unsigned Int 64": (np.dtype("<u8"), True),
    "Complex Int 8": (np.dtype("i1"), True),
    "Complex Unsigned Int 8": (np.dtype("u1"), True),
    "Float/Float 32": (np.dtype("<f4"), False),
    "Float/Float 64": (np.dtype("<f8"), False),
    "Short/Int 16": (np.dtype("<i2"), False),
    "Unsigned Int 16": (np.dtype("<u2"), False),
    "Int/Int 32": (np.dtype("<i4"), False),
    "Unsigned Int 32": (np.dtype("<u4"), False),
    "Byte/Int 8": (np.dtype("i1"), False),
    "Unsigned Int 8": (np.dtype("u1"), False),
}


def _format_duration(seconds: float) -> str:
    if seconds < 1e-3:
        return f"{seconds * 1e6:.3f} us"
    if seconds < 1.0:
        return f"{seconds * 1e3:.3f} ms"
    return f"{seconds:.6g} s"


def _runs(mask):
    if mask.size == 0:
        return []

    changes = np.flatnonzero(mask[1:] != mask[:-1]) + 1
    starts = np.r_[0, changes]
    ends = np.r_[changes, mask.size]

    return [
        (bool(mask[start]), int(start), int(end))
        for start, end in zip(starts, ends)
    ]


def _otsu_threshold(values) -> float:
    values = np.asarray(values, dtype=np.float64)
    values = values[np.isfinite(values)]
    if values.size == 0:
        raise ValueError("No finite magnitude samples are available.")

    low = float(np.min(values))
    high = float(np.max(values))
    if high <= low:
        return low

    hist, edges = np.histogram(values, bins=512, range=(low, high))
    centers = (edges[:-1] + edges[1:]) * 0.5
    hist = hist.astype(np.float64)

    weight_low = np.cumsum(hist)
    weight_high = hist.sum() - weight_low
    weighted_sum = np.cumsum(hist * centers)
    total_sum = weighted_sum[-1]

    valid = (weight_low > 0) & (weight_high > 0)
    mean_low = np.divide(
        weighted_sum,
        weight_low,
        out=np.zeros_like(weighted_sum),
        where=weight_low > 0,
    )
    mean_high = np.divide(
        total_sum - weighted_sum,
        weight_high,
        out=np.zeros_like(weighted_sum),
        where=weight_high > 0,
    )

    score = np.full_like(centers, -np.inf, dtype=np.float64)
    score[valid] = (
        weight_low[valid]
        * weight_high[valid]
        * (mean_low[valid] - mean_high[valid]) ** 2
    )

    index = int(np.argmax(score))
    return float(edges[index + 1])


def _clean_mask(mask, min_high_samples: int, merge_low_samples: int):
    cleaned = np.asarray(mask, dtype=bool).copy()

    for is_high, start, end in _runs(cleaned):
        if is_high and (end - start) < min_high_samples:
            cleaned[start:end] = False

    if merge_low_samples > 0:
        segments = _runs(cleaned)
        for index, (is_high, start, end) in enumerate(segments):
            if is_high or index == 0 or index == len(segments) - 1:
                continue
            if (end - start) > merge_low_samples:
                continue
            if segments[index - 1][0] and segments[index + 1][0]:
                cleaned[start:end] = True

    return cleaned


def _cluster_two_widths(widths_us):
    widths = np.asarray(widths_us, dtype=np.float64)
    if widths.size < 4:
        return None

    centers = np.array(
        [
            np.percentile(widths, 25),
            np.percentile(widths, 75),
        ],
        dtype=np.float64,
    )

    if abs(float(centers[1] - centers[0])) < 1e-9:
        return None

    for _ in range(50):
        labels = np.argmin(
            np.abs(widths[:, None] - centers[None, :]),
            axis=1,
        )

        if not np.any(labels == 0) or not np.any(labels == 1):
            return None

        next_centers = np.array(
            [
                float(np.mean(widths[labels == 0])),
                float(np.mean(widths[labels == 1])),
            ]
        )

        if np.allclose(next_centers, centers, rtol=0.0, atol=1e-9):
            centers = next_centers
            break

        centers = next_centers

    centers = np.sort(centers)
    boundary = float(np.mean(centers))

    short_count = int(np.sum(widths < boundary))
    long_count = int(np.sum(widths >= boundary))
    if short_count < 2 or long_count < 2:
        return None

    if centers[1] < centers[0] * 1.15:
        return None

    return float(centers[0]), float(centers[1]), boundary


class OperationMain(Operation):
    """Measure OOK pulse widths and derive short/long width sequences."""

    def __init__(
        self,
        filepath: str = "",
        data_type: str = "Complex Float 32",
        sigmf_datatype: str = "",
        sample_rate_hz: float = 0.0,
        center_frequency_hz: float = 0.0,
        sample_count: int = 0,
        start_sample: int = 0,
        end_sample: int = 0,
        threshold: float = 0.0,
        min_pulse_us: float = 50.0,
        merge_gap_us: float = 20.0,
        burst_gap_us: float = 2000.0,
        max_samples: int = 10000000,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        inspection_callback: Union[Callable, None] = None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            inspection_callback=inspection_callback,
        )
        self.filepath = str(filepath or "").strip()
        self.data_type = str(data_type or "Complex Float 32").strip()
        self.sigmf_datatype = str(sigmf_datatype or "").strip()
        self.sample_rate_hz = max(0.0, float(sample_rate_hz or 0.0))
        self.center_frequency_hz = float(center_frequency_hz or 0.0)
        self.sample_count = max(0, int(sample_count or 0))
        self.start_sample = max(0, int(start_sample or 0))
        self.end_sample = max(0, int(end_sample or 0))
        self.threshold = float(threshold or 0.0)
        self.min_pulse_us = max(0.0, float(min_pulse_us or 0.0))
        self.merge_gap_us = max(0.0, float(merge_gap_us or 0.0))
        self.burst_gap_us = max(0.0, float(burst_gap_us or 0.0))
        self.max_samples = max(1000, int(max_samples or 10000000))

    def _type_info(self):
        if self.sigmf_datatype in _SIGMF_TYPES:
            return _SIGMF_TYPES[self.sigmf_datatype]

        return _FISSURE_TYPES.get(
            self.data_type,
            (np.dtype("<c8"), False),
        )

    def _read_samples(self):
        if not self.filepath or not os.path.isfile(self.filepath):
            raise FileNotFoundError(f"IQ file not found: {self.filepath}")

        dtype, interleaved = self._type_info()
        bytes_per_sample = dtype.itemsize * 2 if interleaved else dtype.itemsize
        available_samples = os.path.getsize(self.filepath) // bytes_per_sample
        total = (
            min(self.sample_count, available_samples)
            if self.sample_count
            else available_samples
        )

        start = min(self.start_sample, total)
        end = min(self.end_sample or total, total)
        if end <= start:
            raise ValueError("Inspection selection contains no samples.")

        selection_count = end - start
        if selection_count > self.max_samples:
            raise ValueError(
                "OOK analysis requires full-rate samples for pulse timing. "
                f"The current selection contains {selection_count:,} samples, "
                f"which exceeds Max Samples ({self.max_samples:,}). "
                "Select a smaller range or increase Max Samples."
            )

        if interleaved:
            raw = np.memmap(
                self.filepath,
                dtype=dtype,
                mode="r",
                shape=(total * 2,),
            )
            selected = np.asarray(raw[start * 2:end * 2])
            real = np.asarray(selected[0::2], dtype=np.float64)
            imag = np.asarray(selected[1::2], dtype=np.float64)

            if np.issubdtype(dtype, np.integer):
                info = np.iinfo(dtype)
                scale = max(
                    abs(float(info.min)),
                    abs(float(info.max)),
                ) or 1.0
                real /= scale
                imag /= scale

            data = real + 1j * imag
        else:
            raw = np.memmap(
                self.filepath,
                dtype=dtype,
                mode="r",
                shape=(total,),
            )
            data = np.asarray(raw[start:end])

            if np.issubdtype(dtype, np.integer):
                info = np.iinfo(dtype)
                scale = max(
                    abs(float(info.min)),
                    abs(float(info.max)),
                ) or 1.0
                data = data.astype(np.float64) / scale

        return np.asarray(data), selection_count

    async def _emit_inspection(self, inspection, final=True):
        await self.inspection_callback(
            self.node_uid,
            self.opid,
            inspection,
            final,
        )

    async def run(self) -> None:
        try:
            if self.sample_rate_hz <= 0:
                raise ValueError("OOK analysis requires a valid sample rate.")

            data, selection_count = self._read_samples()
            if data.size == 0:
                raise ValueError("OOK analysis read no samples.")

            magnitude = np.abs(data).astype(np.float64)
            threshold = (
                self.threshold
                if self.threshold > 0.0
                else _otsu_threshold(magnitude)
            )

            min_high_samples = max(
                1,
                int(round(self.min_pulse_us * 1e-6 * self.sample_rate_hz)),
            )
            merge_low_samples = max(
                0,
                int(round(self.merge_gap_us * 1e-6 * self.sample_rate_hz)),
            )
            burst_gap_samples = max(
                1,
                int(round(self.burst_gap_us * 1e-6 * self.sample_rate_hz)),
            )

            high_mask = _clean_mask(
                magnitude >= threshold,
                min_high_samples,
                merge_low_samples,
            )

            pulses = [
                (start, end, end - start)
                for is_high, start, end in _runs(high_mask)
                if is_high
            ]

            if not pulses:
                raise ValueError(
                    "No OOK pulses were detected. Try lowering the threshold "
                    "or Min Pulse Width."
                )

            bursts = []
            current = []

            for pulse in pulses:
                if (
                    current
                    and pulse[0] - current[-1][1] >= burst_gap_samples
                ):
                    bursts.append(current)
                    current = []

                current.append(pulse)

            if current:
                bursts.append(current)

            widths_us = np.asarray(
                [
                    width * 1e6 / self.sample_rate_hz
                    for _, _, width in pulses
                ],
                dtype=np.float64,
            )

            values = {
                "Analyzed Samples": int(selection_count),
                "Selection Duration": _format_duration(
                    selection_count / self.sample_rate_hz
                ),
                "Magnitude Threshold": round(float(threshold), 6),
                "Detected Pulses": len(pulses),
                "Burst Candidates": len(bursts),
                "Burst Gap": f"{self.burst_gap_us:.3f} us",
            }

            clustered = _cluster_two_widths(widths_us)
            if clustered is not None:
                short_center, long_center, boundary = clustered
                short_widths = widths_us[widths_us < boundary]
                long_widths = widths_us[widths_us >= boundary]

                sequences = []
                for burst in bursts:
                    sequence = "".join(
                        "0"
                        if (width * 1e6 / self.sample_rate_hz) < boundary
                        else "1"
                        for _, _, width in burst
                    )
                    sequences.append(sequence)

                patterns = Counter(sequences)
                dominant_sequence, dominant_count = patterns.most_common(1)[0]

                values.update(
                    {
                        "Width Mapping": "0 = short, 1 = long",
                        "Short Width": (
                            f"{short_center:.3f} us "
                            f"(n={short_widths.size}, "
                            f"range={np.min(short_widths):.3f}-"
                            f"{np.max(short_widths):.3f} us)"
                        ),
                        "Long Width": (
                            f"{long_center:.3f} us "
                            f"(n={long_widths.size}, "
                            f"range={np.min(long_widths):.3f}-"
                            f"{np.max(long_widths):.3f} us)"
                        ),
                        "Width Boundary": f"{boundary:.3f} us",
                        "Long / Short Ratio": round(
                            long_center / short_center,
                            3,
                        ),
                        "Dominant Sequence": dominant_sequence,
                        "Dominant Count": (
                            f"{dominant_count}/{len(sequences)} bursts"
                        ),
                        "Pattern Counts": "; ".join(
                            f"{pattern} x{count}"
                            for pattern, count in patterns.most_common(8)
                        ),
                    }
                )

                preview_count = min(16, len(sequences))
                values["Burst Sequences"] = "\n".join(
                    f"{index + 1}: {sequences[index]}"
                    for index in range(preview_count)
                )

                if len(sequences) > preview_count:
                    values["Burst Sequences"] += (
                        f"\n... {len(sequences) - preview_count} more"
                    )
            else:
                values.update(
                    {
                        "Width Mapping": (
                            "Two distinct pulse widths were not resolved."
                        ),
                        "Mean Pulse Width": (
                            f"{float(np.mean(widths_us)):.3f} us"
                        ),
                        "Pulse Width Range": (
                            f"{float(np.min(widths_us)):.3f}-"
                            f"{float(np.max(widths_us)):.3f} us"
                        ),
                    }
                )

            await self._emit_inspection(
                {
                    "title": "OOK Pulse Analysis",
                    "values": values,
                },
                final=True,
            )
        except Exception as error:
            try:
                await self._emit_inspection(
                    {
                        "title": "OOK Pulse Analysis",
                        "error": str(error),
                        "values": {},
                    },
                    final=True,
                )
            except Exception:
                self.logger.exception(
                    "Failed to emit OOK Inspection error result"
                )

            raise
