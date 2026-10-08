import csv
import tempfile
import unittest
from pathlib import Path

import numpy as np

from scripts.radar_analyzer import (
    _scan_periodicity,
    analyze_file,
    inspection_payload,
)


class RadarAnalyzerTests(unittest.TestCase):
    def test_scan_period_refinement(self):
        pulse_count = 489
        pri_s = 0.001
        toa = np.arange(pulse_count) * pri_s
        amplitude = 0.55 + 0.45 * np.cos(
            2.0 * np.pi * np.arange(pulse_count) / 200.0
        )

        result = _scan_periodicity(toa, amplitude)

        self.assertTrue(result["detected"])
        self.assertAlmostEqual(
            result["period_s"],
            0.2,
            delta=0.01,
        )

    def test_pdw_requires_toa(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.csv"
            path.write_text(
                "pulse_width_s,amplitude\n1e-5,1.0\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError,
                "toa_s",
            ):
                analyze_file(
                    path,
                    "pdw_csv",
                )

    def test_pdw_optional_columns_are_unsupported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "minimal.csv"
            with path.open(
                "w",
                newline="",
                encoding="utf-8",
            ) as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["toa_s"],
                )
                writer.writeheader()
                for index in range(10):
                    writer.writerow(
                        {
                            "toa_s": index * 0.001,
                        }
                    )

            result = analyze_file(
                path,
                "pdw_csv",
            )
            payload = inspection_payload(result)

            self.assertEqual(
                result["lfm"]["status"],
                "unsupported",
            )
            self.assertEqual(
                payload["values"]["LFM/Chirp"],
                "unsupported/not observable",
            )
            self.assertEqual(
                result["pulse_width_s"]["status"],
                "unsupported",
            )

    def test_raw_samples_require_sample_rate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.cf32"
            np.zeros(
                32,
                dtype=np.complex64,
            ).tofile(path)

            with self.assertRaisesRegex(
                ValueError,
                "positive sample rate",
            ):
                analyze_file(
                    path,
                    "iq_cf32",
                    sample_rate_hz=0.0,
                )


if __name__ == "__main__":
    unittest.main()
