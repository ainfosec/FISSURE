import importlib.util
from pathlib import Path
import tempfile
import sys
import contextlib
import io
import unittest
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("ais_b210_diagnostics", str(ROOT / "scripts" / "ais_b210_diagnostics.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class B210DiagnosticsTests(unittest.TestCase):
    def test_tone_found_in_synthetic_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "rx.cf32"
            mod.write_tone(f, 240000, 40000)
            result = mod.analyze_capture(f, 240000, 40000)
            self.assertTrue(result["tone_detected"])
            self.assertTrue(result["visible_power_bursts"])
            self.assertAlmostEqual(result["tone_best_offset_hz"], 40000, delta=80)

    def test_noise_only_not_mistaken_for_tone(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "noise.cf32"
            rng = np.random.default_rng(42)
            noise = (rng.normal(size=240000) + 1j*rng.normal(size=240000)).astype(np.complex64) * 1e-4
            noise.tofile(f)
            result = mod.analyze_capture(f, 240000, 40000)
            self.assertFalse(result["tone_detected"])
            self.assertFalse(result["visible_power_bursts"])

    def test_analyze_cli_does_not_open_uhd(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "rx.cf32"
            mod.write_tone(file, 240000, 40000)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = mod.main(["--analyze", str(file)])
            self.assertEqual(code, 0)
            self.assertIn('"tone_detected": true', output.getvalue())


if __name__ == "__main__":
    unittest.main()
