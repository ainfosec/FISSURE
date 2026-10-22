#!/usr/bin/env python3
"""HD Radio Quick Scan: rtl_power shortlist then nrsc5 confirmation."""
from pathlib import Path
import sys

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PLUGIN_ROOT.parent.parent
for directory in (str(REPO_ROOT), str(PLUGIN_ROOT / "scripts")):
    if directory not in sys.path:
        sys.path.insert(0, directory)

from fissure.utils.plugins.operations import Operation
from hd_radio_scan_core import ScanCore


class OperationMain(ScanCore, Operation):
    """Quick Scan: survey occupied FM channel centers before NRSC-5 acquisition."""

    mode = "quick"


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})
