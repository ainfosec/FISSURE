#!/usr/bin/env python3
"""HD Radio Full Scan: exhaustive, channel-by-channel NRSC-5 decoding."""
from pathlib import Path
import sys

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PLUGIN_ROOT.parent.parent
for directory in (str(REPO_ROOT), str(PLUGIN_ROOT / "scripts")):
    if directory not in sys.path:
        sys.path.insert(0, directory)

from fissure.utils.plugins.operations import Operation
from hd_radio_scan_core import ScanCore, channel_tenths, int_param

# Preserve names used in prior user tests/scripts for backwards compatibility.
_channel_tenths = channel_tenths
_int_param = int_param


class OperationMain(ScanCore, Operation):
    """Full Scan: acquire each FM grid channel for the configured duration."""

    mode = "full"


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})
