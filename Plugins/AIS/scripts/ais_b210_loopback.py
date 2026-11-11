#!/usr/bin/env python3
"""Backward-compatible entry point for AIS B210 lab loopback diagnostics.

The hardware implementation lives in `ais_b210_rf_hardware.py`, using a module
name distinct from the dynamically loaded FISSURE Action of the same old name.
"""
from ais_b210_rf_hardware import (
    LoopbackConfigError, validate_settings, verify_iq_file,
    prepare_tx_file, probe, make_top_block, run, main,
)

if __name__ == "__main__":
    raise SystemExit(main())
