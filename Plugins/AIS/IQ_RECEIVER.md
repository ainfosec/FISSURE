# AIS IQ Receive — GNU Radio 3.8/3.10 offline file adapter

The `ais_iq_receive` Action reads a *Sensor Node-local* raw complex64 IQ
recording, demodulates AIS through the installed GNU Radio version's `gr-ais`
receiver, and feeds decoded NMEA into the existing Detection/Target/Artifact
pipeline used by `ais_receive`. This operation never opens an SDR or emits RF.

**Do not supply `ais_simulated.nmea` here.** NMEA strings are decoded text,
not modulated GMSK IQ. To replay NMEA text, use `ais_receive` with file input.

## Requirements

- Ubuntu 20.04 / GNU Radio 3.8: installed bmagistro/gr-ais with the
  top-level `ais` Python package and its `ais.ais_rx` hierarchy. It produces
  NMEA through its legacy print message port. **No `ais_rx_core.py` needed.**
- Ubuntu 22.04 / 24.04 / GNU Radio 3.10: `bkerler/gr-ais` maint-3.10
  installed for the matching GNU Radio ABI. It must expose
  `gnuradio.ais.pdu_to_nmea`; GNU Radio provides the other receiver DSP
  blocks. The plugin reproduces the enabled `ais_demod.grc` chain directly
  without importing generated `ais_rx_core.py`.
- `pyais` installed in the Python environment of the executing Sensor Node.
- Raw complex64 little-endian IQ data: **interleaved float32 I/Q**, exactly
  eight bytes per complex sample, **no header**.
- Correct capture sample rate and RF center frequency. Defaults are
  200,000 complex samples/second centered on 162,000,000 Hz, which can cover
  AIS A (161.975 MHz) and B (162.025 MHz) simultaneously.

If you have 16-bit interleaved IQ, WAV, SigMF, or another recording format,
convert to raw complex64 using your existing FISSURE IQ Data tools first and
carry across the correct sample rate/frequency. No automatic respecification or
sample-format guessing is performed by this Action.

## Readiness and command-line test

Run the preflight on the executing Sensor Node (does not open an SDR):

```bash
python3 Plugins/AIS/scripts/ais_iq_decoder.py --probe
```

For a known-good AIS IQ recording, test the backend outside FISSURE:

```bash
python3 -u Plugins/AIS/scripts/ais_iq_decoder.py \
  --input /path/on/sensor_node/ais_complex64.iq \
  --sample-rate 200000 --center-freq 162000000 --channel both
```

The helper prints NMEA `!AIVDM` messages to stdout (one per line). Diagnostic
and preflight errors go to stderr. With correct dependencies and a file that
contains AIS signal energy, decoded output is expected, but this GNU Radio
modulation/demodulation path has **not yet been hardware-tested** as part of
v0.3 in this runtime.

In FISSURE, select AIS > `ais_iq_receive`, enter the node-local IQ path,
frequency, sample rate, and channel choice (`A`, `B` or `both`). The result is
normal FISSURE Detections, per-MMSI Targets, and a five-file receive Artifact.
The IQ source path, sample format, frequency and sample rate are preserved in
metadata. The original (possibly large) IQ input is **not copied** into the
Artifact.

## Technical integration

The helper uses `blocks.file_source` and selects a version-specific receiver:
GNU Radio 3.8 uses installed `gr-ais` `ais_rx`; GNU Radio 3.10
builds the bkerler `ais_rx_core` signal-processing chain in Python using
standard GNU Radio blocks and the installed OOT `pdu_to_nmea`. Both
select AIS channels using signed offsets of -25/+25 kHz.
The hierarchy performs demodulation and framing and forwards NMEA lines to
stdout through its message printing port. The 3.10 path has no dependency on
FISSURE's retired Flow Graph Library.
The Operation starts this helper as a managed subprocess and reuses its
existing AIS parser and callbacks. It checks failures, reacts to Stop, and
terminates the child cleanly, escalating to kill if necessary.

## Remaining work

- Confirm real gr-ais GMSK decode on known AIS IQ recordings (Ubuntu 20.04 and 24.04).
- Validate the receiver's channel/frequency-shift signs and tune as needed.
- Integrate live SDR RX with FISSURE hardware selection/resource claiming.
- Generate a proper AIS GMSK IQ recording and attempt IQ->decode roundtrip
  using the new `ais_iq_loopback` Action (v0.4). This still needs actual
  GNU Radio 3.8 host validation; see `IQ_LOOPBACK.md`.
- Verify the GNU Radio 3.8 adapter and stdout behavior on an actual
  Ubuntu 20.04 host (not available in this build environment).
- Add a separately gated/isolated lab RF transmission mode only when properly
  authorized and verified. Never radiate fabricated identities or location
  reports on operational maritime AIS frequencies.
