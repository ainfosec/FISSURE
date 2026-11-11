# Archived AIS development notes (pre-v1.0)

> **Historical reference only.** Some sections below describe old
> receiver variants, manual frequency-correction parameters, or
> installation experiments that are no longer part of the current
> plugin. For AIS **v1.0** behavior and instructions, see [README.md](README.md).

---

Current release v0.9.25: preserve the working 3.10 carrier recovery and
whole-process-group Stop. Fix live Detection visibility by separating static
and position rate limits, defaulting to 5s per MMSI/class, and adding nominal
AIS A/B channel frequencies to Detection payloads. No receiver/transmitter
DSP changes, installer changes, or Action control additions.

Current release v0.9.24: preserves the validated v0.9.23 single-chain
carrier-recovery receiver on GNU Radio 3.10. Native streaming Stop now
terminates the complete child process group (HackRF/RTL-SDR and decoder),
with Detection callback handoff/throttle counts in the JSON summary.
The installer and manual frequency Action parameters remain unchanged.

Current release v0.9.23: GNU Radio 3.10 retains one AIS A decoder and one
AIS B decoder with burst-aware carrier recovery. The resampler now preserves
wider signal bandwidth until after CFO correction, then applies the usual
narrow channel filter; startup noise estimation is robust to initial zero
samples. No manual frequency parameters, parallel receivers, IQ recordings,
or installer changes. GNU Radio 3.8 keeps its original receiver.

---

Current release v0.9.22: GNU Radio 3.10 streams one AIS A decoder and one
AIS B decoder. Burst-aware square-and-FFT carrier recovery runs before AGC,
with 256-sample frequency estimates and a 768-sample lookahead that corrects
the beginning of short bursts. The correction is held through silence; no
manual frequency controls, parallel decoder hypotheses, or IQ recording.
GNU Radio 3.8 continues to use the original gr-ais `ais.ais_rx` hierarchy.
No installer changes.

---

Current release v0.9.21: normal B210/HackRF/RTL-SDR receive Actions use
single-chain frequency recovery.  GNU Radio 3.8 uses its original gr-ais
`ais.ais_rx` hierarchy; GNU Radio 3.10 uses one channel receiver for A and
one for B with the installed `square_and_fft_sync_cc` carrier synchronizer.
No multi-candidate Python AFC is active, and no manual RX correction parameter
is exposed.  The installer does not change.

Current release v0.9.20: all normal B210/HackRF/RTL-SDR receive Actions
use automatic GNU Radio 3.10 AFC with no user-facing RX Correction parameter.
The legacy manual-correction guidance below is historical only.

---

Note for v0.9.13: On B210 streaming receive with GNU Radio 3.10,
`RX Correction (Hz)` changes the UHD hardware tune frequency (requested RF
center + correction); it is not also applied to DSP channel offsets. Other
receive paths retain DSP correction. This behavior is a focused RF test.

# v0.9.10 receive compatibility update

- Standalone B210/HackRF/RTL-SDR RX uses one streaming decoder for every
  duration; raw IQ is not captured or archived by these Actions.
- GNU Radio 3.10 timing recovery uses the 0.05 loop bandwidth of the installed
  `bkerler/gr-ais` maint-3.10 `apps/ais_demod.grc`.
- `RX Correction (Hz)` provides a signed, manual DSP offset for diagnosing
  oscillator errors (default 0); it is not automatic carrier tracking.
- The 24.04 installer correction uses CMake C++17 variables and checks the
  Python module import; a successful module import alone does not validate
  packet decoding from actual RF.

---

## Earlier compatibility notes

# AIS v0.9.8: GNU Radio 3.8 + 3.10 compatibility preflight

This is a **plugin-only** compatibility candidate. The existing Ubuntu 20.04 /
GNU Radio 3.8 pipeline is the proven reference. Ubuntu 24.04 / GNU Radio
3.10 has not been tested on physical radios in this release.

## Required runtime packages

- On Ubuntu 20.04: existing matching 3.8 `gr-ais` with `import ais`,
  `ais.ais_rx`, and `ais.pdu_to_nmea`.
- On Ubuntu 24.04: GNU Radio 3.10 + compiled
  https://github.com/bkerler/gr-ais matching that GNU Radio/Python
  environment, providing `from gnuradio import ais` and `ais.pdu_to_nmea`. The
  plugin builds the receiver core from the published bkerler
  `apps/ais_demod.grc` DSP chain.
- For B210: the matching GNU Radio UHD bindings (`from gnuradio import uhd`).
- For HackRF TX and optional finite gr-osmosdr fallback: the matching
  `osmosdr` Python bindings and GNU Radio `filter.rational_resampler_ccc`.
- For the RTL-SDR/HackRF live RX path: `rtl_sdr` / `hackrf_transfer` CLI
  utilities and Python `numpy`, `scipy`, `pyais`.

Use the **same Python interpreter** as the Sensor Node. Mixing /usr and
/usr/local GNU Radio or OOT packages can produce ABI errors.

## Preflight: no RF transmission, no SDR opened

From the FISSURE root:

```bash
python3 Plugins/AIS/setup.py check
python3 Plugins/AIS/scripts/ais_iq_generator.py --probe
python3 Plugins/AIS/scripts/ais_iq_decoder.py --probe
python3 Plugins/AIS/scripts/ais_sdr_hardware.py --probe
python3 Plugins/AIS/scripts/ais_osmosdr_hardware.py --probe
python3 -c 'from gnuradio import gr; print(gr.version())'
```

The UHD and gr-osmosdr probes do **not** start an RF transmitter. The
osmosdr probe may fail if that optional OOT is absent. On 24.04 the IQ
decoder probe specifically checks for updated `installed GNU Radio 3.10 AIS blocks`.

## Suggested 24.04 test order

1. Install v0.9.8, restart the Sensor Node, and verify the probes above.
2. Run **AIS Offline IQ Loopback** for three synthetic vessels (no RF);
   verify the expected decoded messages, simulations, Targets and Artifacts.
3. Run **AIS IQ File Decode** using a known-good 20.04 complex64 AIS IQ file.
4. Run receive-only **RTL-SDR Receive** (or HackRF Receive) at an authorized
   test frequency, then stop and inspect the single Monitoring Summary.
5. Only after passive/offline checks pass, test the **B210/HackRF TX** with
   an appropriately attenuated, isolated and authorized non-maritime RF
   setup and a separate SDR receiver. Test repeating TX and clean Stop.
6. Run B210 hardware loopback last, using a verified receiver-safe RF path.

Never broadcast synthetic AIS vessel identity/location reports on live
maritime AIS channels. Gain settings do not establish a safe RF power level.

## How the GNU Radio versions differ

- 3.8: `import ais; ais.ais_rx(offset_hz, sample_rate, channel)`
- 3.10: `from gnuradio import ais; ais.pdu_to_nmea(channel)` with in-plugin
  DSP core reconstructed from the enabled blocks of bkerler `ais_demod.grc`

Both integrate into the plugin's Python GNU Radio graph directly, without
GRC-generated `ais_rx_core.py` or the old FISSURE Flow Graph Library.
The modulation helper uses `gnuradio.digital.gmsk_mod` in both versions;
UHD and gr-osmosdr use their existing Python block constructors.

## Information to capture on a 24.04 failure

Collect the first actual traceback, especially errors from the `--probe`
commands, along with:

```bash
python3 -c 'import sys; from gnuradio import gr; print(sys.version); print(gr.version())'
python3 -c 'from gnuradio import ais; print(ais.__file__); print(hasattr(ais, "ais_rx"))'
python3 -c 'from gnuradio import uhd; print(uhd.__file__)'
python3 -c 'import osmosdr; print(osmosdr.__file__)'
```

A missing optional OOT should be handled separately from an actual AIS
modulator/demodulator incompatibility. Physical performance and full duplex
streaming are not asserted by the local mock-based test suite.


## v0.9.8 Ubuntu 24.04 correction

FISSURE 24.04 installer uses `bkerler/gr-ais` maint-3.10. The fork's
published `apps/ais_rx.py` imports a separate GRC-generated `ais_rx_core`
which is **not** exported from `gnuradio.ais`. Previous attempts to use
`ais_rx` or `ais_demod` directly failed at startup. Version 0.9.8
implements the enabled `apps/ais_demod.grc` receive chain inside the plugin
using standard GNU Radio 3.10 blocks and `gnuradio.ais.pdu_to_nmea`.

The probe reports `backend=bkerler_core` when required blocks exist. This
checks import/readiness, not end-to-end IQ decode. The first physical-system
validation remains Offline IQ Loopback, then RTL-SDR/HackRF/B210 RX.

B210 receive defaults to TX/RX; RX2 remains selectable. Channel 0 = A:A,
channel 1 = A:B. USRP serial is optional; empty lets UHD discover.
