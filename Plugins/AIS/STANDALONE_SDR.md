# Archived AIS development notes (pre-v1.0)

> **Historical reference only.** Some sections below describe old
> receiver variants, manual frequency-correction parameters, or
> installation experiments that are no longer part of the current
> plugin. For AIS **v1.0** behavior and instructions, see [README.md](README.md).

---

v0.9.13: B210 streaming receive on GNU Radio 3.10 applies RX Correction to
UHD center tuning (e.g., 915000000 - 3000 = 914997000 Hz), unlike other
receive paths which use a DSP channel offset. This matches the working GRC
lab experiment. Do not interpret the offset as an OS-wide calibration.

# Current standalone receiver behavior (v0.9.10)

B210/HackRF/RTL-SDR receive **never record IQ**. They always use a single
continuous hardware-to-decoder pipeline, regardless of duration. Duration 0
runs until Stop; positive durations stop after that many wall-clock seconds.
AIS Detections and Targets update while the Action runs, and only a bounded
session-summary JSON Artifact is retained when it ends. No temporary IQ is
created for these Actions. The IQ File Decode and explicit hardware loopback
Actions are separate, deliberate test/recording workflows.

The optional **RX Correction (Hz)** field adjusts baseband channel-selection
frequencies without changing the hardware tuner; normally use zero. During
an isolated two-SDR 915 MHz test, `2700` is a useful diagnostic trial based on
an earlier measured receive signal displacement. It does not automatically
calibrate the SDR clock. Receiver antenna ports must still match cabling,
and all cabled RF tests need appropriate attenuation.

The sections below document previous releases and their historical behavior;
where they discuss 20-second segmented captures, that behavior was removed
from the standalone receive Actions in v0.9.10.

---

# v0.9.1 — FISSURE status callback and cross-device testing

- Corrected hardware Action status callbacks in Tactical and Single Action by
  passing the FISSURE `(node_uid, opid, status_text)` signature. A resilient
  adapter also supports one- and two-argument test callbacks without relying
  on possibly incorrect signature inspection or cached parent modules.
- TX and RX **must use the same RF center frequency** when testing between
  separate devices. TX defaults to **915 MHz isolated lab**, while RX defaults
  to **162 MHz**, suitable for ordinary AIS listening. Set the receiver to the
  same legal laboratory frequency for synthetic IQ replay, with physical
  attenuation and proper RF isolation. Never transmit synthetic AIS on
  live maritime AIS channels.
- Streaming acquisition, sample conversion, demodulation, gain settings,
  vessel Detections/Targets, and monitoring-summary Artifacts are unchanged.

---

# v0.9.0 — Persistent, gap-free-by-design AIS reception

The **default `duration_s=0`** now starts one persistent RF receiver and GNU
Radio AIS demodulator, instead of restarting acquisition every 20 seconds.
While the Action is active, decoded AIS NMEA is immediately published to
FISSURE Detections (rate-limited) and per-MMSI vessel Targets. **No temporary
or retained IQ file is created** in streaming mode. Stop ends the stream and
creates one compact JSON session-summary Artifact containing the latest state
of each vessel. This does not make an Artifact for each message or boat.

| Duration | Mode | IQ files | Artifacts |
|---|---|---|---|
| `0` (default) | Continuous streaming until FISSURE Stop | None | One JSON summary at Stop |
| `1`–`120` seconds | Original finite IQ capture/decode for troubleshooting | Retained as an IQ Artifact | IQ + decoded observations |
| `121`–`86400` seconds | Persistent streaming for specified wall-clock time | None | One JSON summary when finished |

**Device-specific RF pipelines:**

- **B210 RX2**: UHD source -> GNU Radio `gr-ais` demodulator directly at the
  selected 240 kS/s sample rate. Never stops reception for a decoding phase.
- **RTL-SDR**: `rtl_sdr -` continuously writes 2.4 MS/s unsigned 8-bit IQ
  samples to stdout; fixed-size IQ buffers are converted/resampled to 240 kS/s
  and streamed to a *single* persistent GNU Radio `gr-ais` decoder.
- **HackRF**: `hackrf_transfer -r -` continuously writes 2.4 MS/s signed
  8-bit IQ samples. The same in-memory resampler and GNU Radio demodulator
  are reused. HackRF is still half-duplex.

The RTL/HackRF implementation avoids the observed mixed-install
`gr-osmosdr` ABI error; GNU Radio and `gr-ais` are still required for decoding.
The native capture program and GNU Radio decoder remain running continuously.
Their stdout streams contain **only IQ and NMEA**, respectively; the plugin
never writes the streaming IQ to disk. This eliminates the deliberate capture /
decode gaps present in v0.8.4. USB overruns or a slow CPU can still drop samples;
hardware performance must be verified on the executing node.

**Detection traffic control:** A new **Streaming Detection Interval per MMSI**
setting defaults to **30 seconds** for live streaming, or `0` to publish a
Detection for every decoded message. All valid messages still contribute to
vessel state, message counts and Target updates; only duplicate Detection
publishing is throttled. This helps keep the Detection database manageable in
busy waterways. Existing nonstreaming/offline Actions are unchanged.

**Status and shutdown:** The Action reports decoded-message and unique-vessel
counts every 15 seconds, stops its capture and decoder subprocesses when Stop
is pressed, and releases its per-device hardware lock. Unexpected RF subprocess
termination is reported as a failure rather than as a successful zero-message
capture. On completion the summary marks `streaming_mode=true`,
`capture_segments=0`, `capture_gaps_possible=false`, and `raw_iq_archived=false`.
The completion reason is saved whether it finished, stopped, or errored.

Run `python3 -c "import numpy, scipy, pyais"` to check Python dependencies, and
`command -v rtl_sdr` / `command -v hackrf_transfer` for native receiver tools.
You can also test the offline decoder with `python3
Plugins/AIS/scripts/ais_iq_decoder.py --probe`. Restart the FISSURE Sensor
Node after installing so it uses the new streaming Action classes.

**Compatibility (v0.9.7 candidate):** GNU Radio 3.8 receives via
`ais.ais_rx`; 3.10 uses the bkerler `ais_demod.grc` DSP chain in the plugin and installed `gnuradio.ais.pdu_to_nmea`
without a generated graph. Actual 24.04 hardware/decoding validation is still
required. Automated tests validate subprocess lifecycle,
resampling, streaming Action dispatch and Artifact behavior without hardware.
The new persistent RF paths still require live B210/HackRF/RTL-SDR validation.

---

## v0.8.4 continuous-session summary and duration fix

Duration `0` is accepted in the HackRF, RTL-SDR, and B210 receive Actions,
even if the Sensor Node retains an older `ais_osmosdr_receive`/`ais_sdr_receive`
module in Python's import cache. Continuous mode still uses 20-second *finite*
IQ capture/decode segments, with reception gaps between segments. At Stop or
completion, one small `ais_rx_monitor_summary` Artifact is created containing
aggregate counts and latest per-MMSI vessel information. Temporary IQ is
removed after each segment; no raw IQ is archived in continuous mode. A
finite duration of 1–120 seconds still saves detailed capture Artifacts.
Live no-gap stream decoding is a separate future architectural improvement.

## v0.8.2 GNU Radio 3.8 mixed-install capture workaround

On the verified Ubuntu 20.04 system, `gr-osmosdr` identifies its build as
GNU Radio 3.8.1.0 while the installed GNU Radio Python runtime identifies
3.8.5.0. Both HackRF and RTL receiver flow graphs failed at startup with
`RuntimeError: list contains invalid format!`. That is consistent with an ABI
mismatch and does **not** mean the SDRs were absent: the log enumerated both.

The receive Actions now use native **receive-only** utilities if installed:
`rtl_sdr` (unsigned interleaved 8-bit IQ) or `hackrf_transfer` (signed
interleaved 8-bit IQ). Their finite capture is then converted into complex64
and anti-alias decimated using NumPy/SciPy (2.4 MS/s -> 240 kS/s), then passed
to the same `gr-ais` AIS decoder and FISSURE Artifact/Target pipeline. This
bypasses the incompatible `gr-osmosdr` *source* blocks. If neither vendor
utility is found, the legacy `gr-osmosdr` capture is attempted with a
more specific diagnostic. The HackRF transmit implementation is unchanged.

No Action parameters need changing. To check native dependencies:

```bash
command -v rtl_sdr
command -v hackrf_transfer
python3 -c "import numpy, scipy; print(numpy.__version__, scipy.__version__)"
python3 Plugins/AIS/scripts/ais_osmosdr_hardware.py --probe
```

For a standalone **receive-only** hardware test (does not transmit RF):

```bash
python3 Plugins/AIS/scripts/ais_osmosdr_hardware.py --mode rx --device rtl \
 --capture-backend native --output /tmp/ais_rtl.cf32 \
 --manifest /tmp/ais_rtl.json --duration-s 5
```

Replace `rtl` with `hackrf` to test the HackRF receiver; default device
selectors are `rtl=0` and `hackrf=0`. The output file should contain complex64
IQ with a 240 kS/s effective rate. Presence of samples does not guarantee AIS
decoding when no actual AIS signal is present. The user confirmed that HackRF and RTL-SDR receive Actions now start and capture; message decoding and cross-radio verification remain to be tested.

For a lasting fix rather than the native-utility workaround, rebuild
`gr-osmosdr` against the *active* GNU Radio installation in a consistent
build environment, avoiding `/usr` versus `/usr/local` mixtures. Do not purge
unrelated SDR packages merely to make this plugin work.

---

# AIS hardware-specific Actions — v0.8.0 (Ubuntu 20.04, GNU Radio 3.8)

The hardware Actions are named explicitly. The previous generic `ais_sdr_transmit` and `ais_sdr_receive` names have been retired from the Action list. Their implementation files remain as internal compatibility helpers for the B210 Actions.

| FISSURE Action | Radio | Direction | RF hardware rate | AIS IQ rate |
|---|---|---|---:|---:|
| `ais_usrp_b210_transmit` | USRP B210 | TX | 240 kS/s | 240 kS/s |
| `ais_usrp_b210_receive` | USRP B210 RX2 | RX | 240 kS/s | 240 kS/s |
| `ais_hackrf_transmit` | HackRF One | TX | 2.4 MS/s | 240 kS/s |
| `ais_hackrf_receive` | HackRF One | RX | 2.4 MS/s | 240 kS/s |
| `ais_rtlsdr_receive` | RTL-SDR | RX | 2.4 MS/s | 240 kS/s |
| `ais_b210_loopback` | Single B210 | simultaneous TX/RX | 240 kS/s | 240 kS/s |
| `ais_iq_offline_loopback` | No hardware | offline | — | 240 kS/s |

HackRF TX interpolates 240k to 2.4M; HackRF/RTL receivers decimate 2.4M to 240k before calling the *existing* GNU Radio `gr-ais` 3.8 decoder. The AIS frame encoder, NMEA parser, detections, Target handling and artifact pipeline are shared. The HackRF is half-duplex; a single HackRF cannot transmit and receive at the same time.

## Installation

Extract the ZIP at the FISSURE repository root and overwrite existing plugin files. Restart the Sensor Node and refresh the AIS plugin, since older Python imports may remain cached in a long-running Sensor Node process. The old general SDR operation files in `Plugins/AIS/operations` remain intentionally for the B210 wrappers and should not be removed.

## No-RF probes

```bash
python3 Plugins/AIS/scripts/ais_sdr_hardware.py --probe
python3 Plugins/AIS/scripts/ais_osmosdr_hardware.py --probe
hackrf_info
rtl_test -t
uhd_find_devices
```

The first two commands only test Python GNU Radio block availability; they do not open radios. `hackrf_info`, `rtl_test -t`, and `uhd_find_devices` individually inspect the relevant radio(s), if installed.

## Testing two different radios on one computer

These distinct SDRs can run concurrently under the AIS plugin's per-device advisory locks:

1. HackRF TX + RTL-SDR RX (same isolated laboratory frequency).
2. B210 TX + HackRF RX (same isolated laboratory frequency).
3. B210 TX + RTL-SDR RX (same isolated laboratory frequency).
4. HackRF TX + B210 RX2 (same isolated laboratory frequency).

Use `ais_b210_loopback` for one B210 transmitting and receiving together; the two standalone B210 Actions intentionally lock one another out. One HackRF is half-duplex and its receive and transmit Actions also lock one another out. RTL-SDR has no transmit Action.

Start the RX Action (`duration_s=0` runs until stopped), then start TX on the other radio. The TX Action generates the finite IQ waveform before it starts the radio stream, so leave enough time for generation and for the SDR to initialize. Both Actions must have **the same RF center frequency**, e.g. a properly authorized isolated 915 MHz lab connection. The RX Actions default to 162 MHz for receiving *legitimate real AIS traffic*; retune to the laboratory center for a test replay.

**Important physical safety:** A direct TX-to-RX cable without rated external attenuation can exceed the receiving SDR's maximum input power and damage it. A TX gain of zero does not imply zero output power. Do not use the unattenuated B210 connection described during earlier tests for a new cross-radio test. Use a properly characterized, adequately attenuated coaxial setup with no antennas, or run RX-only and offline IQ tests until one is available. Transmitting AIS on operational maritime frequencies is not part of these tests.

## Gain configuration

- `ais_usrp_b210_transmit` — 60 dB default TX gain (retains previous setting; **not a safe recommended level** for unattenuated connections), 915 MHz lab frequency.
- `ais_usrp_b210_receive` — 70 dB default gain on RX2, 162 MHz default for live AIS, switch to lab frequency for tests.
- `ais_hackrf_transmit` — 10 dB *IF/VGA* gain, amp off; adjustable 0–47 dB. HackRF gains differ from UHD gains.
- `ais_hackrf_receive` — independent LNA (16 dB) and VGA (16 dB) controls; RF amp off.
- `ais_rtlsdr_receive` — single tuner-gain setting (35 dB), adapter chooses supported step.

The independent TX Actions have `Save TX Waveform Artifact=false` by default. **In v0.9.10 every standalone receive duration is streaming only:** no saved IQ files, no segment recording gaps, one monitoring-summary Artifact at completion. Combined B210 and explicit IQ loopback Actions retain their diagnostic IQ Artifacts.

If the receiver is tuned outside the AIS maritime frequencies, the plugin automatically marks any decoded AIS observations as **simulated** (laboratory replay), even when the user leaves `simulated_input=false`. Ordinary 162 MHz reception is not automatically simulated.

## Compatibility and validation

The existing B210 combined loopback and 240 kS/s offline roundtrip have been verified by the user on Ubuntu 20.04 with GNU Radio 3.8.5.0. New HackRF/RTL-SDR TX/RX hardware paths have mock-based automated tests but **have not yet been validated with physical radios**. The first 24.04/3.10 source compatibility pass is included in v0.9.7;
physical device and decoder validation remains pending.

This package intentionally preserves existing operation script names used for Python imports. Remove stale plugin directories only after moving these compatibility dependencies or after a full deployment migration.


## v0.8.1 Action compatibility filtering

FISSURE `ACTION_HARDWARE` matches configured Sensor Node hardware type names:
B210 -> `USRP B2x0`; HackRF -> `HackRF`; RTL-SDR -> `RTL2832U`.
If a hardware-specific Action is missing from the Dashboard, check the Sensor
Node hardware configuration (not merely USB enumeration), refresh the plugin,
and restart the Sensor Node. These filters are not hardware reservations.


## v0.8.3 indefinite AIS reception

Hardware RX Actions accept `duration_s=0` (**new default**) to monitor until Stop. They repeat bounded 20-second capture/decode segments and delete each segment's temporary IQ after decoding. Capture and decoding are sequential, not simultaneous: transmissions can be missed during decode gaps. For a single captured IQ Artifact, use a finite duration from 1 through 120 seconds. Longer positive durations are segmented and publish Detections and Targets without IQ archiving. The original hardware gain defaults remain unchanged.

Nonhardware Action labels are now `ais_nmea_udp_file_receive`, `ais_nmea_udp_simulate`, `ais_iq_file_decode`, and `ais_iq_offline_loopback`. These use the existing internal Operation scripts; saved Action-name references should be updated. The UDP NMEA listener itself also supports duration 0 (until stopped).

## v0.9.3 repeat standalone RF TX

B210 and HackRF TX expose `repeat_count=0` (default, until Stop) and
`repeat_pause_s=2` (0–60s). Each batch runs the verified finite hardware TX
script with the *same* IQ and MMSIs; the hardware stream is restarted between
batches, so there are short gaps. A finite positive repeat count completes
without needing Stop. Underlying capture/streaming RX paths are unchanged.
Do not transmit AIS at a real maritime channel, or replay at a lab channel
without legally authorized RF isolation, attenuation and power budget.
