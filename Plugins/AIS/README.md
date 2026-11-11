# AIS Plugin for FISSURE — v1.0

The AIS plugin adds maritime Automatic Identification System (AIS) reception,
synthetic signal transmission, NMEA ingestion, and offline IQ analysis to
[FISSURE](https://github.com/ainfosec/FISSURE), an open-source RF and cyber
experimentation framework. It provides hardware-specific Actions in the FISSURE
Tactical interface and publishes decoded vessel observations as **Detections**,
per-vessel **Targets**, and managed **Artifacts**.

This is the **first public release** of the plugin. It supports Ubuntu 20.04
(GNU Radio 3.8) and Ubuntu 24.04 (GNU Radio 3.10) with separate, compatible
AIS demodulator implementations. Live RF reception has been exercised with
USRP B210, HackRF One, and RTL-SDR. Re-run a short hardware acceptance test on
your particular radios and installation; the two GNU Radio versions are not
identical internally.

## Capabilities

| Action | Purpose | RF hardware |
| --- | --- | --- |
| **USRP B210 Receive** (`ais_usrp_b210_receive`) | Continuous dual-channel AIS monitoring | B210 RX |
| **HackRF Receive** (`ais_hackrf_receive`) | Continuous dual-channel AIS monitoring | HackRF RX |
| **RTL-SDR Receive** (`ais_rtlsdr_receive`) | Continuous dual-channel AIS monitoring | RTL-SDR RX |
| **USRP B210 Transmit** (`ais_usrp_b210_transmit`) | Repeating synthetic AIS RF test batches | B210 TX |
| **HackRF Transmit** (`ais_hackrf_transmit`) | Repeating synthetic AIS RF test batches | HackRF TX |
| **B210 Loopback** (`ais_b210_loopback`) | Combined B210 TX/RX test | One B210, externally connected/attenuated |
| **NMEA UDP/File Receive** (`ais_nmea_udp_file_receive`) | Decode existing AIS NMEA without an SDR | None |
| **NMEA UDP Simulate** (`ais_nmea_udp_simulate`) | Generate test NMEA over localhost UDP | None; no RF |
| **IQ File Decode** (`ais_iq_file_decode`) | Decode a local complex64 IQ recording | None |
| **Offline IQ Loopback** (`ais_iq_offline_loopback`) | Build and decode synthetic AIS IQ | None; no RF |

Actions are filtered by configured Sensor Node hardware where applicable.
HackRF is half-duplex: use a separate receiver for simultaneous TX/RX tests.
The B210 loopback Action opens its own combined transmit/receive flowgraph.

## AIS channels and frequency selection

The two standard AIS data channels are:

| AIS channel | Nominal maritime frequency | Position relative to RF center |
| --- | --- | --- |
| AIS 1 / A (87B) | **161.975 MHz** | **−25 kHz** |
| AIS 2 / B (88B) | **162.025 MHz** | **+25 kHz** |
| RF center for both | **162.000 MHz** | 0 kHz |

All live SDR **Receive** Actions use both AIS channels at once, with a
separate decoder for A and B. Set **RF Center** to **162000000** Hz to listen
to the standard AIS frequencies. You do **not** select a single AIS channel
by tuning the radio to 161.975 or 162.025 MHz.

The synthetic RF Transmit Actions retain the same *relative* ±25 kHz channel
spacing around a configurable laboratory center. For an **authorized, isolated
915000000 Hz test**, transmitted AIS A appears nominally at **914.975 MHz**
and AIS B at **915.025 MHz**. Set the separate receiver to the **same RF
center**, 915000000 Hz. These are synthetic signals, **not** ordinary marine
AIS transmissions.

**Safety:** Do not transmit test AIS messages on 161.975/162.025 MHz or into
public RF channels. RF transmission requires appropriate authorization and a
shielded or appropriately attenuated laboratory path. An unattenuated direct
coax connection can damage a receiver. The plugin cannot verify the physical
attenuation or isolation. Receive-only monitoring is separate from these
transmit restrictions.

## How live reception works

```text
B210 (UHD) ──────────────────────┐
HackRF (hackrf_transfer, IQ8) ────┼─> continuous complex IQ
RTL-SDR (rtl_sdr, IQ8) ──────────┘              │
                                   optional IQ8 conversion/resampling
                                               │
                               ┌───────────────┴───────────────┐
                               ▼                               ▼
                         AIS A: −25 kHz                   AIS B: +25 kHz
                         channel selection                channel selection
                               │                               │
                       frequency recovery*              frequency recovery*
                               │                               │
                       AIS GMSK demodulation             AIS GMSK demodulation
                       + HDLC/FCS decode                + HDLC/FCS decode
                               └───────────────┬───────────────┘
                                               ▼
                                    decoded AIS NMEA sentences
                                               ▼
                              pyais / FISSURE observation handling
                                    │                 │
                                Detections          Targets
                                    └────────┬────────┘
                                       JSON summary Artifact
```

`*` Frequency synchronization is implemented differently on GNU Radio 3.8
and 3.10 (details below). Both branches share AIS message parsing, Detection,
Target and Artifact handling.

**Continuous streaming:** Receiver hardware and decoder stay active for the
whole Action. **Duration = 0** runs until Stop; a positive Duration sets a
wall-clock limit. Ordinary live Receive Actions **do not record raw IQ**, even
for short positive durations. The receiver uses bounded buffers rather than
repeated 20-second captures. Stopping releases the hardware process and saves
a compact monitoring-summary JSON Artifact rather than a file for every AIS
message. Native HackRF/RTL-SDR receivers use a subprocess group so the radio
and decoder are stopped together.

**Sample rates:** On GNU Radio 3.10, B210 uses a 200 kS/s reference receive
profile. HackRF acquires at 2.4 MS/s and is decimated internally to 200 kS/s
for demodulation. RTL-SDR acquires at 2.4 MS/s and supplies a 240 kS/s
baseband stream. Hardware acquisition rates should not be confused with the
symbol rate (**9,600 bit/s**) or the per-channel demodulator rate.

**GNU Radio 3.8 (Ubuntu 20.04):** Uses the installed legacy `gr-ais`
`ais.ais_rx` receiver hierarchy for each channel, including its established
carrier synchronization and AIS packet decoding.

**GNU Radio 3.10 (Ubuntu 24.04):** The installed `gnuradio.ais` / `gr-ais`
maint-3.10 fork provides decoding blocks, but not the same Python `ais_rx`
hierarchy. FISSURE builds the equivalent demodulator flowgraph from the
published 3.10 GRC design. The live receiver adds **burst-aware square-and-FFT
carrier recovery**: it identifies actual RF bursts, estimates short carrier
offsets with a 256-sample FFT, delays the input by approximately 20 ms so
correction applies from the beginning of the burst, and retains the last
reliable correction during silence. A wider pre-correction channel passband
preserves offset signal energy; the narrower AIS filter runs **after**
correction. There is **one continuous decoder per AIS channel**—no scanning,
parallel acquisition candidates, or manual frequency-correction Action field.

## How synthetic RF transmission works

```text
Simulated vessel identities/positions (MMSIs, lat/lon, static data)
                 │
        pyais-generated NMEA (Type 24 static + Type 18 position)
                 │
        AIS payload framing: HDLC / FCS / NRZI
                 │
        GNU Radio GMSK (BT 0.4, 9,600 bit/s)
                 │
        place each burst at −25 kHz (A) or +25 kHz (B)
                 │
        finite complex64 IQ waveform (240 kS/s baseband)
                 │
       B210 UHD TX or HackRF TX backend at laboratory RF center
                 │
        repeat finite batches until Stop or batch count
```

The TX implementation uses FISSURE's finite AIS framing and GNU Radio's
GMSK modulator; it does **not** depend on the old `gr-aistx` frame-builder
path. By default the Action creates **three simulated vessels**, three
position reports per vessel plus Type 24 identity data, and alternates vessels
between AIS A and B. Individual frames are separated by a configurable gap
(350 ms by default). A single generated waveform is reused for repeated
batches rather than regenerated every time. **Repeat Batches = 0** continues
until Stop; the internal pause between batches defaults to 2 seconds.

TX hardware defaults are **915 MHz center**, **B210 TX gain 60 dB**, and
**HackRF TX gain 40 dB**; these are software defaults, **not safe power
recommendations**. Select appropriate RF levels and external attenuation
for your lab. The HackRF TX implementation can use a native or gr-osmosdr
backend depending on the runtime. TX waveform Artifacts are optional and
**off by default**; temporary generated IQ used for actual RF transmission
is distinct from normal receive streaming.

The **Offline IQ Loopback** performs the same synthetic NMEA-to-IQ-to-decoder
exercise without keying an SDR. The **B210 Loopback** explicitly uses TX/RX
and RX2 paths in one device; it still requires a suitable external RF
connection and attenuation. **NMEA UDP Simulate** sends decoded NMEA via
loopback UDP only—never RF.

## FISSURE outputs and provenance

- **Detections** are emitted from decoded observations, with a **5-second
  per-MMSI, per-message-class** rate limit for live streaming. Static
  messages and position messages have separate limits so identity reports do
  not suppress position observations. For RF reception, Detections include
  `frequency_hz` for the *nominal* AIS A/B channel center when known. If the
  decoded channel is unavailable, the known SDR **center** is reported with
  `frequency_semantics=receiver_center_channel_unknown` instead of guessing.
- **Targets** maintain the latest vessel identity, position, and observation
  state by MMSI. AIS coordinates are **self-reported vessel locations, not
  independent RF geolocation**. Test vessels are marked as simulated.
- **Artifacts** from live Receive Actions contain a compact JSON monitoring
  summary with message/MMSI counts, latest vessel state, receiver diagnostics,
  Stop reason, and `metadata.detection_delivery` callback statistics.
  `callback_succeeded` records the plugin's handoff to FISSURE; it does not
  by itself prove that the Tactical UI displayed a row.
- **NMEA-only UDP/file** input has no inherent tuned RF center and does not
  fabricate one. **Offline IQ Decode** can attribute nominal channel
  frequency when the recording's center frequency is supplied.

## Installation and compatibility

1. Copy the complete `Plugins/AIS` directory into the FISSURE plugin
   location on the relevant Sensor Node. Restart the Sensor Node after
   replacing an earlier version, then refresh/re-query the available Actions.
2. Install **`pyais`** and the matching GNU Radio / `gr-ais` build for the
   system Python used by that Sensor Node. Ubuntu 20.04 uses GNU Radio 3.8
   and the legacy `import ais` API; Ubuntu 24.04 uses GNU Radio 3.10 and
   `from gnuradio import ais` from the compatible maint-3.10 build.
3. For **B210**, ensure working UHD and GNU Radio UHD Python bindings; for
   **HackRF**, the `hackrf_transfer` utility; for **RTL-SDR**, `rtl_sdr`.
   Native streaming also requires Python **NumPy** and **SciPy**. HackRF TX
   can additionally use gr-osmosdr where available.
4. Configure the Sensor Node hardware so the B210/HackRF/RTL-SDR Actions are
   discoverable. B210 RX allows hardware RF channel 0 (A:A) or 1 (A:B), RX
   antenna **TX/RX** (default) or **RX2**, and an optional UHD serial. These
   **B210 hardware channels are not AIS radio channels A and B**. HackRF
   Device Args may be left blank to select the first available device.

The plugin's `setup.py check` checks `pyais` availability; its `install` and
`cleanup` hooks **do not install or remove host packages**. Use the FISSURE
installation workflow for SDR/GNU Radio dependencies. Do not mix different
Python environments or incompatible GNU Radio out-of-tree builds.

## Quick acceptance test (isolated RF lab)

1. Install the plugin on the transmitting and receiving Sensor Nodes;
   restart/re-query Actions after updating the files.
2. On a physically isolated or adequately attenuated test path, select a
   **B210 Transmit** or **HackRF Transmit** Action at **915000000 Hz**.
   Use the default three simulated vessels and **Repeat Batches = 0**.
3. Start a separate **HackRF**, **RTL-SDR**, or **B210 Receive** Action at
   **915000000 Hz**. Leave its **Duration = 0** to run until Stop. In practice,
   starting the receiver before transmit is useful for acquisition testing.
4. Confirm **all three Targets** update and that **position Detections** are
   visible. AIS A should report **914975000 Hz** and B **915025000 Hz**.
5. Stop Receive; confirm the SDR closes and inspect the JSON Artifact,
   including `metadata.decoded_messages`, `metadata.unique_mmsi`, and
   `metadata.detection_delivery`. Repeat Start/Stop to check process cleanup.
6. Repeat receive checks with each supported SDR. For the Ubuntu 20.04
   regression, verify its receive **frequency field** as well as Detections,
   Targets, Stop, and Artifacts.

If Targets update but Detections are absent, inspect
`metadata.detection_delivery` to distinguish messages throttled in the plugin
from callbacks handed to FISSURE but filtered downstream. If there are no
messages, check center frequency, antenna selection, gain, SDR process logs,
Python/GNU Radio version compatibility, and whether the transmitter is
actually sending repeated batches. B210 serial/RF connector selection and
HackRF USB connection are common hardware checks.

## Additional reference notes

- [GNU Radio 3.8/3.10 compatibility](DUAL_GNURADIO_3_8_3_10.md)
- [Standalone SDR implementation history](STANDALONE_SDR.md)
- [Offline IQ receiver](IQ_RECEIVER.md) and [offline IQ loopback](IQ_LOOPBACK.md)
- [B210 loopback](B210_LOOPBACK.md)

These companion documents contain **development history** and may mention
retired test configurations. This v1.0 README and the live Action schema in
`actions.py` describe the current release; use those instead of obsolete
manual frequency-correction guidance from pre-release notes.
