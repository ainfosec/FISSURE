# AIS B210 cabled RF loopback — GNU Radio 3.8 / 3.10 compatibility candidate

## What this does

`ais_b210_loopback` runs one GNU Radio top block with both **UHD TX** and **UHD RX** on a **single USRP B210**. It reuses the same Python HDLC / GMSK complex64 IQ generator and gr-ais decode pipeline already validated in the offline Action.

The synthetic vessels are not real vessels and the RF center is **915 MHz by default**, not AIS Channel A/B. AIS A/B are represented as baseband offsets of -25/+25 kHz from the lab RF center. All generated vessel Detections and Targets retain `simulated=true`, and the AIS coordinates describe the **self-reported position in the synthetic packet**, not the physical B210 location.

## Physical configuration — read before running

**Important hardware warning:** The v0.6.4 interface does not ask for an
attenuation value or isolation confirmation. This removes only software fields;
it **does not** attenuate RF or protect the B210 receiver. The RX input-power
limit still applies regardless of TX/RX gain or software digital scaling.
**A direct TX/RX-to-RX2 coax connection without external attenuation can damage
the B210.** Physically verify the RF output power, receiver maximum input,
and adequate rated attenuation before running a transmitting Action. Use a
shielded, conducted setup without antennas; do not radiate maritime AIS data.

The Action accepts non-AIS laboratory RF center frequencies from 500 MHz to
3 GHz. Only **B210 TX Gain** and **B210 RX Gain** are user-adjustable gain
settings. The digital baseband scale is fixed internally at 0.15. No measured
attenuation or RF-path verification is asserted in the Artifact metadata.

## Readiness

On the **Sensor Node** running Ubuntu 20.04:

```bash
python3 Plugins/AIS/scripts/ais_iq_generator.py --probe
python3 Plugins/AIS/scripts/ais_iq_decoder.py --probe
python3 Plugins/AIS/scripts/ais_b210_loopback.py --probe
uhd_find_devices
```

`--probe` checks for GNU Radio 3.8/3.10 UHD blocks only; it never opens a radio or transmits. `uhd_find_devices` is a separate read-only UHD hardware discovery command.

## Action test

1. Establish a physically safe, appropriately attenuated conducted RF connection
   between B210 channel-0 TX/RX and channel-0 RX2. Do not use antennas.
2. Refresh/redeploy the AIS plugin in FISSURE and restart the Sensor Node to
   clear cached AIS helper modules.
3. On the B210 Sensor Node, run **AIS → `ais_b210_loopback`**. Defaults use
   sample rate **240000**, lab center **915000000**, TX gain **40**, RX gain **40**,
   and a fixed internal digital scale **0.15**. The TX gain interface accepts **0–90 dB** (in 0.5 dB steps) with no
   additional 40 dB software ceiling; UHD ultimately determines the actual
   supported hardware range. RX remains **0–60 dB**. A gain value is not an
   absolute RF output-power measurement.
4. The Action generates 15 synthetic AIS messages by default (3 vessels ×
   [Type 24A + Type 24B + 3 Type 18 positions]), then saves TX IQ, records
   RX IQ, decodes with `gr-ais`, and writes Artifacts and a validation report.
5. **Pass** requires exact recovered NMEA message content, MMSIs and names.
   Incomplete RF reception yields a failed validation report and retains RX IQ.

No software attenuation confirmation is required. That does not make an
unattenuated cable safe.

## Architecture

```text
Synthetic AIS NMEA → Python AIS HDLC/CRC/NRZI → GNU Radio GMSK IQ file
   → [two seconds leading silence, amplitude scale] → B210 TX/RX
   → [physically power-limited, conducted coax connection] → B210 RX2
   → RX complex64 file → gr-ais IQ decoder → FISSURE AIS decode
   → Detections / SIM Targets / Artifacts / final RF validation report
```

Both UHD source and sink exist in **one** GNU Radio top block. RF acquisition is saved as an IQ file before decoding so the RF timing problem can be diagnosed independently of packet parsing. RX capture uses a finite sample limit; the Action has a timeout and Stop handler.

## Limitations

- **Not an RF-decoding success yet.** A B210 host test completed an 11-second RX capture on 2026-11-07 but produced no detectable RF bursts and 0/15 AIS messages. UHD stream start-up and RX capture occurred, but actual transmitted energy reaching RX2 and packet recovery remain unverified.
- GNU Radio 3.10 is now accepted by the v0.9.6 UHD helper, but B210 hardware loopback is not verified on 24.04; test the offline loopback first.
- The plugin has an advisory lock preventing two copies of this AIS B210 loopback on the same node. It does not yet claim a FISSURE hardware resource or prevent other SDR tools outside this Action from using the B210. Stop other B210 tasks before testing.
- RF loopback is **not proof of AIS protocol RF compliance** or suitability to transmit on navigational AIS frequencies.
- The current hardware Action tests only physically looped-back, synthetic traffic; standalone receive/transmit Actions remain future work.

### v0.6.1 module naming

The public diagnostic command `scripts/ais_b210_loopback.py --probe` remains
available. The Action invokes `scripts/ais_b210_rf_hardware.py` internally to
avoid colliding with `operations/ais_b210_loopback.py` in Python's module cache.


## Diagnosing an RX capture with zero AIS messages

An Artifact containing RX IQ is evidence of a completed receive stream, not
necessarily evidence that RF was transmitted or received. Version 0.6.2
attaches `ais_b210_signal_diagnostics.json` to the B210 RX Capture Artifact and
records the signal-power summary in the final Validation Artifact.

The earlier 0/15 test showed approximately 0.000127 full-scale median RMS,
with only 0.35 dB peak variation over 11 s. This was noise-like, with no
recognizable AIS bursts. Check the actual isolated coax connection, correct
B210 channel-0 TX/RX and RX2 connectors, and UHD output diagnostics first.

The independent test in `scripts/ais_b210_diagnostics.py --tone-test` produces
a short *non-AIS* pilot 40 kHz above a 915 MHz laboratory center, through the
same B210 helper. See README for the exact commands. This test now has no
software attenuation confirmation; do not run it without a verified, protected
conducted RF path.

