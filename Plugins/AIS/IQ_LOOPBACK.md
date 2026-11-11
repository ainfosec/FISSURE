# AIS Offline IQ Loopback — GNU Radio 3.8 / 3.10 candidate

**No RF is transmitted.** This FISSURE Action generates finite AIS GMSK
bursts into a raw complex64 file, reads them with the installed `gr-ais`
receiver, correlates vessel identities, and creates managed FISSURE Artifacts.
It uses FISSURE's existing Sensor Node Operation, Target, Detection, and
Artifact callbacks; no new core service or SDR output is introduced.

## Verified baseline (v0.4.4, 2026-11-06)

On Ubuntu 20.04 with GNU Radio 3.8.5.0, the original Type 1 position-only
loopback recovered all nine transmitted NMEA messages exactly, covering three
synthetic MMSIs. The file-based modulator uses Python finite-frame
CRC-16/X.25, HDLC bit stuffing and NRZI, then GNU Radio GMSK (BT=0.4).
The gr-aistx legacy `Build_Frame` block previously stalled when used as a finite
stream source; it is **not** used by the offline generator. The installed gr-aistx
module and FISSURE's original flow graphs are otherwise unchanged.

## New in v0.5.0

With **Include Type 24 Vessel Names / Call Signs = true** (the default),
`ais_iq_loopback` generates a coherent synthetic **Class B** message set:

| Message | Quantity at default settings | Purpose |
|---|---:|---|
| 24 Part A | 3 | Synthetic vessel names |
| 24 Part B | 3 | Synthetic call signs and static particulars |
| 18 | 9 | Moving position reports (3 per vessel) |
| **Total** | **15** | **3 distinct MMSIs** |

Type 24A and 24B are **two separate single-slot AIS transmissions**, not one
multipart over-the-air message. The generator supports 160- and 168-bit
single-slot reports and validates each NMEA sentence and its declared type.
Type 5 multi-slot over-the-air generation is deliberately excluded.

The software receiver must reproduce **all 15 original NMEA sentences exactly**
(including repeated messages), successfully decode the three identities,
and update the same persistent MMSI-correlated Targets. A failure of any of
these checks fails the Action, while preserving the recorded IQ and diagnostics.
The new mode is **not yet verified using real GNU Radio 3.8**; it needs this
Ubuntu 20.04 host test.

Set **Include Type 24 Vessel Names / Call Signs = false** to repeat the already
verified Type 1-only nine-message test from v0.4.4.

## Artifact provenance

The plugin registers **AIS Offline GMSK IQ Stimulus** before decoding, so the
**AIS NMEA Reception (iq_file)** Artifact references the source by real
`stimulus_artifact_id` plus `decoded_from` relation. Once the decoder finishes,
both Artifacts gain a `roundtrip_validation` metadata value and reciprocal
Artifact relations; SHA-256 hashes connect the NMEA source, IQ file, and
stimulus manifest. All files live in the same managed Operation directory.

## Test on Ubuntu 20.04

Extract the entire `Plugins/AIS` folder from this release into the FISSURE
root, overwriting the earlier version, then refresh the plugin. Run:

```bash
python3 Plugins/AIS/scripts/ais_iq_generator.py --probe
python3 Plugins/AIS/scripts/ais_iq_decoder.py --probe
python3 Plugins/AIS/setup.py check
```

In FISSURE, select **AIS → `ais_iq_loopback`** and keep the defaults:

- 3 vessels and 3 position updates each
- Include Type 24 Vessel Names / Call Signs: `true`
- Starting latitude `40.722`, longitude `-74.020` (Hudson River, NYC map pack)
- Sample rate `240000` Hz, between-burst gap `350` ms
- Publish SIMULATED Targets: `true`

Expected outcome: **15/15 AIS messages**, three named Targets in the Tactical
Targets tab, and two linked managed Artifacts. In the reception Artifact,
`roundtrip_validation` should be `passed`, `nmea_messages` should be 15, and
`unique_mmsi` should be 3. Verify actual map display separately: FISSURE
Targets and map rendering are independent of the AIS decoder.

If the run fails, download both Artifacts and send their files or log output.
The failure will identify NMEA mismatches, missing MMSIs, or incomplete static
identity; the generator never claims RF transmission. The next step after a
passing test is real SDR receive using both AIS channels, then GNU Radio 3.10
portability.
