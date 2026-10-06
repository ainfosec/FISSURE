# APRS — RTL-SDR monitor for FISSURE

Receive-only 144.390 MHz (North America) APRS. This plugin follows the FISSURE
`Plugins/<name>/` layout: thin `actions.py`, a framework-managed Operation, and
plugin-owned parser. It uses FISSURE's existing detections, Target callbacks,
status messages, and optional Artifact framework; no FISSURE core changes.

## Install

Place the supplied `APRS/` directory at `FISSURE/Plugins/APRS/` on the FISSURE
hub/local Sensor Node, or deploy it using the normal FISSURE plugin deployment
workflow for remote nodes. Enable the APRS plugin for your chosen node. For
live reception, configure the node with hardware type **RTL2832U** (exact FISSURE
type), then choose **APRS → aprs_monitor**. The Action's options travel through
the normal `run_plugin_operation` execution path; a remote node reads its *own*
RTL-SDR rather than hardware attached to the Dashboard computer.

Live reception requires host executables: `rtl_fm` (rtl-sdr tools) and
`multimon-ng` (AFSK1200 decoder). Use your distribution packages; e.g. on
Debian/Ubuntu: `sudo apt install rtl-sdr multimon-ng`. `setup.py` intentionally
makes no changes on check/install/cleanup; it never installs packages or changes
device rules.

An RTL2832U receiver and VHF antenna are required for live use; other programs
must release the dongle first. Unprivileged USB access depends on your host's
udev configuration. The frequency is fixed at **144390000 Hz** and reception is
FM → mono 22,050 Hz signed PCM → AFSK1200 → decoded AX.25 APRS. There is **no
transmitter**, APRS-IS forwarding, or internet uplink.

## Action and inputs

- **aprs_monitor** (RTL2832U only): `rtl_device` (device index or serial,
  default `0`) and `rtl_gain_db` (blank means automatic gain). Starts
  immediately and listens until Stop.
- `emit_targets` (default true) controls whether decoded APRS identities create
  and update FISSURE Targets.
- `log_artifact` (default false) controls whether decoded packets are retained
  in the APRS JSONL Artifact.

RTL-SDR PPM correction remains supported internally by the Operation with a
default of zero, but it is intentionally not exposed as a normal Tactical
Action parameter. Target refresh and Artifact refresh cadence also remain
internal Operation defaults. FISSURE's Stop button sets the Operation's stop
flag, terminating and reaping both child programs; other node Operations are
unaffected.

### Generated outputs

- **Detection per decoded packet:** source callsign, AX.25 destination and
  digipeater path, complete TNC2 packet/information field, packet type,
  frequency, reception time, station-first-seen flag, and decoded coordinates
  when supported. Each detection uses the existing `detection_callback` path.
- **Target discovery and position:** deterministic Target ID per APRS identity,
  independent of which Sensor Node receives it; the observing node remains in
  the Target patch/history. New stations are discoverable even without
  coordinates. Self-reported station positions update Targets when they
  change or after the refresh period. APRS `;objects`/`)items` with positions
  are mapped as **separate objects** (not as the transmitting station's
  location). Third-party packets are reported but not incorrectly mapped to
  a gateway.
- **Optional Artifact:** one `protocol_packets` logical Artifact containing
  newline-delimited JSON `aprs_packets.jsonl`. It is created after the first
  valid packet and refreshed every N packets and on normal Stop/completion.
  FISSURE's Artifact manager handles the manifest and remote transfer.
  Empty sessions produce no Artifact.

**Position disclaimer:** APRS coordinates are supplied by transmitters, not
validated RF geolocation. The plugin deliberately does **not** substitute the
sensor's GPS coordinates or invent an accuracy/uncertainty value. APRS
timestamps in payloads are preserved in raw packet text; observation timestamps
use the local node's UTC receive time. No position is fabricated for
unsupported/malformed packets.

## Development validation

The public plugin exposes only the live Tactical monitor. Replay support remains
inside the Operation and test harness so parser, decoder, callback, Target,
Artifact, Stop, and error behavior can be exercised without adding a separate
Tactical Action.

From the repository root, after copying `Plugins/APRS/`:

```bash
python3 -m unittest discover -s Plugins/APRS/tests -v
```

The included synthetic TNC2 fixture contains five packets, two station callsigns
(N0CALL-9, K1ABC), three position packets, one status, and one APRS message. The
14-test suite checks the public Action schema/routing plus Operation-level TNC2
replay, fake WAV decoding, Sensor Node-independent Target identity, error
terminal status, SDR claims, and a fake `rtl_fm`/`multimon-ng` pipeline that
requires the decoder's `-A` argument. These synthetic subprocess tests do **not**
establish actual decoder or hardware RF performance.

For development troubleshooting, `scripts/check_replay.py` can inspect a decoded
TNC2 fixture without FISSURE:

```bash
python3 Plugins/APRS/scripts/check_replay.py /absolute/path/to/testfile
```

Audio replay remains an internal Operation/test capability for validating the
real `multimon-ng` decoder path with APRS AFSK1200 audio. It is not exposed as a
Tactical Action. Real reception still requires a compatible RTL2832U, antenna,
and working `rtl_fm`/`multimon-ng` installation.

## Known limitations

Position decoding covers standard uncompressed, timestamped, compressed,
object, and item position formats. Encapsulated third-party positions, position
ambiguity, Mic-E destinations, weather-only data, malformed reports, and
non-position packets remain raw packet detections without invented locations.
This implementation is a passive APRS station monitor, not a full APRS-IS
client or universal APRS application. Duplicate frames remain separate
observations, intentionally, but Target updates are throttled.

## Development notes

Aligned with upstream `AGENTS.md` and `docs/ai/plugins.md` on FISSURE's
`Python3` branch. No core, UI, or installer modifications. Operation callbacks,
Artifact creation/refresh and runtime SDR resource claim follow current
`fissure/utils/plugins/operations.py` interfaces. Test harness exercises the
same Operation with callback doubles when a full FISSURE installation is absent.
