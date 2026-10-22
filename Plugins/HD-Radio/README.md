# HD Radio — FISSURE Python3 plugin (v1.0.0)

A **FISSURE plugin** for RTL2832U/RTL-SDR scanning of US FM (88.1–107.9 MHz).
Two user-facing Actions share the same receiver, decoder, status, and Artifact
implementation. No changes to FISSURE core, no server, and no new Python package
are required. External CLI dependencies run **on the selected Sensor Node**.

## Actions

| FISSURE Action name | Operator-facing description | RF strategy | Defaults |
| --- | --- | --- | --- |
| `scan_hd_radio` | **HD Radio Full Scan** (the original Action name, kept for saved playlists) | Every FM channel, in ascending order, acquired with `nrsc5`. **No channels skipped for weak RF energy.** | 15 s per channel, 100 channels |
| `hd_radio_quick_scan` | **HD Radio Quick Scan** | One `rtl_power` wideband FFT sweep; rank occupied FM channel centers; use `nrsc5` only on top candidates and extend sync-only acquisition in the same receiver session | 6 s spectrum survey; at least 12 strongest channels; max 40; threshold 6 dB above survey reference; 7 s initial NRSC-5 dwell; 12 s retry on sync-only |

The FFT sweep measures spectral *energy*, **not HD digital carriers**: it can
include analog-only stations and exclude weak HD Radio stations. It cannot
confirm HD Radio. Both Actions confirm with actual NRSC-5 synchronization **and**
station/service metadata in an intact acquisition. Sync without SIS/SIG metadata
is reported as **unconfirmed**. FM/RDS/energy alone never count as confirmed.

Quick scanning is faster when enough channels can be excluded and/or shortened.
In dense or noisy RF environments, many candidates may be selected. FFT
preselection can miss quiet HD stations, so **Full Scan remains the reference**.
The Quick report lists all frequencies excluded by the selection stage rather
than treating them as negative measurements. Set **Max Frequencies to Check** to 0 to remove the cap. The internal
energy threshold and fallback count may be adjusted by advanced developers.
Quick dwell can be increased for slow-to-decode stations.

## Installation

1. Use the [FISSURE `Python3` branch](https://github.com/ainfosec/FISSURE).
   Configure an RTL2832U on the Sensor Node where the Action will run. The node
   user must have access to the RTL-SDR (udev/group setup as appropriate), and
   no other program may hold that dongle.
2. Install third-party [`nrsc5`](https://github.com/theori-io/nrsc5) and
   [`rtl_power`](https://github.com/osmocom/rtl-sdr) (part of `rtl-sdr`, often
   available via `sudo apt install rtl-sdr`). Both must be on the **Sensor
   Node** `PATH`. Full Scan only requires `nrsc5`. Verify:
   ```bash
   command -v nrsc5
   command -v rtl_power
   rtl_power -h    # Some releases exit nonzero after printing usage
   ```
   The plugin does not install drivers or overwrite host dependencies. It also
   does **not** pass the unsupported `-t` option to the older `nrsc5` CLI.
3. Stop any running scan and deploy `HD-Radio/` under `<FISSURE>/Plugins/`
   using the normal plugin mechanism. If `HD-Radio-Station-Scanner/` is already
   deployed, remove that old plugin on the Hub and Sensor Nodes before using
   the new name. Saved playlists referring to the old **plugin name** require
   updating; the Action identifiers themselves are unchanged. Deploy to the
   Sensor Node too, not only the Dashboard or Hub.
4. Reload/activate the plugin using the normal FISSURE Plugins UI. The existing
   Action name `scan_hd_radio` (Full) remains valid; new Action is
   `hd_radio_quick_scan`. They are restricted to configured hardware `RTL2832U`.
   Remote and local nodes use the same Action/Operation mechanism.

### Operator-facing parameters

Both Actions expose five operator controls: **Start FM Frequency (MHz)**,
**Stop FM Frequency (MHz)**, **RTL-SDR Device (index)** (default 0),
**RTL-SDR Gain (dB; -1 = Auto)**, and **Time per Channel (s)**.
Full Scan defaults to 15 s per channel; Quick Scan defaults to 7 s. Frequencies
must be odd-tenth US FM channels (200-kHz spacing).

Quick Scan additionally exposes **Max Frequencies to Check (0 = all)**,
default 40. It can be raised when necessary to favor detection coverage.

Implementation settings use Operation defaults rather than operator controls:
`ppm_correction=0`, `survey_seconds=6`, `threshold_db=6`,
`min_candidates=12`, and `retry_sync_seconds=12`. These remain accepted by the
Operation constructor for specialized use, but are intentionally not in the
standard Action schemas. After the initial Quick Scan dwell, a synchronized
receiver without sufficient metadata can continue decoding for 12 additional
seconds **without restarting `nrsc5`**. A decoder/survey failure produces a failed Artifact and raises an error for
FISSURE's Operation wrapper to log. The current base wrapper catches and logs
these exceptions, so the Sensor Node can still return to Idle after teardown.
A failed Artifact is the authoritative per-scan failure record. Artifact
registration failures likewise produce an explicit error status and log.

**Implementation detail:** The survey calls `rtl_power -f <low>:<high>:100000
-i <seconds>s -1 -d <index> -p <ppm> [ -g <gain> ] -` and parses its documented
CSV format. It uses mean spectral power at each requested channel center,
compares to a broad-band low-percentile reference, and prioritizes channels
above the threshold with a minimum number of high-power fallbacks. Selected
channels are ordered by survey score (not ascending frequency) to surface
strong stations sooner. At most one program holds the SDR at a time.
`nrsc5` always receives `-o /dev/null` to avoid an audio playback device.

## FISSURE Artifacts and progress

Each Operation registers **one analysis Artifact** containing three files
in its managed Operation storage:

- **`hd_radio_stations.txt`** — primary readable report: confirmed list,
  frequencies, station names, country/FCC facility IDs where decoded, slogans,
  HD1/HD2/... service names/types, data services, sync-only list, stats,
  elapsed time, exclusions and errors.
- **`hd_radio_stations.csv`** — compact stations-and-sync-only table for easy
  spreadsheet inspection and Full-vs-Quick comparisons.
- **`hd_radio_scan.json`** — detailed v2 schema with all NRSC-5 acquisitions,
  exact parameter values, station classifications, timing, errors, and Quick
  spectrum-survey power ranking and untested channels.

`status_callback` sends one-string FISSURE status/progress messages with survey
stage, acquisition progress, confirmed station notices and summary statistics.
It does **not** publish a global `Idle` state: FISSURE's Sensor Node runner
manages operation teardown, artifact notification, and transition to idle.
Both Operations stop automatically at the end of their finite work. Stop while
surveying or decoding ends the child subprocess and saves an interrupted partial
Artifact; the runner releases the operation's claimed SDR resource. Decoder
failures and missing CLI tools report a failed Artifact rather than continuing
through doomed acquisitions.

## Hardware comparison procedure

Use the same RTL-SDR, antenna placement, `gain_db`, `ppm_correction`, and
frequency range for both Actions. Suggested sequence:

1. Scan a **small known-good range** (e.g. 2–5 channels) with Full for 15–25 s,
   validate at least one confirmed name/program in the readable Artifact.
2. Run Quick on exactly the same range; set `min_candidates` / `max_candidates`
   appropriately for a small range and compare to the Full confirmed list.
3. Run Full on 88.1–107.9 MHz (default 15 s dwell), then Quick on the same
   range. Compare `duration_seconds`, `confirmed_stations`, `synchronization_candidates`,
   and `channels_not_checked` in the JSON Artifacts. For a controlled comparison
   of candidate filtering alone, set **the same** `acquisition_time_s` in both.
4. Repeat Quick with a higher Max Frequencies to Check (e.g. 60),
   or longer Time per Channel if it misses stations Full confirmed. Re-run under
   similar reception conditions; broadcast conditions and metadata timing vary.
5. Test Stop during Full and Quick, and confirm no `nrsc5` / `rtl_power` is left
   running or holding the dongle. Test unplugged/missing RTL-SDR to confirm a
   failure Artifact. These are **manual tests requiring actual hardware**.

## Tests without a radio

```bash
cd <FISSURE>/Plugins/HD-Radio
python3 -m unittest discover -s tests -v
python3 -m compileall -q actions.py operations scripts tests
python3 setup.py check
```

The unit tests substitute a small fake FISSURE base Operation/ArtifactManager
and fake `nrsc5` / `rtl_power` subprocesses. Passing them does **not** prove
receiver RF performance, local/remote deployment, actual device cleanup, or a
specific reduction in full-band elapsed time.

## Sources and conventions

FISSURE `README.md` → `AGENTS.md` → `docs/ai/plugins.md`, `docs/ai/architecture.md`,
`docs/plans/execution_context_provenance.md` → `fissure/utils/plugins/operations.py`,
`fissure/utils/plugin.py`, `fissure/Sensor_Node/SensorNode.py`. The actual FISSURE
Operation, resource locking, `status_callback(status: str)`, and Artifact APIs
were checked. `rtl_power` FFT CSV/`-1` and `-i` flags are documented by the
[rtl-sdr source](https://github.com/osmocom/rtl-sdr/blob/master/src/rtl_power.c).
All scan/selection/report logic remains plugin-owned.

## Version

- v1.0.0 — initial pre-release version: Full Scan and Quick Scan, shared receiver,
  readable TXT/CSV plus diagnostic JSON Artifact, and hardware-free tests.
  Version intentionally remains 1.0.0 until the plugin is published.
