# RTL433 Device Monitor

One RTL-SDR Tactical Action that runs `rtl_433` on the selected Sensor Node.
It receives 433 MHz IoT device messages, reports native FISSURE Detections, and optionally saves an Artifact when stopped.

## Requirements and operation

- Install `rtl_433` on the executing Sensor Node and configure an RTL2832U in FISSURE.
- Select **RTL433** and **device_monitor_433mhz** in Tactical, adjust frequency,
  device index, gain or PPM if necessary, and execute. Stop when finished.
- **Save Artifact** defaults to **false** in a dropdown. Enable it to save every decoded observation,
  a per-device summary, and the session metadata when the Action stops.
- `setup.py` is deliberately inert; dependency installation is operator-managed.
- Uses FISSURE Operation resource locking, status, native Detection callbacks and Artifacts.
  Works on local or remote Sensor Nodes that have an RTL-SDR and `rtl_433` installed.

## Results

With **Save Artifact** enabled, every decoded JSON message is saved to
`observations.jsonl`, even if repeated Detection callbacks are rate-limited.
`devices.json` summarizes device groups and latest measurements; `session.json`
records configuration, message counts, and the completion reason. The Artifact is
preserved on normal stop or decoder failure when collection has started. With
**Save Artifact** disabled, the Operation does not create log files or an Artifact;
Detection reporting and live status continue normally.

Detector output is not calibrated transmitter power. RSSI, SNR and any other
`rtl_433` fields are preserved verbatim; they are not relabeled as dBm.
Device group IDs use protocol/model, transmitted ID and channel when available.
Groups without a transmitted ID can represent more than one physical device.

Native FISSURE Detections are sent for live observations using a stable
per-node/per-device event UID, with a configurable minimum update interval per
device. Each new observation updates the same Tactical row; all observations
are written to the Artifact only when **Save Artifact** is enabled. Groups without a transmitted ID may combine
multiple devices of the same model and channel.

FISSURE's existing Sensor Node/HIPRFISR position fallback uses the receiving
node's saved or GPS position as the Detection's observation location. A valid
configured node position is therefore required for the existing CoT-based
Tactical table and map to display these Detections. It is an approximate
observation area, **not** the decoded device's measured position. The plugin
does not create Targets; operators can promote interesting Detections manually.
Repeated readings retain the same per-node/per-device CoT event UID so they
update an existing table row rather than adding a new row for each message.
The existing Tactical table may show generic frequency/power/time columns;
detailed device fields are preserved in each native Detection and Artifact.

IQ-file decoding is intentionally outside this hardware Action. A future separate
file-analysis Action could use `rtl_433 -r /path/on/sensor-node`, with independent
hardware availability and replay isolation rules.
