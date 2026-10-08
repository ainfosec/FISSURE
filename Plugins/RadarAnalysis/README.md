# RadarAnalysis

RadarAnalysis provides offline radar pulse analysis through the FISSURE Inspection workflow.

## Action

`radar_analysis`

Supported input representations:

- PDW CSV with required `toa_s` and optional `pulse_width_s`, `amplitude`, and `carrier_offset_hz` columns
- real `float32` log-video / detected-envelope samples
- complex `float32` IQ samples

The Action uses the file already loaded in Inspection. For raw sample files, a positive sample rate must come from Inspection metadata or the Action parameter. Center frequency is optional and is used only to convert baseband offsets into RF-frequency estimates.

The analysis reports pulse count, PRI/PRF statistics and behavior, pulse width, amplitude behavior, frequency offset when observable, scan-like amplitude periodicity, LFM/chirp evidence for IQ, and simple multi-emitter indications. Detailed results and plots are written to a managed FISSURE Artifact.

Properties that cannot be supported by an input representation are reported as unsupported rather than false.
