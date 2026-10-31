# FISSURE Audio Transcription plugin

**Branch target:** `ainfosec/FISSURE`, `Python3` branch. The Audio Transcription cleanup changes only the Operation, documentation, and isolated tests. No FISSURE core, Dashboard, plugin query framework, or setup hooks are changed.

## Action

- **Action:** `Transcribe Audio File` (Python identifier: `transcribe_audio_file`).
- **Parameter:** `Local Audio File Path` / `audio_file_path`: an existing local file on the **executing Sensor Node**, not necessarily the Dashboard machine.
- **Input:** WAV (mono/stereo, arbitrary supported sample rate), and other formats FFmpeg can decode.
- **Output:** one readable `audio_transcript.txt` inside the current FISSURE Operation's managed Artifact storage, registered through `Operation.create_artifact`. It contains a metadata header, a continuous transcript for easy reading/copying, and timestamped segments for analysis.
- **Artifact metadata:** a short `transcript_preview` (up to 240 characters), duration, language, segment count, and an audio-check note when applicable. These are available to FISSURE's existing Artifact details view; Last Result is not overwritten.
- **CPU:** `whisper-cli -ng`; multilingual model; language detection with `-l auto`.
- **No external calls:** runtime performs only local FFmpeg and whisper-cli executions.

## Prerequisites for running the Operation

This cleanup deliberately does **not** change `setup.py` or any plugin-installation behavior. Runtime still uses local FFmpeg and whisper.cpp, regardless of how the machine was provisioned.

On Ubuntu 20.04 or 24.04, use your existing manually installed whisper.cpp and FFmpeg. Expected default layout:

```
~/Installed_by_FISSURE/whisper.cpp/build/bin/whisper-cli
~/Installed_by_FISSURE/whisper.cpp/models/ggml-small.bin
```

The initial experiment used a compatible whisper.cpp build and a multilingual `small` model. For custom locations, set `FISSURE_WHISPER_CPP_DIR` in the **Sensor Node process environment**, pointing to the whisper.cpp root directory. A remote Sensor Node must have its own local model/binaries and access to the specified audio file. No GPU required. The Operation itself never installs packages or downloads models.

## Plugin files and usage

1. Keep the existing plugin installation and setup configuration unchanged.
2. Select `Audio Transcription` → `Transcribe Audio File` in FISSURE's existing Actions interface.
3. Provide an absolute local audio file path on the Sensor Node that will execute it.
4. Inspect or download the registered Artifact through FISSURE's existing Artifact UI/transfer functionality. The TXT is stored in the Sensor Node's managed `artifacts_node/<operation_id>/files/` location.

## Result/status limitations

The Python3 Sensor Node runner (`run_plugin_operation`) starts the Operation and manages its lifetime. An Operation's returned Python value is **not** delivered as a Dashboard Action result. This plugin therefore provides a concise `completed`, `no_speech`, `failed`, or `stopped` summary via the existing status callback and Sensor Node logs, and persists the complete outcome in Artifact metadata and the TXT. It does **not** modify the Dashboard, create a new result transport, or attempt to overwrite the `Last Result` widget. The normal Sensor Node runner may subsequently reset its status to Idle.

## Error handling

A nonexistent/unreadable file, missing model or whisper-cli, missing FFmpeg, failed conversion, malformed Whisper JSON, and Artifact-registration failure all produce an actionable failure status and log message. Digital silence produces a `no_speech` TXT Artifact. A second, conservative check recognizes some **low-level broadband-like noise** by combining low amplitude and high zero-crossing rate before Whisper runs, reducing hallucinations on the original noise-only test. Both checks run on normalized 16 kHz mono WAV audio.

**Limitations:** These checks are not general voice activity detection. Very quiet, noisy speech could be rejected, and louder noise can still produce hallucinations. Do not treat `no_speech` as proof that nobody spoke. Verify important material against the recording. This change intentionally does not add an external VAD dependency or alter Whisper model selection.

Stop requests terminate active subprocesses without stopping other FISSURE Operations. Intermediate converted audio and JSON are removed after use; the original input is never altered.

## Repository contracts

Aligned with `AGENTS.md`, `docs/ai/plugins.md`, `fissure/utils/plugins/operations.py`, `fissure/utils/artifacts.py`, and `fissure/Sensor_Node/SensorNode.py` from FISSURE's Python3 branch. No core edits.
