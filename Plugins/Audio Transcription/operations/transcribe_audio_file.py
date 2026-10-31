#!/usr/bin/env python3
"""Offline audio transcription with a readable managed TXT Artifact.

No model downloads, package installation, APIs, or extra background services.
"""

import asyncio
import array
import json
import logging
import math
import os
import sys
import tempfile
import wave
from pathlib import Path
from typing import Callable, Union

from fissure.utils.plugins.operations import Operation


# Node-side binaries/models are installed *manually*, outside the plugin.
# An operator can point to a different whisper.cpp root without changing FISSURE.
WHISPER_ROOT_ENV = "FISSURE_WHISPER_CPP_DIR"


class TranscriptionError(Exception):
    """A recoverable input, dependency, or transcription problem."""


class OperationStopped(Exception):
    """The operator stopped this specific Operation."""


class OperationMain(Operation):
    """Transcribe one recorded audio file and register a readable TXT Artifact."""

    def __init__(
        self,
        audio_file_path: str = "",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        status_callback: Union[Callable, None] = None,
        artifact_manager=None,
    ) -> None:
        """Initialize this Operation.

        Parameters
        ----------
        audio_file_path : str, optional
            Path to a recorded audio file on the executing Sensor Node.
        node_uid : str, optional
            FISSURE Sensor Node UID.
        logger : logging.Logger, optional
            FISSURE logger.
        status_callback : Callable, optional
            Existing FISSURE status publisher.
        artifact_manager : ArtifactManager, optional
            Existing FISSURE Artifact manager.
        """
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            status_callback=status_callback,
            artifact_manager=artifact_manager,
        )
        self.audio_file_path = str(audio_file_path or "").strip()
        self._process = None
        self.result = None  # Local diagnostic/test state; FISSURE does not transport return values.

    async def _publish(self, text: str) -> None:
        self.logger.info("Audio Transcription: %s", text)
        if self.status_callback:
            try:
                await self.status_callback(text)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.warning("Could not publish transcription status", exc_info=True)

    @staticmethod
    def _tools():
        root = Path(
            os.environ.get(WHISPER_ROOT_ENV)
            or str(Path.home() / "Installed_by_FISSURE" / "whisper.cpp")
        ).expanduser()
        cli = root / "build" / "bin" / "whisper-cli"
        model = root / "models" / "ggml-small.bin"
        return cli, model

    @staticmethod
    def _validate_input(raw_path: str) -> Path:
        if not raw_path:
            raise TranscriptionError("Local Audio File Path is required")
        source = Path(raw_path).expanduser()
        if not source.is_file():
            raise TranscriptionError("File does not exist or is not a regular file: {}".format(source))
        if source.stat().st_size == 0:
            raise TranscriptionError("Input file is empty: {}".format(source))
        if not os.access(str(source), os.R_OK):
            raise TranscriptionError("Input file is not readable: {}".format(source))
        return source.resolve()

    @staticmethod
    def _validate_tools(cli: Path, model: Path) -> None:
        if not cli.is_file() or not os.access(str(cli), os.X_OK):
            raise TranscriptionError(
                "whisper-cli missing or not executable: {} (install whisper.cpp manually)".format(cli)
            )
        if not model.is_file() or model.stat().st_size == 0:
            raise TranscriptionError(
                "Multilingual ggml-small.bin model missing: {} (download manually)".format(model)
            )
        # ffmpeg is checked by subprocess execution, so a missing executable gets
        # an actionable error without importing another dependency.

    async def _run_command(self, argv, label: str) -> None:
        """Run one command asynchronously and cooperatively honor Stop."""
        if self._stop:
            raise OperationStopped()
        try:
            self._process = await asyncio.create_subprocess_exec(
                *[str(part) for part in argv],
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            raise TranscriptionError("{} executable not found: {}".format(label, argv[0]))
        except OSError as exc:
            raise TranscriptionError("Cannot start {}: {}".format(label, exc))

        process = self._process
        communicate = asyncio.create_task(process.communicate())
        try:
            while not communicate.done():
                if self._stop:
                    raise OperationStopped()
                await asyncio.wait({communicate}, timeout=0.2)
            _, stderr = await communicate
            if self._stop:
                raise OperationStopped()
            if process.returncode != 0:
                error_text = stderr.decode("utf-8", errors="replace").strip()
                # Keep operator-facing errors short; preserve full tool diagnostics in logs.
                self.logger.error("%s failed (%s): %s", label, process.returncode, error_text)
                detail = error_text.splitlines()[-1] if error_text else "no error detail"
                raise TranscriptionError("{} failed (exit {}): {}".format(
                    label, process.returncode, detail[:220]
                ))
        finally:
            if process.returncode is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(process.wait(), timeout=3.0)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
            if not communicate.done():
                await communicate
            self._process = None

    @staticmethod
    def _is_silent(wav_path: Path) -> bool:
        """Check the normalized 16kHz mono S16 PCM WAV using bounded reads.

        RMS <= 8/32768 is essentially digital silence. This is intentionally a
        conservative check, not a speech-vs-noise classifier.
        """
        try:
            with wave.open(str(wav_path), "rb") as wav:
                if wav.getnchannels() != 1 or wav.getsampwidth() != 2:
                    raise TranscriptionError("Normalized audio is not mono 16-bit PCM WAV")
                sample_count = 0
                total_square = 0
                while True:
                    frame_data = wav.readframes(32000)
                    if not frame_data:
                        break
                    samples = array.array("h")
                    samples.frombytes(frame_data)
                    if sys.byteorder != "little":
                        samples.byteswap()
                    sample_count += len(samples)
                    total_square += sum(value * value for value in samples)
                if sample_count == 0:
                    return True
                return math.sqrt(total_square / sample_count) <= 8.0
        except (wave.Error, EOFError, OSError) as exc:
            raise TranscriptionError("Cannot read normalized WAV: {}".format(exc))

    @staticmethod
    def _is_low_level_noise(wav_path: Path) -> bool:
        """Conservatively reject very quiet, broadband-like background noise.

        This is *not* voice activity detection. Requiring both low amplitudes
        and a high zero-crossing rate prevents an ordinary low-volume voiced
        signal from being rejected solely because it is quiet. It cannot
        distinguish all speech from noise, and users should inspect the audio
        whenever a no_speech result is surprising.
        """
        try:
            with wave.open(str(wav_path), "rb") as wav:
                if (wav.getnchannels(), wav.getsampwidth(), wav.getframerate()) != (1, 2, 16000):
                    raise TranscriptionError("Normalized audio must be 16 kHz mono S16 WAV")
                active_windows = 0
                crossings_sum = 0.0
                max_window_rms = 0.0
                max_peak = 0
                while True:
                    raw = wav.readframes(3200)  # 200 ms, bounded RAM usage.
                    if not raw:
                        break
                    samples = array.array("h")
                    samples.frombytes(raw)
                    if sys.byteorder != "little":
                        samples.byteswap()
                    if len(samples) < 2:
                        continue
                    rms = math.sqrt(sum(v * v for v in samples) / len(samples))
                    if rms <= 48.0:  # Ignore effectively silent windows.
                        continue
                    active_windows += 1
                    max_window_rms = max(max_window_rms, rms)
                    max_peak = max(max_peak, max(abs(v) for v in samples))
                    crossings = sum(
                        (a >= 0) != (b >= 0)
                        for a, b in zip(samples, samples[1:])
                    )
                    crossings_sum += crossings / (len(samples) - 1)
                return (
                    active_windows >= 3
                    and max_window_rms < 550.0
                    and max_peak < 2500
                    and crossings_sum / active_windows > 0.38
                )
        except (wave.Error, EOFError, OSError) as exc:
            raise TranscriptionError("Cannot analyze normalized WAV: {}".format(exc))

    @staticmethod
    def _duration_seconds(wav_path: Path) -> float:
        try:
            with wave.open(str(wav_path), "rb") as wav:
                return wav.getnframes() / wav.getframerate()
        except (wave.Error, EOFError, OSError, ZeroDivisionError) as exc:
            raise TranscriptionError("Cannot measure audio duration: {}".format(exc))

    @staticmethod
    def _time_string(seconds: float) -> str:
        milliseconds = max(0, int(round(seconds * 1000)))
        total, fraction = divmod(milliseconds, 1000)
        return "{:02d}:{:02d}:{:02d}.{:03d}".format(
            total // 3600, (total // 60) % 60, total % 60, fraction
        )

    @staticmethod
    def _parse_json(json_path: Path):
        try:
            with json_path.open("r", encoding="utf-8") as stream:
                payload = json.load(stream)
        except (ValueError, OSError) as exc:
            raise TranscriptionError("whisper.cpp produced no valid JSON transcript: {}".format(exc))
        if not isinstance(payload, dict) or not isinstance(payload.get("transcription"), list):
            raise TranscriptionError("Unexpected whisper.cpp JSON transcript structure")
        result = payload.get("result")
        language = str(result.get("language") or "und") if isinstance(result, dict) else "und"
        segments = []
        for segment in payload["transcription"]:
            if not isinstance(segment, dict):
                continue
            text = str(segment.get("text") or "").strip()
            if not text:
                continue
            timestamps = segment.get("timestamps")
            timestamps = timestamps if isinstance(timestamps, dict) else {}
            start = str(timestamps.get("from") or "").strip()
            end = str(timestamps.get("to") or "").strip()
            segments.append((start, end, text))
        return language, segments

    def _write_artifact(
        self, source: Path, language: str, segments, status: str,
        duration_seconds: float, activity_note: str = "",
    ) -> str:
        """Store one readable TXT, with searchable excerpt in Artifact metadata."""
        if not self.artifact_manager:
            raise TranscriptionError("FISSURE ArtifactManager is unavailable")
        _, files_dir = self.artifact_manager.create_operation_dir(self.opid)
        transcript_path = Path(files_dir) / "audio_transcript.txt"
        full_text = " ".join(" ".join(text.split()) for _, _, text in segments).strip()
        preview = full_text[:240] + ("…" if len(full_text) > 240 else "")
        with transcript_path.open("w", encoding="utf-8") as handle:
            handle.write("AUDIO TRANSCRIPTION\n")
            handle.write("=" * 60 + "\n")
            handle.write("Source: {}\n".format(source.name))
            handle.write("Source path: {}\n".format(source))
            handle.write("Duration: {} ({:.2f} seconds)\n".format(
                self._time_string(duration_seconds), duration_seconds
            ))
            handle.write("Language: {}\n".format(language))
            handle.write("Status: {}\n".format(status))
            handle.write("Segments: {}\n".format(len(segments)))
            handle.write("Engine: whisper.cpp / ggml-small multilingual\n")
            handle.write("Operation ID: {}\n".format(self.opid))
            if activity_note:
                handle.write("Audio check: {}\n".format(activity_note))
            handle.write("\nTRANSCRIPT\n")
            handle.write("-" * 60 + "\n")
            handle.write((full_text or "[No speech detected / no transcription segments]") + "\n")
            if segments:
                handle.write("\nTIMESTAMPED SEGMENTS\n")
                handle.write("-" * 60 + "\n")
                for start, end, text in segments:
                    if start and end:
                        handle.write("[{} --> {}] {}\n".format(start, end, text))
                    else:
                        handle.write("{}\n".format(text))
            handle.write("\nNote: Automated speech recognition can mishear or invent words, ")
            handle.write("especially in noise. Verify important content against the recording.\n")

        metadata = {
            "role": "audio_transcription",
            "source_file": str(source),
            "detected_language": language,
            "transcription_status": status,
            "duration_seconds": round(duration_seconds, 2),
            "engine": "whisper.cpp",
            "model": "ggml-small (multilingual)",
            "segment_count": len(segments),
        }
        if preview:
            metadata["transcript_preview"] = preview
        if activity_note:
            metadata["audio_check"] = activity_note
        artifact_id = self.create_artifact(
            files=[str(transcript_path)],
            name="Audio transcript: {}".format(source.name),
            artifact_type="transcript",
            metadata=metadata,
            file_metadata={str(transcript_path): {
                "role": "transcript",
                "content_type": "text/plain",
            }},
        )
        if not artifact_id:
            raise TranscriptionError("TXT created but FISSURE Artifact registration failed")
        return artifact_id

    async def run(self) -> None:
        """Convert input with FFmpeg; transcribe with whisper-cli; register TXT."""
        source = None
        try:
            source = self._validate_input(self.audio_file_path)
            cli, model = self._tools()
            self._validate_tools(cli, model)
            await self._publish("Transcribing: {}".format(source.name))

            activity_note = ""
            with tempfile.TemporaryDirectory(prefix="fissure_audio_transcribe_") as work:
                work_dir = Path(work)
                wav_file = work_dir / "input_16k_mono.wav"
                output_prefix = work_dir / "whisper_result"
                await self._run_command([
                    "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
                    "-y", "-i", source, "-map", "0:a:0", "-vn",
                    "-ar", "16000", "-ac", "1", "-c:a", "pcm_s16le", wav_file,
                ], "FFmpeg")
                if not wav_file.is_file() or wav_file.stat().st_size <= 44:
                    raise TranscriptionError("Audio conversion produced an empty WAV")

                duration_seconds = self._duration_seconds(wav_file)
                if self._is_silent(wav_file):
                    language, segments, status = "und", [], "no_speech"
                    activity_note = "Digital silence"
                elif self._is_low_level_noise(wav_file):
                    language, segments, status = "und", [], "no_speech"
                    activity_note = (
                        "Low-level broadband-like noise; heuristic classification, "
                        "not definitive speech detection"
                    )
                else:
                    await self._publish("Recognizing speech: {}".format(source.name))
                    await self._run_command([
                        cli, "-ng", "-m", model, "-l", "auto", "-f", wav_file,
                        "-oj", "-of", output_prefix,
                    ], "whisper.cpp")
                    language, segments = self._parse_json(Path(str(output_prefix) + ".json"))
                    status = "completed" if segments else "no_speech"

            if self._stop:
                raise OperationStopped()
            artifact_id = self._write_artifact(
                source, language, segments, status, duration_seconds, activity_note
            )
            result = {
                "source_file": str(source),
                "detected_language": language,
                "transcription_status": status,
                "artifact_id": artifact_id,
                "segment_count": len(segments),
                "duration_seconds": round(duration_seconds, 2),
            }
            self.result = result
            await self._publish(
                "Audio transcription {}: {} | language={} | artifact={}".format(
                    status, source.name, language, artifact_id
                )
            )
        except OperationStopped:
            self.result = {
                "source_file": str(source or self.audio_file_path),
                "detected_language": "und",
                "transcription_status": "stopped",
                "artifact_id": "",
            }
            await self._publish("Audio transcription stopped: {}".format(
                source.name if source else self.audio_file_path
            ))
        except asyncio.CancelledError:
            raise
        except (TranscriptionError, OSError, ValueError) as exc:
            name = source.name if source else (self.audio_file_path or "(unspecified)")
            self.result = {
                "source_file": str(source or self.audio_file_path),
                "detected_language": "und",
                "transcription_status": "failed",
                "artifact_id": "",
                "error": str(exc),
            }
            self.logger.error("Audio Transcription failed for %s: %s", name, exc)
            detail = " ".join(str(exc).split())[:180]
            await self._publish("Audio transcription failed: {} | {}".format(name, detail))
        except Exception as exc:
            self.logger.exception("Unexpected audio transcription failure")
            self.result = {
                "source_file": str(source or self.audio_file_path),
                "detected_language": "und",
                "transcription_status": "failed",
                "artifact_id": "",
                "error": str(exc),
            }
            await self._publish("Audio transcription failed: unexpected error (see Sensor Node log)")

    async def stop(self) -> None:
        """The base-class Stop wrapper sets _stop; run() terminates active child."""
        return

    async def teardown(self) -> None:
        """No persistent external service or resource to release."""
        return
