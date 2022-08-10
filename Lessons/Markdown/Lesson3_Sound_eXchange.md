---
Sound eXchange (SoX) is the Swiss Army knife of sound processing programs. It is a cross-platform command line utility that can convert various formats of computer audio files into other formats. It can also apply various effects to these sound files as well as do recording and playback.

This lesson will list many `sox` examples as well as other related audio commands.

## Table of Contents
1. [Install](#install)
2. [Record](#record)
3. [Play](#play)
4. [Effects](#effects)
5. [Combine](#combine)
6. [Volume](#volume)
7. [Extract](#extract)
8. [Noise Removal](#noise_removal)
9. [Trim Silence](#trim_silence)
10. [Split by Silence](#split_by_silence)
11. [Reverse](#reverse)
12. [Normalize](#normalize)
13. [Convert to Stereo](#convert_to_stereo)
14. [Convert to Mono](#convert_to_mono)
15. [Change Sample Rate](#change_sample_rate)
16. [Change Sample Size](#change_sample_size)
17. [Raw to Wav](#raw_to_wav)
18. [Wav to MP3](#wav_to_mp3)
19. [MP3 to Wav](#mp3_to_wav)
20. [Info](#info)
21. [Spectrogram](#spectrogram)
22. [Waveforms](#waveforms)
23. [Batch](#batch)


## Examples

<div id="install"/> 

**Install**
```
sudo apt-get install sox mpv ffmpeg lame mplayer
```

<div id="record"/> 

**Record**
```
sox -t alsa default test.wav
sox -t ossdsp /dev/dsp test.wav (for some)
rec test.wav
rec test.wav trim 0 30:00
rec -r 8000 -c 1 test.wav
```

<div id="play"/> 

**Play**
```
play test.wav
play test.wav speed 0.5
mplayer test.wav
mplayer test.mp3
mpv test.wav
mpv test.mp3
```

<div id="effects"/> 

**Effects**
```
allpass, band, bandpass, bandreject, bass, bend, biquad, channels, chorus, compand, contrast, dcshift, deemph, delay, dither, downsample, earwax, echo, echos, equalizer, fade, fir, flanger, gain, highpass, hilbert, ladspa, loudness, lowpass, mcompand, noiseprof, noisered, norm, oops, overdrive, pad, phaser, pitch, rate, remix, repeat, reverb, reverse, riaa, silence, sinc, spectrogram, speed, splice, stat, stats, swap, stretch, synth, tempo, treble, tremolo, trim, upsample, vad, vol
```

<div id="combine"/> 

**Combine**
```
sox -m first_part.wav second_part.wav whole_part.wav
sox --combine mix countdown.mp3 intro.ogg output.flac (at same time)
```

<div id="volume"/> 

**Volume**
```
sox -v -0.5 srcfile.wav dstfile.wav
```

<div id="extract"/> 

**Extract**
```	
sox input.wav output.wav trim 0 10 (location, duration)
```

<div id="noise_removal"/> 

**Noise Removal**
```
sox foo.wav -t nul /dev/null trim 0 0.5 noiseprof profile
play foo.wav noisered profile
```

<div id="trim_silence"/> 

**Trim Silence**
```
sox infile.wav outfile.wav silence 1 0.1 1%          (beginning)
sox infile.wav outfile.wav silence 1 0.1 1% 1 0.1 1% (beginning and end)
sox in.wav out.wav silence 1 0.1 1% -1 0.1 1%        (middle)
sox in.wav out.wav silence -l 1 0.1 1% -1 2.0 1%     (trims long silence)
play speech.wav vad                                  (beginning)
play speech.wav vad reverse vad reverse              (beginning and end)
```

<div id="split_by_silence"/> 

**Split By Silence**
```
sox in.wav out.wav silence 1 0.5 1% 1 5.0 1% : newfile : restart
```

<div id="reverse"/> 

**Reverse**
```
play test.wav reverse
```

<div id="normalize"/> 

**Normalize**
```
sox in.wav out.wav norm 
for file in *.wav; do sox "$file" "n_$file" norm -0.1; done
```

<div id="convert_to_stereo"/> 

**Convert to Stereo**
```
sox mono.wav -c 2 stereo.wav
```

<div id="convert_to_mono"/> 

**Convert to Mono**
```
sox stereo.wav mono.wav channels 1
sox stereo.wav -c 1 mono.wav avg -l
sox stereo.wav -c 1 mono.wav avg     
for file in *.wav; do sox "$file" "mono_$file" channels 1; done
```

<div id="change_sample_rate"/> 

**Change Sample Rate**
```
sox in.wav out.wav rate 48k  (8k, 11.025k, 16k, 22.05k, 32k, 37.8k, 44.056k, 44.1k, 47.25k, 48k, 50k, 50.4k, 64k, 88.2k, 96k, 176.4k, 192k, 352.8k, 2822.4k, 5644.8k, 11289.6k, 22579.2k) 
for file in *.wav; do sox "$file" "48khz_$file" rate 48k; done
```

<div id="change_sample_size"/> 

**Change Sample Size**
```
sox in.wav -b 16 out.wav
for file in *.wav; do sox "$file" -b 16 "16bit_$file"; done
```

<div id="raw_to_wav"/> 

**Raw to Wav**
```
sox -c 2 -r 8000 audio1.raw audio1.wav
sox -w -c 2 -r 8000 audio1.raw audio1.wav (-w not recognized)
```

<div id="wav_to_mp3"/> 

**Wav to MP3**
```
ffmpeg -i foo.wav foo.mp3
lame -h audio1.wav audio1.mp3
mplayer audio1.mp3
```

<div id="mp3_to_wav"/> 

**MP3 to Wav**
```
ffmpeg -i foo.mp3 foo.wav
```

<div id="info"/> 

**Info**
```
soxi test.wav
soxi *.wav > database.csv
sox inputFile.wav -n stat
```

<div id="spectrogram"/> 

**Spectrogram**
```
sox input.wav -n spectrogram -t "top label" -c "corner label" -o inputFileName.png
```

<div id="waveforms"/> 

**Waveforms**
```
ffmpeg -i inputFile.wav -lavfi showwavespic=split_channels=1:s=1024x800 outputWaveform.png
```

<div id="batch"/> 

**Batch**
```
for file in *.wav; do sox "$file" "n_$file" norm -0.1; done
```
