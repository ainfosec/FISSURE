# GNURadio Iridium Out Of Tree Module

This module provides blocks to build an Iridium burst detector and demodulator.

It provides a sample application which can be used to detect and demodulate data from the Iridium satellite network.

You should also have a look at the [iridium-toolkit](https://github.com/muccc/iridium-toolkit).

> :warning: **If you want to build for GNURadio 3.7**: Make sure to use the `main-3.7` branch of this repository (i.e. run `git checkout maint-3.7` before installation).

## Prerequisites
A working [GNURadio](https://gnuradio.org) installation with the following components is necessary:

 - VOLK
 - FFT
 - Filter
 - Python
 - SWIG

No other OOT module is needed.

## Installation
If you want to build for GNURadio 3.7, run `git checkout maint-3.7` before installation!

```
mkdir build
cd build
cmake ..
make
sudo make install
sudo ldconfig
```
## Sample Usage
The following commands are examples how to use the `iridium-extractor` tool. To further parse the demodulated frames have a look at the [iridium-toolkit](https://github.com/muccc/iridium-toolkit). It provides scripts to extract meaningful information.

### Online (with an SDR)

`iridium-extractor -D 4 examples/hackrf.conf > output.bits`

This will capture the complete Iridium band using a connected HackRF and demodulate detected bursts into frames. It uses decimation to keep up if there are many bursts at the same time.

### Offline (file based)
`iridium-extractor -c 1626000000 -r 2000000 -f float --offline name-f1.626000e+09-s2.000000e+06-t20160401000000.cfile > output.bits`

This processes the file in offline mode and supplies the needed options via the command line.

## Extracting Iridium Frames From Raw Data

To capture and demodulate Iridium frames use `iridium-extractor`. You can either process a file offline or stream data into the tool.

The extractor can read a configuration file. It also accepts arguments from the command line.
The `examples/` directory contains example configuration files for common use cases.

Some options are only available via the configuration file, others are only available via the command line. If no configuration file is used, a file name can be provided to read samples from a file. If no (configuration) file is specified, samples are read from stdin.

### Configuration File
Configuration files need to have a `.conf` file extension.
The configuration file is grouped into sections. Each section starts with a `[section-name]` line.
### `osmosdr-source` Section

If this section is present an `osmosdr-source` is instantiated

| Option Name      | Description                                |
|------------------|--------------------------------------------|
| `sample_rate`    | Sample rate at which the source should run |
| `center_freq`    | Center frequency for the source in Hz      |
| `gain`           | (RF)-Gain in dB                            |
| `if_gain`        | IF-Gain in dB                              |
| `bb_gain`        | BB-Gain in dB                              |
| `bandwidth`      | Base band filter bandwidth in Hz           |


### Command Line Options
Command line options can be used instead of a configuration file. If a configuration file is also specified, command line options take precedence.

#### `-o`, `--offline`: Offline Processing
By default, the extractor will drop samples or bursts if the computing power available is not enough to keep up.

If you have an already recorded file, use the `-o`,`--offline` option to not drop bursts. In this case the extractor will pause reading the file (or input stream) until it can process more samples again.

#### `-D`, `--decimation`: Decimation
This option enables decimation and channelization of the input stream before it gets handled by the burst based components. This helps to reduce the needed memory bandwidth when many bursts appear at the same time. Use this option if you get dropped bursts during online operation.

The decimation has to be even. Internally a poly phase filter bank will be used to channelize the input spectrum. Each channel will be decimated by the chosen decimation. To account for Doppler shift, the channels overlap each other. To provide the needed additional sample rate, one more channel than needed is created and oversampling activated. This results in a total output bandwidth of input bandwidth * (1 + 1/decimation).

It is not recommended to use a decimation smaller than 4, as there is only little benefit otherwise.

Decimating the input signal can improve real time performance but is not recommended for offline processing. During offline processing it tends to become a major bottleneck.

#### `-c`: Center Frequency
The center frequency for the source or the file in Hz.

#### `-r`: Sample Rate
The sample rate of the source or the file.

#### `-f`: Input File Format
| File Format                                        | `iridium-extractor` format option |
|----------------------------------------------------|-----------------------------------|
| complex uint8 (RTLSDR)                             | `rtl`                             |
| complex int8 (hackrf, rad1o with hackrf-transfer)  | `hackrf`                          |
| complex int16 (USRP with specrec from gr-analysis) | `sc16`                            |
| complex float (GNURadio, `uhd_rx_cfile`)           | `float`                           |

#### `-q`: Queue Length
For each channel (by default there is one), a queue is filled with samples where the detector has detected activity. By default each queue is 500 frames long. You can tweak the length of the queue(s) with this option.

#### `--debug-id`: Output debug information for a specific burst
Each burst which is detected gets assigned an id. It appears in the output data as `I:xxxxxxxxxxx` for bursts which were decoded into frames.

Set this option (e.g. `--debug-id=23`) to output debug information for burst number 23. Debug information includes:

 - Debug prints on `stdout`.
 - Raw sample files written to `/tmp/signals`.

#### `--file-info`: File Info
Manually set the file info field (second field) in the output data. If this option is not used, the current time will be used.
