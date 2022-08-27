# GNU Radio Iridium Out Of Tree Module

[![CI](https://github.com/muccc/gr-iridium/actions/workflows/ci.yml/badge.svg)](https://github.com/muccc/gr-iridium/actions/workflows/ci.yml)

This module provides blocks to build an Iridium burst detector and demodulator.

It provides a sample application which can be used to detect and demodulate data from the Iridium satellite network.

You should also have a look at the [iridium-toolkit](https://github.com/muccc/iridium-toolkit).

> :warning: **If you want to build for GNU Radio 3.8**: Make sure to use the `maint-3.8` branch of this repository (i.e. run `git checkout maint-3.8` before installation). Also make sure to check the README.md from that branch for correct build instructions.

A working [GNU Radio 3.10](https://gnuradio.org) installation is necessary to use gr-iridium.

## Build & Installation

Installation instructions for:

 - [Ubuntu 22.04 (from source)](docs/install-ubuntu-22.04.md)
 - [Ubuntu 22.04 on Rasperry Pi 4 (from source)](docs/install-ubuntu-22.04-rpi-source.md)
 - [DragonOS Pi64 Beta](docs/install-dragon-os-pi64-beta.md)

If your operating system is not listed above, first install the following dependencies:
 - gnuradio-dev
 - libvolk-dev
 - pybind11-dev
 - libsndlib1-dev

Afterwards try these generic build instructions:
```
cmake -B build
cmake --build build
sudo cmake --install build
sudo ldconfig
```

### GNU Radio on Ubuntu 20.04 or Debian stable (bullseye) or Raspberry Pi OS (64-bit)
The recommended GNU Radio versions to use gr-iridium with is GNU Radio 3.10. If you use a Ubuntu version older than Ubuntu 22.04 or Debian stable (bullseye) our recommended way to install GNU Radio is to use PyBOMBS as described here: https://github.com/Sec42/sec-gr/. Please expect trouble if you install GNU Radio any other way on these systems.

## Usage examples
The following commands are examples how to use the `iridium-extractor` tool. To further parse the demodulated frames have a look at the [iridium-toolkit](https://github.com/muccc/iridium-toolkit). It provides scripts to extract meaningful information.

### SDR Sample Rates and Iridium

![channels](docs/channels.svg)

To our knowledge Iridium is currently using the spectrum between 1.618 GHz and 1.6265 GHz which is a bandwidth of 8.5 MHz.
Many modern SDRs support such a bandwidth with sample rates >= 10 MSPS. RTL-SDR devices do not though and you need to make
a choice which section of the band you want to listen to. The configurations in the `example/` folder for RTL-SDRs
include the "Time and Location", "Ring Alert" and "Pager / Global Burst" channels. If you are more interested in
user payloads (like ACARS) you might want to move the center frequency of the RTL-SDR configurations to a lower
frequency (e.g. 1622 MHz) to capture more of the duplex band. You can also experiment with the sample rate and
for example raise it to 2.5 MSPS or 3.0 MSPS.

If your SDR supports at maximum 8 MSPS you will have to decide if the simplex band is of interest to you or if you
want to capture the first 500 kHz of the duplex band.

SDRs which support more than 10 MSPS capture the whole used band.

### Online (with an SDR)
`iridium-extractor -D 4 examples/hackrf.conf > output.bits`

This will capture the complete Iridium band using a connected HackRF and demodulate detected bursts into frames. It uses decimation to keep up if there are many bursts at the same time.

### Online (with external tool)
`hackrf_transfer -f 1626000000 -s 10000000 -r - | iridium-extractor -c 1626000000 -r 10000000 -f hackrf -`

You can also pipe a raw sample stream into `iridium-extractor`. This may be useful if your SDR is not supported or if you stream samples from another computer via TCP (e.g. with `rtl_tcp`).

### Offline (raw capture)
`iridium-extractor -c 1626000000 -r 2000000 -f float name-f1.626000e+09-s2.000000e+06-t20160401000000.cfile > output.bits`

This processes the file in offline mode and supplies the needed options via the command line.

### Offline (wav file)
`iridium-extractor -c 1622000000 baseband.wav > output.bits`

A 2-channel 16bit wav file is also accepted as input.  Command line option `-r` can be used to override the sample rate.

###  Offline (SigMF)
 `iridium-extractor recording-test.sigmf-data > output.bits`

`iridium-extractor`  supports both [SigMF](https://github.com/gnuradio/SigMF/blob/sigmf-v1.x/sigmf-spec.md) files (`.sigmf-meta` / `.sigmf-data`) as well as [SigMF archives](https://github.com/gnuradio/SigMF/blob/sigmf-v1.x/sigmf-spec.md#sigmf-archives) (`.sigmf`).

Command line options `-c`, `-r` and `-f` can be used to override the SigMF information.

## Extracting Iridium Frames From Raw Data
To capture and demodulate Iridium frames use `iridium-extractor`. You can either process a file offline or stream data into the tool.

The extractor can talk directly to an SDR with the help of [SoapySDR](https://github.com/pothosware/SoapySDR) or [OsmoSDR](https://osmocom.org/projects/gr-osmosdr/wiki). This is enabled via a configuration file.

The `examples/` directory contains example configuration files for common use cases.

If no configuration file is used, a file name can be provided to read samples from a file. If no file is specified, samples are read from `stdin`.

### Configuration File
Configuration files need to have a `.conf` file extension.
The configuration file must contain exactly one source section and start with a
corresponding `[section-name]` line.

### `osmosdr-source` Section
If the `[osmosdr-source]` section is present, an OsmoSDR source is instantiated.

The following options are available in this section:

| Option Name      | Required | Description                                |
|------------------|----------|--------------------------------------------|
| `device_args`    | No       | Device arguments passed onto osomosdr<sup>[1](#dev)</sup>|
| `sample_rate`    | Yes      | Sample rate at which the source should run. Must be divisible by 100000. |
| `center_freq`    | Yes      | Center frequency for the source in Hz      |
| `gain`           | No       | (RF)-Gain in dB                            |
| `*_gain`         | No       | set specific Gain in dB (e.g. IF, BB, VGA1) |
| `bandwidth`      | No       | Base band filter bandwidth in Hz           |
| `antenna`        | No       | Antenna port to use                        |

<a name="dev">1</a>: Mostly used to enable bias tee - check files under `examples/`

### `soapy-source` Section
If the `[soapy-source]` section is present, a SoapySDR source is instantiated.

The following options are available in this section:

| Option Name      | Required | Description                                |
|------------------|----------|--------------------------------------------|
| `driver`         | Yes      | Soapy driver to be used<sup>[1](#factories)</sup>        |
| `dev_args`       | No       | Device arguments passed onto SoapySDR<sup>[2](#dev)</sup>|
| `stream_args`    | No       | Stream arguments passed onto SoapySDR via gr-soapy<sup>[3](#args)</sup>      |
| `tune_args`      | No       | Tune arguments passed onto SoapySDR via gr-soapy<sup>[3](#args)</sup>        |
| `other_settings` | No       | "Other settings" parameter passed onto SoapySDR via gr-soapy<sup>[3](#args)</sup>        |
| `sample_rate`    | Yes      | Sample rate at which the source should run. Must be divisible by 100000. |
| `center_freq`    | Yes      | Center frequency for the source in Hz      |
| `bandwidth`      | No       | Base band filter bandwidth in Hz           |
| `antenna`        | No       | Which antenna port should be used          |
| `gain`           | No       | (RF)-Gain in dB                            |
| `*_gain`         | No       | set specific Gain in dB<sup>[4](#gain)</sup> |

<small><a name="factories">1</a>: Run `SoapySDRUtil --info |grep factories` to see available drivers on your system.</small>
<small><a name="dev">2</a>: Mostly used to enable an integrated bias tee - check files under `examples/`.</small>
<small><a name="args">3</a>: These arguments are highly device specific. You might find hints in `examples/` or your SDR's SoapySDR driver. </small>
<small><a name="gain">4</a>: Check the output of `SoapySDRUtil --probe` to find valid gain names for your SDR. Gain names are usually different between OsmoSDR and SoapySDR.</small>

### `zeromq-sub-source` Section
If the `[zeromq-sub-source]` section is present, ZeroMQ is used to receive data from a `ZMW PUB Sink` running in another flow graph.

The following options are available in this section:

| Option Name      | Required | Description                                |
|------------------|----------|--------------------------------------------|
| `address`        | Yes      | Address of the source. Something like `tcp://127.0.0.1:5000`. |
| `sample_rate`    | Yes      | Sample rate at which the source is running. Must be divisible by 100000. |
| `center_freq`    | Yes      | Center frequency of the source in Hz.      |
| `pass_tags`      | No       | Must be equal to the `Pass Tags` setting of the `ZMQ PUB Sink` block. Default is `False`. Valid options are `True` and `False`. Relevant if you want to receive `rx_time` tags from your source.|
| `high_water_mark`| No       | ZMQ's "High Water Mark" option. Default is `-1`. |

See `examples/zeromq-sub.conf` and `experimental/zmq-publisher.grc` for examples how to use this source.
Also have a look at https://wiki.gnuradio.org/index.php/ZMQ_SUB_Source and https://wiki.gnuradio.org/index.php/ZMQ_PUB_Sink .

Also consider https://github.com/muaddib1984/stillsuit as a solution to create a compatible source.

Warning: If you set `pass_tags` to `True` make sure that your source is not supplying bogus `rx_time` tags.
This is by default the case when using a USRP without a properly configured external time source. In this case
the timestamps reported by gr-iridium will follow what ever the `rx_time` tags of the source tell it. Sometimes
this might be based on the uptime of some system part or something similar.

### `uhd-source` Section
If the `[uhd-source]` section is present, UHD is used to connect to a USRP.

This is mainly of interest when working with an internal GPSDO as gr-iridium will wait for
it to lock if `clock_source` or `time_source` specifies an internal GPSDO. This source will always
use channel 0 of the chosen USRP.

| Option Name      | Required | Description                                |
|------------------|----------|--------------------------------------------|
| `device_addr`    | No       | Device address. Default lets UHD pick a device.|
| `device_args`    | Yes      | Device arguments passed onto UHD. Must be supplied to configure buffer sizes.|
| `sample_rate`    | Yes      | Sample rate at which the source is running. Must be divisible by 100000. |
| `center_freq`    | Yes      | Center frequency of the source in Hz.      |
| `gain`           | No       | Gain in dB.                                |
| `bandwidth`      | No       | Base band filter bandwidth in Hz.          |
| `antenna`        | No       | Antenna port to be used.                   |
| `clock_source`   | No       | Can be used to specify an external reference clock.                   |
| `time_source`    | No       | Can be used to specify the time source.                   |

Please refer to the UHD documentation for your device to understand the options for `antenna`, `clock_source` and
`time_source`. Tested options so far are `external`, `gpsdo` and `jacksonlabs` (see below).

gr-iridium implements a special `clock_source` and `time_source` for USRP B2x0 devices `jacksonlabs`. It
improves waiting for proper GPS lock before starting a capture. Use this if you have an internal Jacksonlabs
GPSDO.

See `examples/usrp-b2x0-uhd.conf` for an example how to use this with a B2x0 device.

### `demodulator` Section
The optional `[demodulator]` section can be used to influence the demodulator behavior.

| Option Name          | Required | Description                                |
|----------------------|----------|--------------------------------------------|
| `samples_per_symbol` | No       | Modifies the number of samples per symbol after down-mixing. Default is 10. Lower values decrease CPU/memory requirements and offer more flexibility for SDR sample rates. Higher values might demodulate a few more burst. |
| `decimation`         | No       | See `--decimation` in the section below.   |

The `samples_per_symbol` option is useful if you are running on a constrained system like a single
board ARM computer (e.g. a Raspberry Pi). It also allows you to use sample rates which are not a
multiple of 250000 samples per second. E.g. a setting of 5 samples per symbol allows your SDRs sample
rate to be a multiple of 25000 * 5 = 125000 samples per second. A setting of 8 allows the sample rate
to be a multiple of 200000 samples per second which for example works out well with 3.2 MSPS RTL-SDRs.

### Command Line Options
Command line options can be used instead of a configuration file. If a configuration file is also specified, command line options take precedence.

#### `-o`, `--offline`: Offline Processing
In live/SDR mode, the extractor will drop samples or bursts if the computing power available is not enough to keep up. (See `-q` option).

In offline/file mode, the extractor will pause reading the file (or stream) until it can process more samples again.

When reading samples from a pipe / stdin `iridium-extractor` does not know which mode is correct and defaults to live mode. You can use this option to override this choice and avoid dropping bursts.

This option is only necessary to use if you pipe samples from stdin.

#### `-D`, `--decimation`: Decimation
This option enables decimation and channelization of the input stream before it gets handled by the burst based components. This helps to reduce the needed memory bandwidth when many bursts appear at the same time. Use this option if you get dropped bursts during online operation.

The decimation has to be even. Internally a poly phase filter bank will be used to channelize the input spectrum. Each channel will be decimated by the chosen decimation. To account for Doppler shift, the channels overlap each other. To provide the needed additional sample rate, one more channel than needed is created and oversampling activated. This results in a total output bandwidth of input bandwidth * (1 + 1/decimation).

It is not recommended to use a decimation smaller than 4, as there is only little benefit otherwise.

Decimating the input signal can improve real time performance but is not recommended for offline processing. During offline processing it tends to become a major bottleneck.

This value is limited to even values and the sample rate divided by decimation must be a multiple of 250000.

#### `-c`: Center Frequency
The center frequency for the source or the file in Hz.

#### `-r`: Sample Rate
The sample rate of the source or the file. Must be divisible by 100000.

#### `-f`: Input File Format
The following 4 formats are supported for sample input. For ease of use the names in the alias column can also be used.
| Format    | File Format                                        | Alias            |
|-----------|----------------------------------------------------|------------------|
| `cu8`     | complex uint8 (RTL-SDR)                            | `rtl`            |
| `ci8`     | complex int8 (hackrf, rad1o with hackrf-transfer)  | `hackrf`         |
| `ci16_le` | complex int16 (USRP with specrec from gr-analysis) | `sc16`           |
| `cf32_le` | complex float (GNU Radio, `uhd_rx_cfile`)           | `float` , `fc32`, `cfile` |

If not specified otherwise, `iridium-extractor` tries to use the file extension to identify the format.

This option has no effect while directly reading from an SDR.

#### `-q`: Queue Length
For each channel (by default there is one channel, unless specified with `-D` ), a queue is filled with samples where the detector has detected activity. By default each queue is 500 frames long. You can tweak the length of the queue(s) with this option.

#### `--debug-id`: Output debug information for a specific burst
Each burst which is detected gets assigned an id. It appears in the output data as `I:xxxxxxxxxxx` for bursts which were decoded into frames.

For example `--debug-id=230` to output debug information for the burst containing frames `230` up to `239`.

 Debug information includes:

 - Debug prints on `stdout`.
 - Raw sample files written to `/tmp/signals`.

**Note:** Last digit needs to always be `0`

#### `--file-info`: File Info
Manually set the file info field (second field) in the output data. If this option is not used, the default will be:
* basename of the sample source file if available
* current time otherwise (i.e.  when reading from an SDR or stdin)

#### `-v`: Verbose
will output some additional info when starting up.

#### `--db`: Signal detection threshold
how much stronger a signal needs to be over the noise floor to attempt to extract it.

Default value is `18`. Values lower than `16` are rarely useful, as the QPSK decoder will produce too many bit errors.

#### `--raw-capture`: Copy raw samples to file
write a copy of the samples to a SigMF recording.

The parameter specifies the path & basename of the SigMF files.

This is mostly useful for debugging when using SDR mode to process live data.

The samples will be written in `ci16_le` format.

### Interactive Output
During normal operation `iridium-extractor` will output a status line once per second on `stderr`.
#### SDR / live mode

`1577922120 | i:   0/s | i_avg:   0/s | q_max:    0 | i_ok:   0% | o:    0/s | ok:   0% | ok:   0/s | ok_avg:   0% | ok:          0 | ok_avg:   0/s | d: 0`

|Column|Mnemonic|Explanation|
|-|-|-|
|  1|time         |Current time in seconds (unix time)|
|  2|input        |number of "bursts" detected in the last second|
|  3|input average|average of `2` since program start|
|  4|queue max    |High-water mark of the sum of the queue size(s) in the last second (see `-q`)|
|  5|in ok%       |Percentage of bursts with at least one ok frame relative to `2`|
|  6|out          |Number of "frames" after splitting bursts into frames|
|  7|ok%          |Percentage of "ok" frames(`8`) relative to `2` |
|  8|ok           |Number of frames in the last second that could be extracted & demodulated|
|  9|ok% average  |average of `7` since program start|
| 10|ok total     |Total number of ok frames since program start|
| 11|ok avg       |average of `8` since program start|
| 12|drops        |Total number of candidate bursts that had to be dropped due to queue full (i.e. CPU being too slow)|

During normal operation `drops` should remain `0`, while `queue max` should be in the lower double digits "most" of the time.
The `input` number is largely dependent on your antenna and will also vary depending on satellite location.

#### File / offline mode
`1577922120 | srr: 0.0% | i_avg:   0/s | q_max:    0 | i_ok:   0% | o:    0/s | ok:   0% | ok:   0/s | ok_avg:   0% | ok:          0 | ok_avg:   0/s | d: 0`

All columns here have the same content as in SDR/live mode, except

|Column|Mnemonic|Explanation|
|-|-|-|
|  2|sample rate rate|Processing speed relative to recorded sample rate in the last second|

If this value is consistently lower than 100% it is likely that you would loose/drop bursts in SDR/live mode.

### Bits Output
During normal operation `iridium-extractor` will output one line of bits per "ok" frame on `stdout`. Usually `stdout` should be redirected to a file. By convention this file should have the extension `.bits`.

`RAW: prbs15-2M-20dB 0000599.9996 1622000000 N:32.12-80.05 I:00000000000 100% 0.13551 179 0011000000110000111100111000000000000011000000000000101000000000001111000000000010001000000000110011000000001010101000000011111111000000100000001000001100000011000010100000101000111100001111001000100010001011001100110011101010101010100111111111111101000000000000111000000000001001000000000011011000000000101101000000001110111000000010011001000000110101011000001011111101000011100000`

|Column|Example|Explanation|
|-|-|-|
|  1|RAW:          |Indicates that this is an unprocessed output from `iridium-extractor` |
|  2|prbs15-2M-20dB|File info - see `--file-info` command line option[^fileinfo]|
|  3|0000599.9996  |Time in ms since start of recording/extraction[^time]. This is derived from sample counting and will drift depending on your SDR clock accuracy (and also when dropping samples)|
|  4|1622000000    |Frequency in Hz at which this "frame" was detected|
|  5|N:32.12-80.05 |Relative Magnitude of the detected "burst" (≥ `--db`) and average Noise/Hz at that time/frequency in dBFS|
|  6|I:00000000000 |Frame ID (unique identifier for each frame)[^id]. Referenced by `--debug-id`|
|  7|100%          |Confidence the QPSK demodulator has in the demodulated bits|
|  8|0.13551       |Signal level of the demodulated signal[^signal]|
|  9|179           |Length of the signal in symbols (i.e. `len(bits)/2`)|
| 10|...           |Raw bits[^bits]|

[^fileinfo]: In live mode: `i-<timestamp>-t1` whereas `timestamp` is a unix `time_t` representing the start of the recording.
[^time]: Time in `3` is defined as the middle of the first symbol of the 12-symbol BPSK Iridium sync word.
[^id]: Last digit identifies the sub-frame of a burst.
[^signal]: Due to historic reasons column `8` is not in dB. Convert do dBFS via `20*log10(_value_)`.
[^bits]: Due to historic reasons the bits in column `10` are symbol-wise reversed to how they would normally be presented.

## Citations

 - Accessing the RF Spectrum with GNU Radio: https://www.osti.gov/servlets/purl/1639511
 - PAST-AI: Physical-layer Authentication of Satellite Transmitters via Deep Learning: https://arxiv.org/pdf/2010.05470.pdf
 - Hacker-Attacks Against Satellites - An Evaluation of Space Law in Regard to the Nature of Hacker-Attacks: https://www.researchgate.net/publication/353846410_Hacker-Attacks_Against_Satellites_An_Evaluation_of_Space_Law_in_Regard_to_the_Nature_of_Hacker-Attacks
 - GNSS Spoofing Detection via Opportunistic IRIDIUM Signals - https://arxiv.org/pdf/2006.10284.pdf
 - The GR PDU Utilities: https://www.osti.gov/servlets/purl/1641974
