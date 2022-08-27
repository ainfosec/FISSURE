gr-nrsc5
========

This project implements an HD Radio transmitter in GNU Radio.
HD Radio is standardized in NRSC-5. The latest version of the
standard is NRSC-5-D, which can be found at
https://www.nrscstandards.org/standards-and-guidelines/documents/standards/nrsc-5-d/nrsc-5-d.asp.

If you're interested in receiving HD Radio, a stand-alone receiver for RTL-SDR
is available here: https://github.com/theori-io/nrsc5/

## Installation

If you installed GNU Radio using PyBOMBS, simply run `pybombs install gr-nrsc5`.

Otherwise, run the following commands:

    mkdir build
    cd build
    cmake ..
    make
    sudo make install
    sudo ldconfig

If your GNU Radio is installed in `/usr` (rather than `/usr/local`), then
replace the cmake line above with:

    cmake -DCMAKE_INSTALL_PREFIX=/usr ..

## Blocks:

### HDC encoder

This block encodes audio into High-Definition Coding (HDC) frames. The input sample rate must be 44,100 samples per second. ADTS headers are added to the output frames to facilitate synchronization. The encoding is performed by a patched version of fdk-aac: https://github.com/argilo/fdk-aac/tree/hdc-encoder

### PSD encoder

This block encodes Program Service Data PDUs, as described in https://www.nrscstandards.org/standards-and-guidelines/documents/standards/nrsc-5-d/reference-docs/1028s.pdf. PSD conveys information (e.g. track title & artist) about the audio that is currently playing.

### SIS encoder

This block encodes Station Information Service PDUs, as described in https://www.nrscstandards.org/standards-and-guidelines/documents/standards/nrsc-5-d/reference-docs/1020s.pdf, and assembles them into the PIDS and SIDS logical channels. SIS provides information about the station. Currently only the short station name (i.e. call sign) is encoded.

### Layer 2 encoder

This block assembles HDC audio frames and PSD PDUs into the audio transport, producing layer 2 PDUs (as defined in https://www.nrscstandards.org/standards-and-guidelines/documents/standards/nrsc-5-d/reference-docs/1014s.pdf and https://www.nrscstandards.org/standards-and-guidelines/documents/standards/nrsc-5-d/reference-docs/1017s.pdf).

### Layer 1 FM encoder

This block implements Layer 1 FM (as defined in https://www.nrscstandards.org/standards-and-guidelines/documents/standards/nrsc-5-d/reference-docs/1011s.pdf). It takes PIDS and Layer 2 PDUs as input, and produces OFDM symbols as output. Only the Hybrid and Extended Hybrid modes have been implemented and tested so far. The All Digital modes are currently under development.

### Layer 1 AM encoder

This block implements Layer 1 AM (as defined in https://www.nrscstandards.org/standards-and-guidelines/documents/standards/nrsc-5-d/reference-docs/1012s.pdf). It takes PIDS and Layer 2 PDUs as input, and produces OFDM symbols as output. Both Hybrid (MA1) mode and All Digital (MA3) mode are implemented.

## Flowgraphs:

Several sample flowgraphs are available in the apps folder:

### FM

* hd_tx_usrp.grc, hd_tx_usrp.py: tested on a USRP B200
* hd_tx_hackrf.grc, hd_tx_hackrf.py: tested on a HackRF One
* hd_tx_rtl_file.grc, hd_tx_rtl_file.py: produces an output file in the format used by https://github.com/theori-io/nrsc5/

### AM

* hd_tx_am_hackrf.grc, hd_tx_am_hackrf.py: Hybrid mode, tested on a HackRF One
* hd_tx_am_ma3_hackrf.grc, hd_tx_am_ma3_hackrf.py: All Digital mode, tested on a HackRF One

These flowgraphs read a WAV file named sample.wav, which must be encoded at 44,100 samples per second. The license for the supplied sample.wav file is as follows:

> Copyright 2013, Canonical Ltd.
> This work is licensed under the Creative Commons Attribution-ShareAlike 3.0
> Unported License. To view a copy of this license, visit
> http://creativecommons.org/licenses/by-sa/3.0/ or send a letter to Creative
> Commons, 444 Castro Street, Suite 900, Mountain View, California, 94041, USA.
