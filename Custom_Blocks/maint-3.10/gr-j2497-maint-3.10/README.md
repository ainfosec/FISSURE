# gr-j2497

This GNU Radio out-of-tree module contains flow graphs with custom blocks for reading and writing PLC4TRUCKS traffic. SAE J2497 defines the method for implementing a bidirectional, serial communications link over the vehicle power supply line among modules containing microcomputers. SAE J2497 (PLC4TRUCKS) is essentially an alternative physical layer for J1708 that encodes payloads using spread-spectrum chirps centered on the 12-volt power line. The PLC bus traffic can be sniffed reliably with an active antenna from several feet away as entailed in CVE-2020-14514 and the 2020 DEF CON 28 talk "Power Line Truck Hacking: 2TOOLS4PLC4TRUCKS":
- https://nvd.nist.gov/vuln/detail/CVE-2020-14514
- http://www.nmfta.org/documents/ctsrp/Power_Line_Truck_Hacking_2TOOLS4PLC4TRUCKS.pdf?v=1

![tractor_trailer_hack](/examples/images/tractor_trailer_hack.png)

The primary purpose for J2497 is monitoring and reporting trailer ABS status to the driver via an instrument panel indicator lamp located in the tractor (LAMP ON and LAMP OFF messages). However, it is also capable of performing trailer brake ECU diagnostic functions. This poses a security risk as there is no authentication or authorization for these functions. See ICSA-22-063-01 and CVE-2022-25922 for more details:
- https://www.cisa.gov/uscert/ics/advisories/icsa-22-063-01
- https://nvd.nist.gov/vuln/detail/CVE-2022-25922

J2497 trailer receivers are susceptible to remote RF induced signals. As trailers and their power lines can be found in many configurations and sizes, the physical geometry and other electromagnetic factors will determine how well a system can receive the induced signals. More information is available at:
- https://www.cisa.gov/uscert/ics/advisories/icsa-22-063-01
- https://nvd.nist.gov/vuln/detail/CVE-2022-26131
- https://www.securityweek.com/tractor-trailer-brake-controllers-vulnerable-remote-hacker-attacks

A great resource on J2497 and truck hacking can be found at:
- http://www.nmfta.org/documents/ctsrp/Commercial_Transportation_v7_DIST.pdf?v=1

An open-source tool for decoding the J2497 messages to a more user-friendly format (requires the latest J1587 and J1708 specifications) can be downloaded at:
- https://github.com/ainfosec/pretty_j1587

The gr-j2497 maint-3.7 branch is compatible with GNU Radio 3.7, maint-3.8 branch is compatible with GNU Radio 3.8 and maint-3.10 branch is compatible with GNU Radio >= 3.10.

# Hardware

This project contains an implementation of a J2497 (PLC4TRUCKS) receiver that can be used with any GNU Radio SDR capable of receiving 100 kHz - 400 kHz. For RTL-SDR and others, this will require an upconverter. Below is an example receiver configuration using an active antenna, Ham It Up, and an RTL-SDR to upconvert the signals to 125 MHz. 

![antenna](/examples/images/antenna.jpg)

J2497 signals can be generated with most SDRs including the HackRF, USRP B205mini & B210, and fl2k. The HackRF and fl2k are capable of transmitting the signals directly at baseband. SDRs that are unable to tune to such low frequencies can use the Ham It Up in reverse as a downconverter to translate signals centered around 125 MHz down to baseband.

# Signal

The J2497 signal consists of two parts: a preamble that uses amplitude shift keying and a body that uses phase shift keying. The chirp signal consists of three transitions: 203 -> 400 kHz, 400 -> 100 kHz, and 100 -> 203 kHz.

![j2497](/examples/images/j2497.png)

![j2497_zoom](/examples/images/j2497_zoom.png)

The preamble is used to perform arbitration using the MID.

![preamble](/examples/images/preamble.png)

The body will typically contain a J1708 message wrapped with extra sync and end bits.

![fields](/examples/images/fields.png)

# Prerequisites

```
sudo apt-get install python-scipy
```

# Installation
```
cd gr-j2497
mkdir build
cd build
cmake .. # or cmake -DCMAKE_INSTALL_PREFIX=<path_to_install> .. # (/usr or /usr/local)
make
sudo make install
sudo ldconfig
```

# Usage

## Receiving
Run the flow graphs in `/examples` with GNU Radio Companion to view messages in the console panel. There are three different receive methods to choose from. If enabled on the decoder blocks, view the decoded output over UDP with a network sniffer (e.g. Wireshark) or with the `j1708dump.py --interface=plc` command of https://github.com/TruckHacking/plc4trucksduck. Successful message decodes of the message body will look like:

![message_printout](/examples/images/message_printout.png)

The custom blocks send UDP packets that are compatible with the `j1708_logger.py` script for https://github.com/TruckHacking/py-hv-networks and the `j1708dump.py` command of https://github.com/TruckHacking/plc4trucksduck, e.g. you can dump PLC traffic with `j1708dump.py --interface=plc` while running the flow graphs in `/examples`.

## Receive Method 1: Correlation with CW
* Correlates J2497 signal with a reference signal
* Works best with 203 kHz as the reference (the frequency in the chirp at the phase transition)
* Ignores the ASK preamble
* Works better than phase-angle measurements in moderate to high noise environments
* Adjust the threshold values to properly tag the start and end of the message body

![method1](/examples/images/method1.png)

![method1_correlation](/examples/images/method1_correlation.png)

## Receive Method 2: Correlation with Chirp
* Correlates J2497 signal with a complete chirp reference signal to detect burst start and stop
* Correlates with 203 kHz snippet to decode 0's and 1's in the body PSK
* Ignores the ASK preamble
* Works good in medium levels of noise

![method2](/examples/images/method2.png)

![method2_correlation](/examples/images/method2_correlation.png)

## Receive Method 3: Instantaneous Frequency
* Uses Quadrature Demod block and measures the phase-angle of the signal
* Keys in on phase discontinuities between chirps to decode the body PSK
* Ignores the ASK preamble
* Adjust the threshold values to properly tag the start and end of the message body
* Adjust the IF peak threshold and the offset for the first bit transition location

![method3](/examples/images/method3.png)

![method3_if](/examples/images/method3_if.png)

## Transmit Method 1: HackRF Direct
* Transmits a J2497 message directly at 100-400 kHz for a HackRF
* The J2497 Generator block has parameters for the MID field, Data field, and transmit interval
* The bits, MID, Data, and Checksum are printed for each transmitted message

![j2497_mod_hackrfdirect](/examples/images/j2497_mod_hackrfdirect.png)

![mod_output](/examples/images/mod_output.png)

## Transmit Method 2: fl2k Direct
* Transmits a J2497 message directly at 100-400 kHz for the fl2k
* Run `fl2k_tcp -a 0.0.0.0 -s 7777777 -p 31337 -b 8` from a terminal to feed data to the fl2k

![j2497_mod_fl2k](/examples/images/j2497_mod_fl2k.png)

## Transmit Method 3: SDR with Downconverter
* Transmits a J2497 message at an intermediate frequency (125 MHz) to feed into a downconverter to produce the 100-400 kHz signals
* For SDRs such as the HackRF, LimeSDR, USRP, BladeRF, etc.
* The final output power may be limited by the downconverter specifications

![j2497_mod](/examples/images/j2497_mod.png)

# License

MIT License

Copyright (c) 2019, 2020 Assured Information Security, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

