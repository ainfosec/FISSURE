# gr-tpms

Software for capturing, demodulating, decoding, and assessing data from
automotive tire pressure monitors using GNU Radio.

Tire pressure monitoring systems (TPMS) are becoming common on automobiles,
and in certain countries, are required as a condition of sale. Most TPMS
devices use simple wireless communication techniques such as:

* ASK or FSK modulation
* Manchester bit coding
* Small CRCs or checksums
* Unique device identifiers

# Background

For more background on this project, please watch Jared Boone's talk from ToorCon 15:

"Dude, Where's My Car?: Reversing Tire Pressure Monitors with a Software Defined Radio" [[video](http://www.youtube.com/watch?v=bKqiq2Y43Wg)] [[slides](http://sharebrained.com/downloads/toorcon/dude_wheres_my_car_toorcon_sd_2013.pdf)]

...or this interview with Darren Kitchen of Hak5:

"Hak5 1511 – Tracking Cars Wirelessly And Intercepting Femtocell Traffic" [[video](http://hak5.org/episodes/hak5-1511)]

# Software

Someone has contributed [a Docker container](https://registry.hub.docker.com/u/nobis99/gr-tpms/) as a quick way to bring up gr-tpms on your computer.

This software was developed for and tested with:

* [Python](http://python.org) 2.7
* [FFTW](http://www.fftw.org) Fastest FFT in the West.
* [GNU Radio](http://gnuradio.org) 3.7.3 (should work with earlier 3.7 releasese)
* [rtl-sdr](http://sdr.osmocom.org/trac/wiki/rtl-sdr)
* [gr-osmosdr](http://sdr.osmocom.org/trac/wiki/GrOsmoSDR)
* [crcmod](http://crcmod.sourceforge.net), CRC library for Python.

Optional dependencies (for tpms_burst_ping):

* [Watchdog](http://packages.python.org/watchdog/) 0.6.0. Filesystem monitoring library for Python.
* [portaudio](http://www.portaudio.com/) v19. Audio I/O abstraction library.
* [pyaudio](http://people.csail.mit.edu/hubert/pyaudio/) 0.2.7. Python wrapper for portaudio.
* [numpy](http://www.numpy.org) 1.8.0. Numerical Python library.

# Hardware

I used a variety of hardware for receiving tire pressure monitors. If you don't already
have a software-defined radio receiver, a $50 US investment is all you need to get started.

### Quick Shopping List for The Impatient

Aside from a modern and fairly fast computer capable of running GNU Radio, here's what you'll need:

* [NooElec TV28T v2 DVB-T USB Stick (R820T) w/ Antenna and Remote Control](http://www.nooelec.com/store/software-defined-radio/tv28tv2.html) or [Hacker Warehouse DVB-T USB 2.0](http://hackerwarehouse.com/product/dvb-t-usb2-0/)
* [NooElec Male MCX to Female SMA Adapter](http://www.nooelec.com/store/software-defined-radio/male-mcx-to-female-sma-adapter.html)
* [Linx Technologies ANT-315-CW-RH-SMA 315MHz 51mm (2") helical whip antenna, SMA](http://mouser.com/Search/Refine.aspx?Keyword=ANT-315-CW-RH-SMA) or [Linx Technologies ANT-433-CW-RH-SMA 433MHz 51mm (2") helical whip antenna, SMA](http://mouser.com/Search/Refine.aspx?Keyword=ANT-433-CW-RH-SMA)
* [Johnson / Emerson Connectivity Solutions 415-0031-024 SMA male to SMA female cable, 61cm (24")](http://mouser.com/Search/Refine.aspx?Keyword=415-0031-024), (Optional, if you don't want your antenna sticking straight out of your USB receiver dongle.)

### Receiver

If you're just getting started with SDR, I highly recommend getting a DVB-T USB dongle,
supported by the [rtl-sdr](http://sdr.osmocom.org/trac/wiki/rtl-sdr) project. They cost
$25 US, typically.

Recommended DVB-T dongle vendors include:

* [Hacker Warehouse](http://hackerwarehouse.com/product/dvb-t-usb2-0/)
* [NooElec](http://www.nooelec.com/store/software-defined-radio.html)

If you're looking to do active attacks on TPMS (a topic I haven't explored), I recommend
the [HackRF](https://github.com/mossmann/hackrf/).

### Antenna

The antenna that comes with your DVB-T dongle will work well, but you'll get more signal
and less noise with a band-specific antenna.

For 315MHz:
* Linx Technologies [ANT-315-CW-RH-SMA](http://mouser.com/Search/Refine.aspx?Keyword=ANT-315-CW-RH-SMA) 315MHz 51mm (2") helical whip antenna, SMA.
* Linx Technologies [ANT-315-CW-RH](http://mouser.com/Search/Refine.aspx?Keyword=ANT-315-CW-RH) 315MHz 51mm (2") helical whip antenna, RP-SMA.
* Linx Technologies [ANT-315-CW-HWR-SMA](http://mouser.com/Search/Refine.aspx?Keyword=ANT-315-CW-HWR-SMA) 315MHz 142mm (5.6") tilt/swivel whip antenna, SMA.
* Linx Technologies [ANT-315-CW-HWR-RPS](http://mouser.com/Search/Refine.aspx?Keyword=ANT-315-CW-HWR-RPS) 315MHz 142mm (5.6") tilt/swivel whip antenna, RP-SMA.

For 433MHz:
* Linx Technologies [ANT-433-CW-RH-SMA](http://mouser.com/Search/Refine.aspx?Keyword=ANT-433-CW-RH-SMA) 433MHz 51mm (2") helical whip antenna, SMA.
* Linx Technologies [ANT-433-CW-RH](http://mouser.com/Search/Refine.aspx?Keyword=ANT-433-CW-RH) 433MHz 51mm (2") helical whip antenna, RP-SMA.
* Linx Technologies [ANT-433-CW-HWR-SMA](http://mouser.com/Search/Refine.aspx?Keyword=ANT-433-CW-HWR-SMA) 433MHz 142mm (5.6") tilt/swivel whip antenna, SMA.
* Linx Technologies [ANT-433-CW-HWR-RPS](http://mouser.com/Search/Refine.aspx?Keyword=ANT-433-CW-HWR-RPS) 433MHz 142mm (5.6") tilt/swivel whip antenna, RP-SMA.

I'm using the Linx Technologies ANT-315-CW-RH-SMA and ANT-433-CW-RH-SMA with good
results, but you may prefer bigger antennas, or RP-SMA connectors.

Ideally, I'd build a [Yagi-Uda antenna](http://en.wikipedia.org/wiki/Yagi-Uda_antenna). :-)

### Cabling

You'll need a cable to connect the antenna to the DVB-T dongle. The DVB-T dongles
from Hacker Warehouse and NooElec have a female MCX connector. The SMA antennas I
use have a male SMA connector. So you'll want a 50 Ohm cable with a male MCX
connector on one side, and a female SMA connector on the other.

### Filtering

I like to use a SAW filter between the antenna and receiver to further cut noise
and interference. It's certainly not necessary (and likely overkill). The SAW
filter I use is built from a PCB I designed.

# Building

Assuming you have the above prerequisites installed, clone this repo and do the
following:

    cd gr-tpms
    mkdir build
    cd build
    cmake ..
    make
    sudo make install
    sudo ldconfig   # only if you're using Linux

If you have trouble building or running gr-tpms, check that you have all the
dependencies installed. Also, review your CMake configuration by running
"ccmake .." instead of "cmake .." and reviewing the "advanced mode" options.
For example, using MacPorts on Mac OS X 10.9, I've had to adjust
PYTHON_INCLUDE_DIR and PYTHON_LIBRARY to start with "/opt/local" instead of the
detected path.

If you're using Linux, and run into a SWIG exception thrown by Python,
metioning _tpms_swig, swig_import_helper, load_module, etc., you may have
missed running ldconfig.

# Using

Once gr-tpms is installed, you may use it in two modes, a live capture mode, or
decoding from a file. To run live using an RTL-SDR dongle as a signal source:

    tpms_rx --source rtlsdr --if-rate 400000 --tuned-frequency 315000000

Or using a HackRF:

    tpms_rx --source hackrf --if-rate 400000 --tuned-frequency 315000000

To detect and decode from a file:

    tpms_rx --if-rate 400000 --file <filename of complex<float32> file sampled at 400kHz>

Optional arguments to tpms_rx include:

    --bursts: Output a complex<float32> file of each burst of significant energy.
    --raw: Output undecoded bits of detected packets.

While gr-tpms is running, you should see a line printed for each TPMS transmission
that gr-tpms can successfully detect, demodulate, and decode. There are several
modulation and encoding schemes that gr-tpms can handle, but certainly many
remain to be observed and reversed. The burst option is handy for capturing raw
baseband data for packets that gr-tpms doesn't recognize.

The output of gr-tpms is the recovered contents (bits) of the received packets.
At the moment, you're on your own as far as figuring out which bits represent a
sensor's unique identifier, tire pressure or temperature, and checksum or CRC field.
As you accumulate more raw packets, you can observe statistics which indicate
the nature of bits in the many different types of packets. For more information on
how this is done, see my ToorCon talk (linked above) and check out my sister
project, [tpms](https://github.com/jboone/tpms), which contains some visualization
and testing tools and techniques.

If you want to drive around, listening for TPMS signals, I recommend using the
optional tpms_burst_ping utility. It takes a single, optional argument that 
specifies a directory to watch for --burst files to appear. When a file appears
(a burst occurs), tpms_burst_ping will emit a "ping" through your audio output.

    tpms_burst_ping .

# License

The associated software is provided under a GPLv2 license:

Copyright (C) 2014 Jared Boone, ShareBrained Technology, Inc.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301, USA.

# Contact

Jared Boone <jared@sharebrained.com>

ShareBrained Technology, Inc.

<http://www.sharebrained.com/>


The latest version of this repository can be found at
https://github.com/jboone/gr-tpms
