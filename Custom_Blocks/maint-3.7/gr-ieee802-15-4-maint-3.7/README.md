Hi!

This is an IEEE802.15.4 O-QPSK transceiver for GNU Radio, based on Thomas
Schmid's implementation.

### Development

Like GNU Radio, this module uses *master* and *maint* branches for development.
These branches are supposed to be used with the corresponding GNU Radio
branches. This means: the *maint-3.7* branch is compatible with GNU Radio 3.7,
*maint-3.8* is compatible with GNU Radio 3.8, and *master* is compatible with
GNU Radio master, which tracks the development towards GNU Radio 3.9.


## Features

- The O-QPSK PHY encapsulated in a hierarchical block.
- The CSS PHY, also encapsulated in a hierarchical block (Limitation: Packets
  need to have a fixed length).
- A block that implements the Rime communication stack. Rime is a lightweight
  communication stack designed for Wireless Sensor Networks and is part of the
  Contiki Operating System.
- A transceiver flow graph with USRP <-> PHY <-> MAC <-> Network layer (Rime)
  <-> UDP Socket / APP which resembles pretty well the ISO/OSI structure.
- A sample application which visualizes sensor values. The application shows how
  easy it is to connect an external program to the flow graph by using Socket
  PDU blocks.
- An IEEE 802.15.4 and Rime dissector for Wireshark.

Some interesting properties:
- Packets can be piped to Wireshark.
- The complete physical modulation is done with plain GNU Radio blocks.
- It is interoperable with TelosB sensor motes.
- It is interoperable with Contiki.
- It uses a block to tag packet bursts with `tx_sob` and `tx_eob` tags. This
  tags are understood by the UHD blocks and allow fast switching between
  transmission and reception.

You can find the firmware that I used to test interoperability with TelosB motes
in the contiki folder. The firmware is based on Contiki v2.6. There is another
README file in the Contiki folder that describes how to compile and use the
firmware.


## Dependencies

- GNU Radio

- gr-foo (Wireshark Connector, Packet Pad and Burst Tagger blocks) <br>
  https://github.com/bastibl/gr-foo.git

- python-matplotlib (if you want to run the GUI sample application) <br>
  `sudo apt-get install python-matplotlib`


## Installation

Please see [www.wime-project.net](https://www.wime-project.net/installation/)
for installation instructions.

## Usage

Open the `examples/transceiver_*.grc` flow graph with gnuradio-companion and
check if all blocks are connected. Enable either the UHD blocks to interface
with real hardware or the Packet Pad block to loop back the samples. Open some
Rime connections and connect messages sources or Socket PDUs. You can easily
connect to the Socket PDU blocks with netcat. Netcat can be started for example
with

```
nc -u localhost 52001
```

There are also startup scripts in the apps folder.

Have fun!

