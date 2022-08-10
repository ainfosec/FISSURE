title: gr-ieee802-15-4
author:
  - Bastian Bloessl <bloessl@ccs-labs.org>
  - Felix Wunsch <wunsch.felix@googlemail.com>
copyright_owner:
  - Bastian Bloessl
  - Felix Wunsch
  - Free Software Foundation
repo: https://github.com/bastibl/gr-ieee802-15-4.git
tags:
  - IEEE 802.15.4
  - ZigBee
  - IoT
website: http://www.ccs-labs.org/software/gr-ieee802-15-4/
brief: An IEEE 802.15.4 (ZigBee) Transceiver
icon: http://www.ccs-labs.org/software/gr-ieee802-15-4/gr-15-4-logo.png
---
This is an IEEE802.15.4 transceiver for GNU Radio v3.7. It is based on the UCLA implementation (https://cgran.org/wiki/UCLAZigBee) of Thomas Schmid.

Currently, it features the following:

- The O-QPSK PHY encapsulated in a hierarchical block.
- The CSS PHY, also encapsulated in a hierarchical block (Limitation: Packets need to have a fixed length). 
- A block that implements the Rime communication stack. Rime is a lightweight communication stack designed for Wireless Sensor Networks and is part of the Contiki Operating System.
- A transceiver flow graph with USRP <-> PHY <-> MAC <-> Network layer (Rime) <-> UDP Socket / APP which resembles pretty well the ISO/OSI structure.
- A sample application which visualizes sensor values. The application shows how easy it is to connect an external program to the flow graph by using Socket PDU blocks.
- An IEEE 802.15.4 and Rime dissector for Wireshark.

Some interesting stuff:

- Packets can be piped to Wireshark.
- The complete physical modulation is done with plain GNU Radio blocks.
- It is interoperable with TelosB sensor motes.
- It is interoperable with Contiki.
- It uses a block to tag packet bursts with tx_sob and tx_eob tags. This tags are understood by the UHD blocks and allow fast switching between transmission and reception.
