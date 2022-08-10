title: gr-ieee802-11
author:
  - Bastian Bloessl <bloessl@ccs-labs.org>
copyright_owner:
  - Bastian Bloessl
dependencies:
  - gnuradio (>= 3.7.4)
repo: https://github.com/bastibl/gr-ieee802-11.git
tags:
  - IEEE 802.11
  - WiFi
  - OFDM
website: http://www.ccs-labs.org/projects/wime/
brief: IEEE 802.11 a/g/p Transceiver
icon: http://www.ccs-labs.org/projects/wime/wime.png
---
This an IEEE 802.11 a/g/p transceiver for GNU Radio v3.7. Over the air, I tested it with the Ettus USRP N210 with XCVR2450 and CBX daughterboards. For interoperability tests I use mainly an Atheros (ath5k) WiFi card. The code can also be used for packet error rate simulations.
