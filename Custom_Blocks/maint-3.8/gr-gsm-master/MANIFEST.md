title: gr-gsm
brief: A GSM receiver
tags:
  - GSM
author:
  - Piotr Krysik
copyright_owner:
  - Piotr Krysik
  - Roman Khassraf
  - Vadim Yanitskiy
  - Pieter Robyns
dependencies:
  - gnuradio
  - gr-osmosdr
  - scipy
  - liblog4cpp
  - libosmocore
repo: https://github.com/ptrkrysik/gr-gsm.git
stable_release: HEAD
icon:
---

The gr-gsm project is based on the gsm-receiver written by Piotr Krysik (also the main author of gr-gsm) for the Airprobe project.

The aim is to provide set of tools for receiving information transmitted by GSM equipment/devices.

Please see project's wiki https://github.com/ptrkrysik/gr-gsm/wiki for information on installation and usage of gr-gsm.

Short presentation of Airprobe'like application of gr-gsm: https://www.youtube.com/watch?v=Eofnb7zr8QE

Credits:

Piotr Krysik <ptrkrysik (at) gmail.com> - main author and project maintainer

Roman Khassraf <rkhassraf (at) gmail.com> - blocks for demultiplexing and decoding of voice channels, decryption block supporting all ciphers used in GSM, blocks for storing and reading GSM bursts, project planning and user support

Pieter Robyns <pieter.robyns (at) uhasselt.be> - block reversing channel hopping

Thanks:

This work is built upon the efforts made by many people to gather knowledge of GSM.

First very significant effort of public research into GSM and its security vulnerabilities was The Hacker's Choice GSM SCANNER PROJECT. One of the results of this project was creation of a software GSM receiver by Tvoid - gsm-tvoid - which was was the most important predecessor of gr-gsm and of gsm-receiver from the Airprobe project.

Gr-gsm wouldn't be also possible without help and inspiration by Harald Welte, Dieter Spaar and Sylvain Munaut.

Special thanks to Pawel Koszut who generously lent his USRP1 to the author of gr-gsm (Piotr Krysik) in 2007-2010.
