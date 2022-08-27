title: gr-nrsc5
brief: A GNU Radio implementation of HD Radio (NRSC-5)
tags:
  - HD Radio
  - NRSC-5
author:
  - Clayton Smith <argilo@gmail.com>
copyright_owner:
  - Clayton Smith <argilo@gmail.com>
dependencies:
  - gnuradio (>= 3.7.0)
license: GPLv3
repo: https://github.com/argilo/gr-nrsc5.git
gr_supported_version: v3.7, v3.8, v3.9
stable_release: HEAD
---
The goal of this project is to implement an HD Radio receiver and transmitter
in GNU Radio. HD Radio is standardized in NRSC-5. The latest version of the
standard is NRSC-5-D, which can be found at
https://www.nrscstandards.org/standards-and-guidelines/documents/standards/nrsc-5-d/nrsc-5-d.asp.

So far only a transmitter has been implemented. A stand-alone receiver for
RTL-SDR is available here: https://github.com/theori-io/nrsc5/
