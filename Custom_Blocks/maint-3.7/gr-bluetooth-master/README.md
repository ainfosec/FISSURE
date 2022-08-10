GR-Bluetooth
============
Welcome to gr-bluetooth!

gr-bluetooth is an implementation of the Bluetooth baseband layer for GNU Radio
for experimentation and teaching students about Software Defined Radio, it
should not be used for Bluetooth communications as it is not a complete
software stack.

The gr-bluetooth web site is: http://gr-bluetooth.sourceforge.net

Building
--------
gr-bluetooth currently requires gnuradio 3.7.0 or later.

To build gr-bluetooth:
```
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
```

License
-------
Copyright 2008 - 2013 Dominic Spill, Michael Ossmann

This file is part of gr-bluetooth

gr-bluetooth is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

gr-bluetooth is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with gr-bluetooth; see the file COPYING.  If not, write to
the Free Software Foundation, Inc., 51 Franklin Street,
Boston, MA 02110-1301, USA.
