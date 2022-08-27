=============
grgsm_livemon
=============

-------------------------------------------------------
GSM C0 monitor forwarding packages to network interface
-------------------------------------------------------

:Author: Piotr Krysik - ptrkrysik@gmail.com
:Date:   2017-08-21
:Copyright: public domain
:Version: 0.0
:Manual section: 1
:Manual group: User Commands

SYNOPSIS
========

grgsm_livemon [options]

DESCRIPTION
===========

Interactive monitor of a single C0 channel with analysis performed by
Wireshark.  Example command to run wireshark:

  sudo wireshark -k -f udp -Y gsmtap -i lo


OPTIONS
=======

-h, --help
  show this help message and exit

--args=ARGS
  Set Device Arguments [default=]

-g GAIN, --gain=GAIN
  Set gain [default=30]

--osr=OSR
  Set OverSampling Ratio [default=4]

-p PPM, --ppm=PPM
  Set ppm [default=0]

-s SAMP_RATE, --samp-rate=SAMP_RATE
  Set samp_rate [default=2M]

-o SHIFTOFF, --shiftoff=SHIFTOFF
  Set Frequency Shiftoff [default=400k]

-f FC, --fc=FC
  Set GSM channel's central frequency [default=941.8M]

SEE ALSO
========

* `<https://github.com/ptrkrysik/gr-gsm/>`__
* ``grgsm_scanner(1)``
