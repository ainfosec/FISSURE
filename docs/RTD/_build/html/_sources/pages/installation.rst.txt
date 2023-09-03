============
Installation
============

The FISSURE installer is helpful for staging computers or installing select software programs of interest. The code can be quickly modified to allow for custom software installs. The size estimates for the programs are before and after readings from a full install. The sizes for each program are not exact as some dependencies are installed in previously checked items. The sizes may also change over time as programs get updated.


Requirements
============

It is recommended to install FISSURE on a clean operating system to avoid conflicts with existing software. The items listed under the "Minimum Install" category are what is required to launch the FISSURE Dashboard without errors. Select all the recommended checkboxes (Default button) to avoid additonal errors while operating the various tools within FISSURE. There will be multiple prompts throughout the installation, mostly asking for elevated permissions and user names. 


Cloning
=======

.. code-block:: console

   $ git clone https://github.com/ainfosec/FISSURE.git
   $ cd FISSURE
   $ git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
   $ git submodule update --init
   $ ./install

This will install PyQt software dependencies required to launch the installation GUIs if they are not found. The git submodule command will download all missing GNU Radio out-of-tree modules from their repositories.


Installer
=========

Next, select the option that best matches your operating system (should be detected automatically if your OS matches an option). The "Minimum Install" option is a list of programs needed to launch the FISSURE Dashboard without any errors. The remaining programs are needed to utilize the various hardware and software tools integrated into FISSURE menu items and tabs.


Uninstalling
============

There is no uninstaller for FISSURE. Exercise caution when installing several GB of new software for all the installer checkboxes. There are only a few places where FISSURE writes to the system outside of apt-get, make, or pip commands. A future uninstaller could get rid of those changes. 

The following are locations that are impacted by the FISSURE installer:

- a couple PPAs for getting the latest/specific versions of software
- writes to ``~/.local/bin`` and ``~/.bashrc`` (or equivalent) for issuing the fissure command and displaying the icon
- GNU Radio paths added to ``~/.bashrc`` (or equivalent)
- GNU Radio ``~/.gnuradio/config.conf`` file for detecting FISSURE OOT modules
- ``/etc/udev`` rules for detecting hardware
- UHD images from ``uhd_images_downloader`` command, ``sysctl`` changes to ``net.core.wmem_max``
- Optional Wireshark user groups to use it without sudo
- ESP32 Bluetooth Classic Sniffer and FISSURE Sniffer wireshark plugins

Many programs are stored in the ~/Installed_by_FISSURE folder but the dependencies are heavily intertwined amongst the programs.


Usage
=====

Open a terminal and enter: ``fissure``

The intended method for launching FISSURE is through the terminal without sudo. The terminal provides important status and feedback for some operations. Refer to the FISSURE documentation for more details.

Known Conflicts
===============

The following are a list of known software conflicts and incompatibilities within FISSURE:

- Ubuntu 18.04
   - aircrack 8812au driver crashes computer on reboot, other drivers are dependent on kernel version
   - Python2 branch avoids installation of programs that depend on PyQt5.
- Ubuntu 20.04
   - Geany in 20.04 needs `[styling] line_height=0;2;` added to Tools>Configuration Files>filetypes.common to see underscores
- Ubuntu 22.04
   - Gpick does not work on Wayland, using wl-color-picker as a substitute
- Other
   - gr-gsm has to be installed twice for all blocks to be recognized
   - UBX daughterboards require specific UHD versions
   - Don't name the TSI component "tsi.py", it messes with importing gr-TSI blocks
   - ZMQ header adds something similar to 0x0007020004 to TCP data in PUB sink (flags/payload_length/command_length/command). A `sub_listener.setsockopt_string(zmq.SUBSCRIBE,u'')` would need to drop the three bytes for the command length and command.
   - The default variable values for flow graphs with GUIs cannot be changed with `loadedmod = __import__(flow_graph_filename)`. This means serial or IP address variables must be accessed with parameter blocks and flow graphs called by the python command (mostly for inspection flow graphs).


Third-Party Software
====================

The following is a table of the major software tools that have been proven to work for each supported operating system.

.. list-table:: 
   :widths: 50 25 25 25
   :header-rows: 1

   * - Software
     - Ubuntu 18.04.6
     - Ubuntu 20.04.4
     - Ubuntu 22.04.1
   * - Aircrack-ng
     - ✅
     - ✅
     - ✅
   * - airgeddon
     - ✅
     - ✅
     - ✅
   * - Anki
     - ✅
     - ✅
     - ✅
   * - Arduino IDE
     - ✅
     - ✅
     - ✅
   * - baudline
     - ✅
     - ✅
     - ✅
   * - Bless
     - ✅
     - ✅
     - ✅
   * - btscanner
     - ✅
     - ✅
     - ✅
   * - CRC RevEng
     - ✅
     - ✅
     - ✅
   * - CyberChef
     - ✅
     - ✅
     - ✅
   * - Dire Wolf
     - ✅
     - ✅
     - ✅
   * - Dump1090
     - ✅
     - ✅
     - ✅
   * - Enscribe
     - ✅
     - ✅
     - ✅
   * - ESP32 Bluetooth Classic Sniffer
     - ✅
     - ✅
     - ✅
   * - ESP8266 Deauther v2
     - ✅
     - ✅
     - ✅
   * - FALCON
     - ✅
     - ✅
     - ❓
   * - fl2k
     - ✅
     - ✅
     - ✅
   * - Fldigi
     - ✅
     - ✅
     - ✅
   * - FoxtrotGPS
     - ✅
     - ✅
     - ✅
   * - Geany
     - ✅
     - ✅
     - ✅
   * - GNU Radio
     - ✅
     - ✅
     - ✅
   * - Google Earth Pro
     - ✅
     - ✅
     - ✅
   * - Gpredict
     - ✅
     - ✅
     - ✅
   * - Gpick
     - ✅
     - ✅
     - ❌
   * - GQRX
     - ✅
     - ✅
     - ✅
   * - gr-acars
     - ✅
     - ✅
     - ✅
   * - gr-adsb
     - ✅
     - ❓
     - ❓
   * - gr-ainfosec
     - ✅
     - ✅
     - ✅
   * - gr-air-modes
     - ✅
     - ✅
     - ✅
   * - gr-ais
     - ✅
     - ✅
     - ✅
   * - gr-bluetooth
     - ✅
     - ✅
     - ❓
   * - gr-clapper_plus
     - ✅
     - ✅
     - ✅
   * - gr-dect2
     - ✅
     - ✅
     - ✅
   * - gr-foo
     - ✅
     - ✅
     - ✅
   * - gr-fuzzer
     - ✅
     - ✅
     - ✅
   * - gr-garage_door
     - ✅
     - ✅
     - ✅
   * - gr-gsm
     - ✅
     - ✅
     - ✅
   * - gr-ieee802-11
     - ✅
     - ✅
     - ✅
   * - gr-ieee802-15-4
     - ✅
     - ✅
     - ✅
   * - gr-iio
     - ✅
     - ✅
     - ❌
   * - gr-iridium
     - ✅
     - ✅
     - ✅
   * - gr-j2497
     - ✅
     - ✅
     - ✅
   * - gr-limesdr
     - ✅
     - ✅
     - ✅
   * - gr-mixalot
     - ✅
     - ✅
     - ✅
   * - gr-nrsc5
     - ✅
     - ✅
     - ✅
   * - gr-paint
     - ✅
     - ✅
     - ✅
   * - gr-rds
     - ✅
     - ✅
     - ✅
   * - gr-tpms
     - ✅
     - ❌
     - ❌
   * - gr-tpms_poore
     - ✅
     - ✅
     - ✅
   * - gr-X10
     - ✅
     - ✅
     - ✅
   * - gr-Zwave
     - ✅
     - ❌
     - ❌
   * - gr-zwave_poore
     - ✅
     - ✅
     - ✅
   * - GraphicsMagick
     - ✅
     - ✅
     - ✅
   * - Grip
     - ✅
     - ✅
     - ✅
   * - HackRF
     - ✅
     - ✅
     - ✅
   * - ham2mon
     - ✅
     - ❌
     - ❌
   * - HamClock
     - ✅
     - ✅
     - ✅
   * - hcidump
     - ✅
     - ✅
     - ✅
   * - htop
     - ✅
     - ✅
     - ✅
   * - Hydra
     - ✅
     - ✅
     - ✅
   * - ICE9 Bluetooth Sniffer
     - ✅
     - ✅
     - ✅
   * - IIO Oscilloscope
     - ✅
     - ✅
     - ❌
   * - IMSI-Catcher 4G
     - ✅
     - ✅
     - ✅
   * - Inspectrum
     - ✅
     - ✅
     - ✅
   * - IridiumLive
     - ✅
     - ✅
     - ✅
   * - iridium-toolkit
     - ✅
     - ✅
     - ✅
   * - Kalibrate
     - ✅
     - ✅
     - ✅
   * - Kismet
     - ✅
     - ✅
     - ✅
   * - libbtbb
     - ✅
     - ✅
     - ✅
   * - LTE-Cell-Scanner
     - ✅
     - ✅
     - ✅
   * - LTE-ciphercheck
     - ✅
     - ✅
     - ❌
   * - m17-cxx-demod
     - ❌
     - ✅
     - ✅
   * - Meld
     - ✅
     - ✅
     - ✅
   * - Metasploit
     - ✅
     - ✅
     - ✅
   * - minicom
     - ✅
     - ✅
     - ✅
   * - minimodem
     - ✅
     - ✅
     - ✅
   * - mkusb/dus/guidus
     - ✅
     - ✅
     - ✅
   * - monitor_rtl433
     - ✅
     - ✅
     - ✅
   * - multimon-ng
     - ✅
     - ✅
     - ✅
   * - NETATTACK2
     - ✅
     - ✅
     - ✅
   * - nrsc5
     - ✅
     - ✅
     - ✅
   * - OpenBTS
     - ✅
     - ❌
     - ❌
   * - openCPN
     - ✅
     - ✅
     - ✅
   * - openHAB
     - ✅
     - ✅
     - ❓
   * - openWebRX
     - ❌
     - ✅
     - ✅
   * - Proxmark3
     - ✅
     - ✅
     - ✅
   * - PuTTY
     - ✅
     - ✅
     - ✅
   * - pyFDA
     - ❌
     - ✅
     - ✅
   * - PyGPSClient
     - ✅
     - ✅
     - ✅
   * - QSpectrumAnalyzer
     - ✅
     - ✅
     - ✅
   * - QSSTV
     - ✅
     - ✅
     - ✅
   * - QtDesigner
     - ✅
     - ✅
     - ✅
   * - radiosonde_auto_rx
     - ✅
     - ✅
     - ✅
   * - rehex
     - ✅
     - ✅
     - ✅
   * - retrogram-rtlsdr
     - ✅
     - ✅
     - ✅
   * - RouterSploit
     - ✅
     - ✅
     - ✅
   * - rtl_433
     - ✅
     - ✅
     - ✅
   * - rtl8812au Driver
     - ✅
     - ✅
     - ✅
   * - RTLSDR-Airband
     - ✅
     - ✅
     - ✅
   * - rtl-zwave
     - ✅
     - ✅
     - ✅
   * - scan-ssid
     - ✅
     - ✅
     - ✅
   * - Scapy
     - ✅
     - ✅
     - ✅
   * - SdrGlut
     - ✅
     - ✅
     - ✅
   * - SDRTrunk
     - ✅
     - ✅
     - ✅
   * - SigDigger
     - ❌
     - ✅
     - ✅
   * - Spectrum Painter
     - ✅
     - ✅
     - ✅
   * - Spektrum
     - ✅
     - ✅
     - ✅
   * - srsRAN/srsLTE
     - ✅
     - ✅
     - ✅
   * - systemback
     - ✅
     - ✅
     - ✅
   * - trackerjacker
     - ✅
     - ✅
     - ✅
   * - UDP Replay
     - ✅
     - ✅
     - ✅
   * - Universal Radio Hacker
     - ✅
     - ✅
     - ✅
   * - V2Verifier
     - ✅
     - ✅
     - ✅
   * - Viking
     - ✅
     - ✅
     - ✅
   * - WaveDrom
     - ✅
     - ✅
     - ✅
   * - Waving-Z
     - ✅
     - ✅
     - ✅
   * - Wifite
     - ✅
     - ✅
     - ✅
   * - Wireshark
     - ✅
     - ✅
     - ✅
   * - wl-color-picker
     - ❓
     - ❓
     - ✅
   * - WSJT-X
     - ✅
     - ✅
     - ✅
   * - Xastir
     - ✅
     - ✅
     - ✅
   * - ZEPASSD
     - ✅
     - ✅
     - ✅
   * - Zigbee Sniffer
     - ✅
     - ✅
     - ✅


Third-Party Software Versions
=============================

The following are the software versions that are included with the FISSURE installer for the most recent major version of each supported operating system. This list will be updated periodically.

- :ref:`Ubuntu 18.04.6`
- :ref:`Ubuntu 20.04.4`
- :ref:`Ubuntu 22.04.1`

Ubuntu 18.04.6
--------------

.. list-table:: 
   :widths: 50 10 5 25
   :header-rows: 1

   * - Software
     - Version
     - From Source
     - Links/Author
   * - Aircrack-ng
     - 1.2 rc4
     - No
     - http://www.aircrack-ng.org/
   * - Arduino IDE
     - 1.8.15
     - No
     - https://www.arduino.cc/en/software
   * - airgeddon
     - v11.01
     - Yes
     - https://github.com/v1s1t0r1sh3r3/airgeddon
   * - Anki
     - 2.1.0beta36
     - No
     - https://apps.ankiweb.net/
   * - baudline
     - version 1.08
     - No
     - https://www.baudline.com/
   * - Bless
     - 0.6.0
     - No
     - https://github.com/afrantzis/bless
   * - btscanner
     - 2.1-6
     - No
     - https://salsa.debian.org/pkg-security-team/btscanner
   * - CRC RevEng
     - 3.0.5
     - Yes
     - https://reveng.sourceforge.io/
   * - CyberChef
     - \-
     - Yes
     - https://gchq.github.io/CyberChef/
   * - Dire Wolf
     - dev
     - Yes
     - https://github.com/wb2osz/direwolf
   * - Dump1090
     - 1.10.3010.14
     - Yes
     - https://github.com/antirez/dump1090
   * - dump978
     - latest
     - Yes
     - https://github.com/mutability/dump978
   * - Enscribe
     - 0.1.0
     - No
     - Jason Downer
   * - ESP32 Bluetooth Classic Sniffer
     - master
     - Yes
     - https://github.com/Matheus-Garbelini/esp32_bluetooth_classic_sniffer
   * - ESP8266 Deauther v2
     - v2
     - Yes
     - https://github.com/SpacehuhnTech/esp8266_deauther
   * - FALCON
     - \-
     - Yes
     - https://github.com/falkenber9/falcon
   * - fl2k
     - \-
     - Yes
     - https://osmocom.org/projects/osmo-fl2k/wiki
   * - Fldigi
     - 4.0.1
     - No
     - http://www.w1hkj.com/
   * - FoxtrotGPS
     - 1.2.1
     - No
     - https://www.foxtrotgps.org/
   * - Geany
     - 1.32
     - No
     - https://www.geany.org/
   * - GNU Radio
     - 3.7.13.5
     - No
     - https://www.gnuradio.org/
   * - Google Earth Pro
     - latest
     - No
     - https://www.google.com/earth/versions/
   * - Gpick
     - 0.2.5
     - No
     - https://github.com/thezbyg/gpick
   * - Gpredict
     - 2.0-4
     - No
     - http://gpredict.oz9aec.net/
   * - GQRX
     - 2.9
     - No
     - https://gqrx.dk/
   * - gr-acars
     - 3.7.5
     - Yes
     - https://sourceforge.net/projects/gr-acars/
   * - gr-adsb
     - master/wnagele
     - Yes
     - https://github.com/wnagele/gr-adsb
   * - gr-ainfosec
     - maint-3.7
     - Yes
     - https://github.com/ainfosec/fissure
   * - gr-air-modes
     - 0.0.2.c29eb60-2ubuntu1
     - No
     - https://github.com/bistromath/gr-air-modes
   * - gr-ais
     - ?
     - Yes
     - https://github.com/bistromath/gr-ais
   * - gr-bluetooth
     - master
     - Yes
     - https://github.com/greatscottgadgets/gr-bluetooth
   * - gr-clapper_plus
     - maint-3.7
     - Yes
     - https://github.com/cpoore1/gr-clapper_plus
   * - gr-dect2
     - pyqt4
     - Yes
     - https://github.com/pavelyazev/gr-dect2
   * - gr-foo
     - maint-3.7
     - Yes
     - https://github.com/bastibl/gr-foo
   * - gr-fuzzer
     - maint-3.7
     - Yes
     - https://github.com/ainfosec/fissure
   * - gr-garage_door
     - maint-3.7
     - Yes
     - https://github.com/cpoore1/gr-garage_door
   * - gr-gsm
     - development
     - Yes
     - https://github.com/ptrkrysik/gr-gsm
   * - gr-ieee802-11
     - maint-3.7
     - Yes
     - https://github.com/bastibl/gr-ieee802-11
   * - gr-ieee802-15-4
     - maint-3.7
     - Yes
     - https://github.com/bastibl/gr-ieee802-15-4
   * - gr-iio
     - 0.3-myriadrf1~bionic
     - No
     - https://github.com/analogdevicesinc/gr-iio
   * - gr-iridium
     - ?
     - Yes
     - https://github.com/muccc/gr-iridium
   * - gr-j2497
     - maint-3.7
     - Yes
     - https://github.com/ainfosec/gr-j2497
   * - gr-limesdr
     - master
     - Yes
     - https://github.com/myriadrf/gr-limesdr
   * - gr-mixalot
     - maint-3.7
     - Yes
     - https://github.com/unsynchronized/gr-mixalot
   * - gr-nrsc5
     - maint-3.7
     - Yes
     - https://github.com/argilo/gr-nrsc5
   * - gr-paint
     - maint-3.7
     - Yes
     - https://github.com/drmpeg/gr-paint
   * - gr-rds
     - maint-3.7
     - Yes
     - https://github.com/bastibl/gr-rds
   * - gr-tpms
     - master
     - Yes
     - https://github.com/jboone/gr-tpms
   * - gr-tpms_poore
     - maint-3.7
     - Yes
     - https://github.com/cpoore1/gr-tpms_poore
   * - gr-X10
     - maint-3.7
     - Yes
     - https://github.com/cpoore1/gr-X10
   * - gr-Zwave
     - master
     - Yes
     - https://github.com/BastilleResearch/scapy-radio/tree/master/gnuradio/gr-Zwave
   * - gr-zwave_poore
     - maint-3.7
     - Yes
     - https://github.com/cpoore1/gr-zwave_poore
   * - GraphicsMagick
     - 1.3.28-2ubuntu0.1
     - No
     - http://www.graphicsmagick.org/
   * - Grip
     - 4.6.1
     - No
     - https://github.com/joeyespo/grip
   * - HackRF
     - 2022.09.1
     - Yes
     - https://github.com/greatscottgadgets/hackrf/releases
   * - ham2mon
     - master
     - Yes
     - https://github.com/madengr/ham2mon
   * - HamClock
     - latest
     - Yes
     - https://www.clearskyinstitute.com/ham/HamClock/
   * - hcidump
     - 5.48
     - No
     - http://www.bluez.org/
   * - htop
     - 2.1.0
     - No
     - https://github.com/htop-dev/htop
   * - Hydra
     - 8.6
     - No
     - https://github.com/vanhauser-thc/thc-hydra
   * - ICE9 Bluetooth Sniffer
     - master
     - Yes
     - https://github.com/mikeryan/ice9-bluetooth-sniffer
   * - IIO Oscilloscope
     - master
     - Yes
     - https://github.com/analogdevicesinc/iio-oscilloscope
   * - IMSI-Catcher 4G
     - \-
     - Yes
     - Joe Reith, AIS
   * - Inspectrum
     - 0.2-1
     - No
     - https://github.com/miek/inspectrum
   * - IridiumLive
     - 1.2-35021
     - Yes
     - https://github.com/microp11/iridiumlive
   * - iridium-toolkit
     - master
     - Yes
     - https://github.com/muccc/iridium-toolkit
   * - Kalibrate
     - v0.4.1-rtl
     - Yes
     - https://github.com/steve-m/kalibrate-rtl
   * - Kismet
     - Kismet 2016-07-R1
     - No
     - https://www.kismetwireless.net/
   * - libbtbb
     - master
     - Yes
     - https://github.com/greatscottgadgets/libbtbb
   * - LTE-Cell-Scanner
     - master/1.1.0
     - Yes
     - https://github.com/JiaoXianjun/LTE-Cell-Scanner
   * - LTE-ciphercheck
     - rebase_20.04
     - Yes
     - https://github.com/mrlnc/LTE-ciphercheck
   * - Meld
     - 3.18.0
     - No
     - https://meldmerge.org/
   * - Metasploit
     - 6.2.10-dev-
     - Yes
     - https://www.metasploit.com/
   * - minicom
     - 2.7.1
     - No
     - https://salsa.debian.org/minicom-team/minicom
   * - minimodem
     - 0.24
     - No
     - http://www.whence.com/minimodem/
   * - mkusb/dus/guidus
     - 22.1.2
     - No
     - https://help.ubuntu.com/community/mkusb
   * - monitor_rtl433
     - master
     - Yes
     - https://github.com/mcbridejc/monitor_rtl433
   * - multimon-ng
     - master
     - Yes
     - https://github.com/EliasOenal/multimon-ng
   * - NETATTACK2
     - master
     - Yes
     - https://github.com/chrizator/netattack2
   * - nrsc5
     - master
     - Yes
     - https://github.com/theori-io/nrsc5
   * - OpenBTS
     - release 5.0-master+646bb6e79f
     - Yes
     - http://openbts.org/
   * - openCPN
     - 5.6.2
     - No
     - https://opencpn.org/
   * - openHAB
     - 3.1.0
     - No
     - https://www.openhab.org/
   * - Proxmark3
     - master
     - Yes
     - https://github.com/Proxmark/proxmark3
   * - PuTTY
     - Release 0.70
     - No
     - https://www.putty.org/
   * - PyGPSClient
     - 1.3.5
     - No
     - https://github.com/semuconsulting/PyGPSClient
   * - QSpectrumAnalyzer
     - 2.1.0
     - No
     - https://github.com/xmikos/qspectrumanalyzer
   * - QSSTV
     - 9.2.6
     - No
     - https://charlesreid1.com/wiki/Qsstv
   * - QtDesigner
     - 4.8.7
     - No
     - https://doc.qt.io/qt-5/qtdesigner-manual.html
   * - radiosonde_auto_rx
     - master
     - yes
     - https://github.com/projecthorus/radiosonde_auto_rx
   * - rehex
     - master
     - Yes
     - https://github.com/solemnwarning/rehex
   * - retrogram-rtlsdr
     - master
     - Yes
     - https://github.com/r4d10n/retrogram-rtlsdr
   * - RouterSploit
     - master
     - Yes
     - https://www.github.com/threat9/routersploit
   * - rtl_433
     - master
     - Yes
     - https://github.com/merbanan/rtl_433
   * - rtl8812au Driver
     - latest (fix)
     - Yes
     - https://github.com/aircrack-ng/rtl8812au
   * - RTLSDR-Airband
     - master
     - Yes
     - https://github.com/szpajder/RTLSDR-Airband
   * - rtl-zwave
     - master
     - Yes
     - https://github.com/andersesbensen/rtl-zwave
   * - scan-ssid
     - master
     - Yes
     - https://github.com/Resethel/scan-ssid
   * - Scapy
     - | 2.4.5 (Python2)
       | 2.4.5 (Python3)
       | 2.4.0 (scapy command)
     - No
     - https://scapy.net/
   * - SdrGlut
     - master
     - Yes
     - https://github.com/righthalfplane/SdrGlut
   * - SDRTrunk
     - v0.5.0-alpha.6
     - Yes
     - https://github.com/DSheirer/sdrtrunk
   * - Spectrum Painter
     - master
     - Yes
     - https://github.com/polygon/spectrum_painter
   * - Spektrum
     - 2.1.0
     - Yes
     - https://github.com/pavels/spektrum
   * - srsRAN/srsLTE
     - 20.10.1
     - Yes
     - https://www.srslte.com/
   * - systemback
     - 1.8.402~ubuntu16.04.1
     - No
     - https://github.com/BluewhaleRobot/systemback
   * - trackerjacker
     - 1.9.0
     - Yes
     - https://github.com/calebmadrigal/trackerjacker
   * - UDP Replay
     - 1.0.0
     - Yes
     - https://github.com/rigtorp/udpreplay
   * - Universal Radio Hacker
     - 2.9.3
     - No
     - https://github.com/jopohl/urh
   * - V2Verifier
     - 1.1: 9e025e1
     - Yes
     - https://github.com/twardokus/v2verifier
   * - Viking
     - 1.10
     - Yes
     - https://sourceforge.net/projects/viking/
   * - WaveDrom
     - Online Editor
     - \-
     - https://github.com/wavedrom/wavedrom
   * - Waving-Z
     - master
     - Yes
     - https://github.com/baol/waving-z
   * - Wifite
     - master
     - Yes
     - https://github.com/derv82/wifite2
   * - Wireshark
     - 3.6.5
     - No
     - https://www.wireshark.org/
   * - WSJT-X
     - 1.1
     - No
     - https://physics.princeton.edu/pulsar/k1jt/wsjtx.html
   * - Xastir
     - 2.1.0-1
     - No
     - https://github.com/Xastir/Xastir
   * - ZEPASSD
     - master
     - Yes
     - https://github.com/pvachon/zepassd
   * - Zigbee Sniffer
     - 0.1
     - Yes
     - https://github.com/yiek888/opensniffer
     
Ubuntu 20.04.4
--------------

.. |ss| raw:: html

   <strike>

.. |se| raw:: html

   </strike>

.. list-table:: 
   :widths: 50 10 5 25
   :header-rows: 1

   * - Software
     - Version
     - From Source
     - Links/Author
   * - Aircrack-ng
     - 1.6
     - No
     - http://www.aircrack-ng.org/
   * - Arduino IDE
     - 1.8.15
     - No
     - https://www.arduino.cc/en/software
   * - airgeddon
     - v11.01
     - Yes
     - https://github.com/v1s1t0r1sh3r3/airgeddon
   * - Anki
     - 2.1.15
     - No
     - https://apps.ankiweb.net/
   * - baudline
     - 1.08
     - No
     - https://www.baudline.com/
   * - Bless
     - 0.6.0
     - No
     - https://github.com/afrantzis/bless
   * - btscanner
     - 2.1-8
     - No
     - https://salsa.debian.org/pkg-security-team/btscanner
   * - CRC RevEng
     - 3.0.5
     - Yes
     - https://reveng.sourceforge.io/
   * - CyberChef
     - \-
     - Yes
     - https://gchq.github.io/CyberChef/
   * - Dire Wolf
     - dev
     - Yes
     - https://github.com/wb2osz/direwolf
   * - Dump1090
     - 1.010.3010.14
     - Yes
     - https://github.com/antirez/dump1090
   * - dump978
     - latest
     - Yes
     - https://github.com/mutability/dump978
   * - Enscribe
     - 0.1.0
     - No
     - Jason Downer
   * - ESP32 Bluetooth Classic Sniffer
     - master
     - Yes
     - https://github.com/Matheus-Garbelini/esp32_bluetooth_classic_sniffer
   * - ESP8266 Deauther v2
     - v2
     - Yes
     - https://github.com/SpacehuhnTech/esp8266_deauther
   * - FALCON
     - \-
     - Yes
     - https://github.com/falkenber9/falcon
   * - fl2k
     - \-
     - Yes
     - https://osmocom.org/projects/osmo-fl2k/wiki
   * - Fldigi
     - 4.1.06
     - No
     - http://www.w1hkj.com/
   * - FoxtrotGPS
     - 1.2.2
     - No
     - https://www.foxtrotgps.org/
   * - Geany
     - 1.36
     - No
     - https://www.geany.org/
   * - GNU Radio
     - 3.8.5.0
     - No
     - https://www.gnuradio.org/
   * - Google Earth Pro
     - latest
     - No
     - https://www.google.com/earth/versions/
   * - Gpick
     - 0.2.6rc1
     -  No
     - https://github.com/thezbyg/gpick
   * - Gpredict
     - 2.3-33-gca42d22-1
     - No
     - http://gpredict.oz9aec.net/
   * - GQRX
     - 2.12
     - No
     - https://gqrx.dk/
   * - gr-acars
     - 3.8
     - Yes
     - https://sourceforge.net/projects/gr-acars/
   * - gr-adsb
     - master
     - Yes
     - https://github.com/mhostetter/gr-adsb
   * - gr-ainfosec
     - maint-3.8
     - Yes
     - https://github.com/ainfosec/fissure
   * - gr-air-modes
     - 0.0.20190917-2build2
     - No
     - https://github.com/bistromath/gr-air-modes
   * - gr-ais
     - master
     - Yes
     - https://github.com/bistromath/gr-ais
   * - |ss| gr-bluetooth |se|
     - 
     - 
     - https://github.com/greatscottgadgets/gr-bluetooth
   * - gr-clapper_plus
     - maint-3.8
     - Yes
     - https://github.com/cpoore1/gr-clapper_plus
   * - gr-dect2
     - master
     - Yes
     - https://github.com/pavelyazev/gr-dect2
   * - gr-foo
     - maint-3.8
     - Yes
     - https://github.com/bastibl/gr-foo
   * - gr-fuzzer
     - maint-3.8
     - Yes
     - https://github.com/ainfosec/fissure
   * - gr-garage_door
     - maint-3.8
     - Yes
     - https://github.com/cpoore1/gr-garage_door
   * - gr-gsm
     - master
     - Yes
     - https://github.com/ptrkrysik/gr-gsm
   * - gr-ieee802-11
     - maint-3.8
     - Yes
     - https://github.com/bastibl/gr-ieee802-11
   * - gr-ieee802-15-4
     - maint-3.8
     - Yes
     - https://github.com/bastibl/gr-ieee802-15-4
   * - gr-iio
     - upgrade-3.8
     - Yes
     - https://github.com/analogdevicesinc/gr-iio
   * - gr-iridium
     - maint-3.8
     - Yes
     - https://github.com/muccc/gr-iridium
   * - gr-j2497
     - maint-3.8
     - Yes
     - https://github.com/ainfosec/gr-j2497
   * - gr-limesdr
     - gr-3.8
     - Yes
     - https://github.com/myriadrf/gr-limesdr
   * - gr-mixalot
     - maint-3.8
     - Yes
     - https://github.com/unsynchronized/gr-mixalot
   * - gr-nrsc5
     - maint-3.8
     - Yes
     - https://github.com/argilo/gr-nrsc5
   * - gr-paint
     - maint-3.8
     - Yes
     - https://github.com/drmpeg/gr-paint
   * - gr-rds
     - maint-3.8
     - Yes
     - https://github.com/bastibl/gr-rds
   * - |ss| gr-tpms |se|
     - 
     - 
     - https://github.com/jboone/gr-tpms
   * - gr-tpms_poore
     - maint-3.8
     - Yes
     - https://github.com/cpoore1/gr-tpms_poore
   * - gr-X10
     - maint-3.8
     - Yes
     - https://github.com/cpoore1/gr-X10
   * - |ss| gr-Zwave |se|
     - \-
     - Yes
     - https://github.com/BastilleResearch/scapy-radio/tree/master/gnuradio/gr-Zwave
   * - gr-zwave_poore
     - maint-3.8
     - Yes
     - https://github.com/cpoore1/gr-zwave_poore
   * - GraphicsMagick
     - 1.4+really1.3.35-1
     - No
     - http://www.graphicsmagick.org/
   * - Grip
     - 4.6.1
     - No
     - https://github.com/joeyespo/grip
   * - HackRF
     - 2022.09.1
     - Yes
     - https://github.com/greatscottgadgets/hackrf/releases
   * - ham2mon
     - master
     - Yes
     - https://github.com/ta6o/ham2mon
   * - HamClock
     - latest
     - Yes
     - https://www.clearskyinstitute.com/ham/HamClock/
   * - hcidump
     - 5.53
     - No
     - http://www.bluez.org/
   * - htop
     - 2.2.0
     - No
     - https://github.com/htop-dev/htop
   * - Hydra
     - 9.0
     - No
     - https://github.com/vanhauser-thc/thc-hydra
   * - ICE9 Bluetooth Sniffer
     - master
     - Yes
     - https://github.com/mikeryan/ice9-bluetooth-sniffer
   * - IIO Oscilloscope
     - master
     - Yes
     - https://github.com/analogdevicesinc/iio-oscilloscope
   * - IMSI-Catcher 4G
     - \-
     - Yes
     - Joe Reith, AIS
   * - Inspectrum
     - 0.2.2-1build1
     - No
     - https://github.com/miek/inspectrum
   * - IridiumLive
     - v1.2
     - Yes
     - https://github.com/microp11/iridiumlive
   * - iridium-toolkit
     - master
     - Yes
     - https://github.com/muccc/iridium-toolkit
   * - Kalibrate
     - v0.4.1-rtl
     - Yes
     - https://github.com/steve-m/kalibrate-rtl
   * - Kismet
     - Kismet 2016-07-R1
     - No
     - https://www.kismetwireless.net/
   * - libbtbb
     - master
     - Yes
     - https://github.com/greatscottgadgets/libbtbb
   * - LTE-Cell-Scanner
     - master/1.1.0
     - Yes
     - https://github.com/JiaoXianjun/LTE-Cell-Scanner
   * - LTE-ciphercheck
     - rebase_20.04
     - Yes
     - https://github.com/mrlnc/LTE-ciphercheck
   * - m17-cxx-demod
     - master
     - Yes
     - https://github.com/mobilinkd/m17-cxx-demod
   * - Meld
     - 3.20.2
     - No
     - https://meldmerge.org/
   * - Metasploit
     - v6.1.44-dev-
     - Yes
     - https://www.metasploit.com/
   * - minicom
     - 2.7.1
     - No
     - https://salsa.debian.org/minicom-team/minicom
   * - minimodem
     - 0.24
     - No
     - http://www.whence.com/minimodem/
   * - mkusb/dus/guidus
     - 22.1.2
     - No
     - https://help.ubuntu.com/community/mkusb
   * - monitor_rtl433
     - master
     - Yes
     - https://github.com/mcbridejc/monitor_rtl433
   * - multimon-ng
     - master
     - Yes
     - https://github.com/EliasOenal/multimon-ng
   * - NETATTACK2
     - master
     - Yes
     - https://github.com/chrizator/netattack2
   * - nrsc5
     - master
     - Yes
     - https://github.com/theori-io/nrsc5
   * - |ss| OpenBTS |se|
     - 
     - 
     - https://github.com/RangeNetworks/dev
   * - openCPN
     - 5.6.2
     - No
     - https://opencpn.org/
   * - |ss| openHAB |se| (fix)
     - 
     - No
     - https://www.openhab.org/
   * - OpenWebRX
     - v0.20.3
     - No
     - https://github.com/jketterl/openwebrx
   * - Proxmark3
     - master
     - Yes
     - https://github.com/Proxmark/proxmark3
   * - PuTTY
     - 0.73
     - No
     - https://www.putty.org/
   * - pyFDA
     - 0.7.1
     - No
     - https://github.com/chipmuenk/pyfda
   * - PyGPSClient
     - 1.3.5
     - No
     - https://github.com/semuconsulting/PyGPSClient
   * - QSpectrumAnalyzer
     - 2.1.0
     - No
     - https://github.com/xmikos/qspectrumanalyzer
   * - QSSTV
     - 9.4.4
     - No
     - https://charlesreid1.com/wiki/Qsstv
   * - QtDesigner
     - 5.12.8
     - No
     - https://doc.qt.io/qt-5/qtdesigner-manual.html
   * - radiosonde_auto_rx
     - master
     - Yes
     - https://github.com/projecthorus/radiosonde_auto_rx
   * - rehex
     - master
     - Yes
     - https://github.com/solemnwarning/rehex
   * - retrogram-rtlsdr
     - master
     - Yes
     - https://github.com/r4d10n/retrogram-rtlsdr
   * - RouterSploit
     - master
     - Yes
     - https://www.github.com/threat9/routersploit
   * - rtl_433
     - master
     - Yes
     - https://github.com/merbanan/rtl_433
   * - rtl8812au Driver
     - latest
     - Yes
     - https://github.com/aircrack-ng/rtl8812au
   * - RTLSDR-Airband
     - master
     - Yes
     - https://github.com/szpajder/RTLSDR-Airband
   * - rtl-zwave
     - master
     - Yes
     - https://github.com/andersesbensen/rtl-zwave
   * - scan-ssid
     - master
     - Yes
     - https://github.com/Resethel/scan-ssid
   * - Scapy
     - 2.4.0
     - No
     - https://scapy.net/
   * - SdrGlut
     - master
     - Yes
     - https://github.com/righthalfplane/SdrGlut
   * - SDRTrunk
     - v0.5.0-alpha.6
     - Yes
     - https://github.com/DSheirer/sdrtrunk
   * - SigDigger
     - master
     - Yes
     - https://github.com/BatchDrake/SigDigger
   * - Spectrum Painter
     - master
     - Yes
     - https://github.com/polygon/spectrum_painter
   * - Spektrum
     - 2.1.0
     - Yes
     - https://github.com/pavels/spektrum
   * - srsRAN/srsLTE
     - master
     - Yes
     - https://www.srslte.com/
   * - systemback
     - 1.8.402~ubuntu16.04.1
     - No
     - https://github.com/BluewhaleRobot/systemback
   * - trackerjacker
     - 1.9.0
     - No
     - https://github.com/calebmadrigal/trackerjacker
   * - UDP Replay
     - master
     - Yes
     - https://github.com/rigtorp/udpreplay
   * - Universal Radio Hacker
     - 2.9.3
     - No
     - https://github.com/jopohl/urh
   * - V2Verifier
     - master
     - Yes
     - https://github.com/twardokus/v2verifier
   * - Viking
     - 1.10
     - Yes
     - https://sourceforge.net/projects/viking/
   * - WaveDrom
     - Online Editor
     - \-
     - https://github.com/wavedrom/wavedrom
   * - Waving-Z
     - master
     - Yes
     - https://github.com/baol/waving-z
   * - Wifite
     - master
     - Yes
     - https://github.com/derv82/wifite2
   * - Wireshark
     - 3.6.5
     - No
     - https://www.wireshark.org/
   * - WSJT-X
     - 2.1.2
     - No
     - https://physics.princeton.edu/pulsar/k1jt/wsjtx.html
   * - Xastir
     - 2.1.4+git20191127.bb66a77-3
     - No
     - https://github.com/Xastir/Xastir
   * - ZEPASSD
     - master
     - Yes
     - https://github.com/pvachon/zepassd
   * - Zigbee Sniffer
     - 0.1
     - Yes
     - https://github.com/yiek888/opensniffer

Ubuntu 22.04.1
--------------

.. list-table:: 
   :widths: 50 10 5 25
   :header-rows: 1

   * - Software
     - Version
     - From Source
     - Links/Author
   * - Aircrack-ng
     - 1.6
     - No
     - http://www.aircrack-ng.org/
   * - Arduino IDE
     - 1.8.15
     - No
     - https://www.arduino.cc/en/software
   * - airgeddon
     - v11.01
     - Yes
     - https://github.com/v1s1t0r1sh3r3/airgeddon
   * - Anki
     - 2.1.15
     - No
     - https://apps.ankiweb.net/
   * - baudline
     - 1.08
     - No
     - https://www.baudline.com/
   * - Bless
     - 0.6.3
     - No
     - https://github.com/afrantzis/bless
   * - btscanner
     - 2.1-9
     - No
     - https://salsa.debian.org/pkg-security-team/btscanner
   * - CRC RevEng
     - 3.0.5
     - Yes
     - https://reveng.sourceforge.io/
   * - CyberChef
     - \-
     - Yes
     - https://gchq.github.io/CyberChef/
   * - Dire Wolf
     - dev
     - Yes
     - https://github.com/wb2osz/direwolf
   * - Dump1090
     - 1.010.3010.14
     - Yes
     - https://github.com/antirez/dump1090
   * - dump978
     - latest
     - Yes
     - https://github.com/mutability/dump978
   * - Enscribe
     - 0.1.0
     - No
     - Jason Downer
   * - ESP32 Bluetooth Classic Sniffer
     - master
     - Yes
     - https://github.com/Matheus-Garbelini/esp32_bluetooth_classic_sniffer
   * - ESP8266 Deauther v2
     - v2
     - Yes
     - https://github.com/SpacehuhnTech/esp8266_deauther
   * - |ss| FALCON |se|
     - \-
     - Yes
     - https://github.com/falkenber9/falcon
   * - fl2k
     - \-
     - Yes
     - https://osmocom.org/projects/osmo-fl2k/wiki
   * - Fldigi
     - 4.1.20
     - No
     - http://www.w1hkj.com/
   * - FoxtrotGPS
     - 1.2.2+
     - No
     - https://www.foxtrotgps.org/
   * - Geany
     - 1.38
     - No
     - https://www.geany.org/
   * - GNU Radio
     - 3.10.4.0
     - No
     - https://www.gnuradio.org/
   * - Google Earth Pro
     - latest
     - No
     - https://www.google.com/earth/versions/
   * - Gpredict
     - 2.3-72-gc596101-3
     - No
     - http://gpredict.oz9aec.net/
   * - GQRX
     - 2.15.8
     - No
     - https://gqrx.dk/
   * - gr-acars
     - 3.10ng
     - Yes
     - https://git.code.sf.net/u/bkerler/gr-acars.git
   * - gr-adsb
     - maint-3.10
     - Yes
     - https://github.com/bkerler/gr-adsb
   * - gr-ainfosec
     - maint-3.10
     - Yes
     - https://github.com/ainfosec/fissure
   * - gr-air-modes
     - 0.0.20210211-2build2
     - No
     - https://github.com/bistromath/gr-air-modes
   * - gr-ais
     - maint-3.10
     - Yes
     - https://github.com/bkerler/gr-ais
   * - |ss| gr-bluetooth |se|
     - 
     - 
     - https://github.com/greatscottgadgets/gr-bluetooth
   * - gr-clapper_plus
     - maint-3.10
     - Yes
     - https://github.com/cpoore1/gr-clapper_plus
   * - gr-dect2
     - maint-3.10
     - Yes
     - https://github.com/bkerler/gr-dect2
   * - gr-foo
     - maint-3.10
     - Yes
     - https://github.com/bastibl/gr-foo
   * - gr-fuzzer
     - maint-3.10
     - Yes
     - https://github.com/ainfosec/fissure
   * - gr-garage_door
     - maint-3.10
     - Yes
     - https://github.com/cpoore1/gr-garage_door
   * - gr-gsm
     - maint-3.10
     - Yes
     - https://github.com/bkerler/gr-gsm
   * - gr-ieee802-11
     - maint-3.10
     - Yes
     - https://github.com/bastibl/gr-ieee802-11
   * - gr-ieee802-15-4
     - maint-3.10
     - Yes
     - https://github.com/bkerler/gr-ieee802-15-4
   * - |ss| gr-iio |se| 
     - 
     - 
     - https://github.com/analogdevicesinc/gr-iio
   * - gr-iridium
     - master
     - Yes
     - https://github.com/muccc/gr-iridium
   * - gr-j2497
     - maint-3.10
     - Yes
     - https://github.com/ainfosec/gr-j2497
   * - |ss| gr-limesdr |se| 
     - 
     - 
     - https://github.com/myriadrf/gr-limesdr
   * - gr-mixalot
     - main
     - Yes
     - https://github.com/unsynchronized/gr-mixalot
   * - gr-nrsc5
     - master
     - Yes
     - https://github.com/argilo/gr-nrsc5
   * - gr-paint
     - master
     - Yes
     - https://github.com/drmpeg/gr-paint
   * - gr-rds
     - maint-3.10
     - Yes
     - https://github.com/bastibl/gr-rds
   * - gr-tpms
     - maint-3.10
     - Yes
     - https://github.com/bkerler/gr-tpms
   * - gr-tpms_poore
     - maint-3.10
     - Yes
     - https://github.com/cpoore1/gr-tpms_poore
   * - gr-X10
     - maint-3.10
     - Yes
     - https://github.com/cpoore1/gr-X10
   * - |ss| gr-Zwave |se|
     - \-
     - Yes
     - https://github.com/BastilleResearch/scapy-radio/tree/master/gnuradio/gr-Zwave
   * - gr-zwave_poore
     - maint-3.10
     - Yes
     - https://github.com/cpoore1/gr-zwave_poore
   * - GraphicsMagick
     - 1.4+really1.3.38-1
     - No
     - http://www.graphicsmagick.org/
   * - Grip
     - 4.6.1
     - No
     - https://github.com/joeyespo/grip
   * - HackRF
     - 2022.09.1
     - Yes
     - https://github.com/greatscottgadgets/hackrf/releases
   * - ham2mon
     - maint-3.10
     - Yes
     - https://github.com/bkerler/ham2mon
   * - HamClock
     - latest
     - Yes
     - https://www.clearskyinstitute.com/ham/HamClock/
   * - hcidump
     - 5.64
     - No
     - http://www.bluez.org/
   * - htop
     - 3.0.5
     - No
     - https://github.com/htop-dev/htop
   * - Hydra
     - 9.2
     - No
     - https://github.com/vanhauser-thc/thc-hydra
   * - ICE9 Bluetooth Sniffer
     - master
     - Yes
     - https://github.com/mikeryan/ice9-bluetooth-sniffer
   * - IIO Oscilloscope
     - master
     - Yes
     - https://github.com/analogdevicesinc/iio-oscilloscope
   * - IMSI-Catcher 4G
     - \-
     - Yes
     - Joe Reith, AIS
   * - Inspectrum
     - 0.2.3-2
     - No
     - https://github.com/miek/inspectrum
   * - IridiumLive
     - v1.2
     - Yes
     - https://github.com/microp11/iridiumlive
   * - iridium-toolkit
     - master
     - Yes
     - https://github.com/muccc/iridium-toolkit
   * - Kalibrate
     - v0.4.1-rtl
     - Yes
     - https://github.com/steve-m/kalibrate-rtl
   * - Kismet
     - latest
     - No
     - https://www.kismetwireless.net/
   * - |ss| libbtbb |se|
     - master
     - Yes
     - https://github.com/greatscottgadgets/libbtbb
   * - LTE-Cell-Scanner
     - master/1.1.0
     - Yes
     - https://github.com/JiaoXianjun/LTE-Cell-Scanner
   * - LTE-ciphercheck
     - rebase_20.04
     - Yes
     - https://github.com/mrlnc/LTE-ciphercheck
   * - m17-cxx-demod
     - master
     - Yes
     - https://github.com/mobilinkd/m17-cxx-demod
   * - Meld
     - 3.20.4
     - No
     - https://meldmerge.org/
   * - |ss| Metasploit |se|
     - v6.1.44-dev- 
     - Yes
     - https://www.metasploit.com/
   * - minicom
     - 2.8
     - No
     - https://salsa.debian.org/minicom-team/minicom
   * - minimodem
     - 0.24
     - No
     - http://www.whence.com/minimodem/
   * - mkusb/dus/guidus
     - 22.1.2
     - No
     - https://help.ubuntu.com/community/mkusb
   * - monitor_rtl433
     - master
     - Yes
     - https://github.com/mcbridejc/monitor_rtl433
   * - multimon-ng
     - master
     - Yes
     - https://github.com/EliasOenal/multimon-ng
   * - |ss| NETATTACK2 |se|
     - master
     - Yes
     - https://github.com/chrizator/netattack2
   * - nrsc5
     - master
     - Yes
     - https://github.com/theori-io/nrsc5
   * - |ss| OpenBTS |se|
     - 
     - 
     - https://github.com/RangeNetworks/dev
   * - openCPN
     - 5.6.2
     - No
     - https://opencpn.org/
   * - |ss| openHAB |se| (fix)
     - 
     - No
     - https://www.openhab.org/
   * - OpenWebRX
     - v1.2.1
     - No
     - https://github.com/jketterl/openwebrx
   * - Proxmark3
     - master
     - Yes
     - https://github.com/Proxmark/proxmark3
   * - PuTTY
     - 0.76
     - No
     - https://www.putty.org/
   * - pyFDA
     - 0.7.1
     - No
     - https://github.com/chipmuenk/pyfda
   * - PyGPSClient
     - 1.3.5
     - No
     - https://github.com/semuconsulting/PyGPSClient
   * - QSpectrumAnalyzer
     - 2.1.0
     - No
     - https://github.com/xmikos/qspectrumanalyzer
   * - QSSTV
     - 9.5.8
     - No
     - https://charlesreid1.com/wiki/Qsstv
   * - QtDesigner
     - 5.15.3
     - No
     - https://doc.qt.io/qt-5/qtdesigner-manual.html
   * - radiosonde_auto_rx
     - master
     - Yes
     - https://github.com/projecthorus/radiosonde_auto_rx
   * - rehex
     - master
     - Yes
     - https://github.com/solemnwarning/rehex
   * - retrogram-rtlsdr
     - master
     - Yes
     - https://github.com/r4d10n/retrogram-rtlsdr
   * - RouterSploit
     - master
     - Yes
     - https://www.github.com/threat9/routersploit
   * - rtl_433
     - master
     - Yes
     - https://github.com/merbanan/rtl_433
   * - rtl8812au Driver
     - latest
     - Yes
     - https://github.com/aircrack-ng/rtl8812au
   * - RTLSDR-Airband
     - master
     - Yes
     - https://github.com/szpajder/RTLSDR-Airband
   * - rtl-zwave
     - master
     - Yes
     - https://github.com/andersesbensen/rtl-zwave
   * - scan-ssid
     - master
     - Yes
     - https://github.com/Resethel/scan-ssid
   * - Scapy
     - | 2.4.5 (Python2)
       | 2.4.4 (Python3)
     - No
     - https://scapy.net/
   * - |ss| SdrGlut |se| 
     - master
     - Yes
     - https://github.com/righthalfplane/SdrGlut
   * - SDRTrunk
     - v0.5.0-alpha.6
     - Yes
     - https://github.com/DSheirer/sdrtrunk
   * - SigDigger
     - master
     - Yes
     - https://github.com/BatchDrake/SigDigger
   * - Spectrum Painter
     - master
     - Yes
     - https://github.com/polygon/spectrum_painter
   * - Spektrum
     - 2.1.0
     - Yes
     - https://github.com/pavels/spektrum
   * - srsRAN/srsLTE
     - master
     - Yes
     - https://www.srslte.com/
   * - systemback
     - 1.8.402~ubuntu16.04.1
     - No
     - https://github.com/BluewhaleRobot/systemback
   * - trackerjacker
     - 1.9.0
     - No
     - https://github.com/calebmadrigal/trackerjacker
   * - UDP Replay
     - master
     - Yes
     - https://github.com/rigtorp/udpreplay
   * - |ss| Universal Radio Hacker |se|
     - 2.9.3
     - No
     - https://github.com/jopohl/urh
   * - V2Verifier
     - master
     - Yes
     - https://github.com/twardokus/v2verifier
   * - Viking
     - 1.10
     - Yes
     - https://sourceforge.net/projects/viking/
   * - WaveDrom
     - Online Editor
     - \-
     - https://github.com/wavedrom/wavedrom
   * - Waving-Z
     - master
     - Yes
     - https://github.com/baol/waving-z
   * - Wifite
     - master
     - Yes
     - https://github.com/derv82/wifite2
   * - Wireshark
     - 3.6.5
     - No
     - https://www.wireshark.org/
   * - wl-color-picker
     - master
     - Yes
     - https://github.com/jgmdev/wl-color-picker
   * - WSJT-X
     - 2.5.4
     - No
     - https://physics.princeton.edu/pulsar/k1jt/wsjtx.html
   * - Xastir
     - 2.1.6-4
     - No
     - https://github.com/Xastir/Xastir
   * - ZEPASSD
     - master
     - Yes
     - https://github.com/pvachon/zepassd
   * - Zigbee Sniffer
     - 0.1
     - Yes
     - https://github.com/yiek888/opensniffer



