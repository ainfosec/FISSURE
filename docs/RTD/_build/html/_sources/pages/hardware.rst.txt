========
Hardware
========

FISSURE was designed to be flexible in its support for integration of commercial-off-the-shelf (COTS) and non-COTS devices. The receive and transmit capabilities within FISSURE are subject to the limitations inherent to the connected hardware. Any device that can be networked and configured through scripting could be supported within FISSURE. More hardware devices and capabilities will be added over time.

Hardware is utilized by FISSURE through the following ways:

- Example commands for third-party tools accessed from the menu
- Target Signal Identifcation (TSI) flow graphs for detection and signal conditioning
- Protocol Discovery flow graphs for demodulation purposes
- Attack scripts and flow graphs for single-stage, multi-stage, and fuzzing attacks
- IQ recording, playback, and inspection in the IQ Data tab
- Transmitting signal playlists in the Archive tab
- Transmitting Scapy messages crafted in the Packet Crafter tab
 
Supported Peripherals
=====================

The following is a list of "supported" peripheral hardware with varying levels of integration:

- USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
- HackRF
- RTL2832U
- 802.11 Adapters
- LimeSDR
- bladeRF, bladeRF 2.0 micro
- Open Sniffer
- PlutoSDR
- SDRplay: RSPduo, RSPdx

Supported Sensor Node Hardware
==============================

Remote sensor nodes have been tested on the following hardware: (coming soon)

Notes
=====

The following are miscellaneous notes regarding particular hardware models.

LimeSDR Notes
-------------

**Links**

- https://wiki.myriadrf.org/Lime_Suite
- https://wiki.myriadrf.org/Gr-limesdr_Plugin_for_GNURadio
- https://myriadrf.org/news/limesdr-made-simple-part-1/

**Installing**

*From Repo*

.. code-block:: console

    sudo add-apt-repository -y ppa:myriadrf/drivers
    sudo apt-get update
    sudo apt-get install limesuite liblimesuite-dev limesuite-udev limesuite-images
    sudo apt-get install soapysdr-tools soapysdr-module-lms7

.. code-block:: console

    # soapysdr-tools was called soapysdr on older packages
    sudo apt-get install soapysdr soapysdr-module-lms7

*From Source*

.. code-block:: console

    sudo apt-get install libboost-all-dev swig

    git clone https://github.com/myriadrf/gr-limesdr

    cd gr-limesdr
    mkdir build
    cd build
    cmake ..
    make
    sudo make install
    sudo ldconfig

**Other Notes**

- `LimeUtil \--find`
- LimeSDR-USB and LimeSDR-PCIe sample rate must be no more than 61.44 MS/s.
- Gain range must be 0dB–70dB (60 on transmit, 70 on receive).
- Up to 10 dBm
- Analog filter bandw. (callback function value): Enter RX analog filter bandwidth for each channel. 0 means that analog filter is turned OFF.
- RX analog filter bandwidth range must be 1.5MHz–130MHz.
- Digital filter bandw. (callback function value):Enter RX digital filter bandwidth for each channel. 0 means that digital filter is turned OFF.
- RX digital filter bandwidth should not be higher than sampling rate.
- LimeSDR v1.4s
- `LimeSuiteGUI`


New USRP X310
-------------

1. Plug 10 GbE into second slot on USRP
2. Set computer IP to 192.168.40.1. Ping 192.168.40.2. Run `uhd_find_devices`. If there is an RFNOC error about a missing folder, download a UHD release and copy the folder:
3. `wget https://codeload.github.com/EttusResearch/uhd/zip/release_003_010_003_000 -O uhd.zip`
4. `unzip uhd.zip`
5. `cd uhd-release_003_010_003_000/host/include`
6. `sudo cp -Rv uhd/rfnoc /usr/share/uhd/`
7. Try to run flow graph. It will print out instructions for matching FPGA images for current version of UHD.
8. `/home/user/lib/uhd/utils/uhd_images_downloader.py` or  `/usr/lib/uhd/utils/uhd_images_downloader.py`
9. `/home/user/bin/uhd_image_loader --args="type=x300,addr=192.168.40.2"` or `/usr/bin/uhd_image_loader" --args="type=x300,addr=192.168.140.2"`
10. Set MTU to 9000 for the 10 GbE network connection.
11. Change IP address of USRP 10 GbE connection as needed:

.. code-block:: console

    cd usr/lib/uhd/utils
    ./usrp_burn_mb_eeprom --args=<optional device args> --values="ip-addr3=192.168.140.2"

12. Adjust this value to something like: `sudo sysctl -w net.core.wmem_max=24862979`

Updating HackRF Firmware
------------------------

Firmware is included with each HackRF `release <https://github.com/greatscottgadgets/hackrf/releases>`_. Firmware updates allow for more advanced features like *hackrf_sweep*.

.. code-block:: console

    hackrf_spiflash -w ~/Installed_by_FISSURE/hackrf-2022.09.1/firmware-bin/hackrf_one_usb.bin

**Updating the CPLD**

Older versions of HackRF firmware (prior to release 2021.03.1) require an additional step to program a bitstream into the CPLD.

To update the CPLD image, first update the SPI flash firmware, libhackrf, and hackrf-tools to the version you are installing. Then:

.. code-block:: console

    hackrf_cpldjtag -x firmware/cpld/sgpio_if/default.xsvf

After a few seconds, three LEDs should start blinking. This indicates that the CPLD has been programmed successfully. Reset the HackRF device by pressing the RESET button or by unplugging it and plugging it back in.

