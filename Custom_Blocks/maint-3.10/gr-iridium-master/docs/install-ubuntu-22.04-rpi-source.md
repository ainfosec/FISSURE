# gr-iridium installation on Ubuntu 22.04 on Raspberry Pi 4

## Install Ubuntu 22.04

The preferred way of installing Ubuntu 22.04 on a Raspberry Pi 4 is via the `rpi-imager` tool.
Please either install "Ubuntu Desktop 22.04 LTS (RPi 4/400)" or "Ubuntu Server 22.04 LTS (RPi Zero 2/3/4/400)"
as these are the 64-bit versions (marked as "64-bit" in the description). You can find Ubuntu 22.04 under
"Choose OS" -> "Other general-purpose OS" -> "Ubuntu".


## Install gr-iridium

After logging into your Raspberry Pi 4 you can follow the normal
[Ubuntu 22.04 instructions](install-ubuntu-22.04.md) to install gr-iridium on Ubuntu.


## Special Notes

The Ethernet interface of the Raspberry Pi 4 produces interference inside the Iridium frequency band.
The device in general also emits noise which an active antenna easily picks up. Try to place your
active antenna away from your Raspberry PI 4 to avoid interference.



