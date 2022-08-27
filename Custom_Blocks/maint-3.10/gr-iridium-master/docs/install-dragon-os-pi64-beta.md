# gr-iridium installation on DragonOS Pi64 Beta

NOTE: At the time of writing DragonOS Pi64 is still in beta state. These instructions
are valid for the last beta available end of April 2022.


## Download

Please navigate to https://sourceforge.net/projects/dragonos-pi64/
to get the latest version. Also consider following https://twitter.com/cemaxecuter for updates.


## Installation

Extract the image file onto an SD card. Something like this might work for you:

```
$ zcat DragonOS_Pi64_Beta_GR3.10v5.img.gz | sudo tee /dev/sdb > /dev/null
$ sync
```

ATTENTION: /dev/sdb is only a placeholder for your SD card reader's device. If you don't
know what that means, please use one of the available "Write image to SD card" tools
available for the Raspberry Pi.


After booting the first time you need to reset the device once to get SSH working.

Get the IP of the Raspberry Pi (maybe check your router's web interface or similar) and log
in using SSH. Username: `ubuntu` Password: `dragon`.

Run `volk_profile` to optimize performance:

```
$ volk_profile
```

## Execution

gr-iridium is located under `/usr/src/gr-iridium` and is already compiled and installed
in the system. You can execute it like this:

```
$ iridium-extractor /usr/src/gr-iridium/examples/<your-sdr>.conf > output.bits`
```

A good starting point for a config on the Raspberry Pi is `hackrf-pi4.conf`. It already
configures gr-iridium to get most of the Iridium band and still be able to do it on a
Raspberry Pi 4.


## Update
You can update gr-iridium by running:
```
$ cd /usr/src/gr-iridium
$ sudo git fetch origin
$ sudo git merge origin/master
$ sudo rm -rf build
$ sudo cmake -B build
$ sudo cmake --build build
$ sudo cmake --install build
```
