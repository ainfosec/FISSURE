---
**OpenBTS** (Open Base Transceiver Station) is a software-based GSM access point, allowing standard GSM-compatible mobile phones to be used as SIP (Session Initiation Protocol) endpoints in Voice over IP (VoIP) networks. The OpenBTS software is a Linux application that uses software-defined radio to present a standard 3GPP air interface to user devices. The intended purpose is to expand coverage to unserved and underserved markets while unleashing a platform for innovation.

This lesson will cover the steps for installation and provide instructions for running the necessary programs to ultimately enable voice and text between mobile phones on a GSM network administered by an SDR. 


## Table of Contents
1. [Installation](#installation)
2. [Running](#running)
3. [Configuring OpenBTS](#configuring_openbts)
4. [Adding a Phone to the Registry](#adding_phone)
5. [Asterisk](#asterisk)
6. [SIM Programming](#sim_programming)

<div id="installation"/> 

## Installation
OpenBTS has been tested successfully with the FISSURE installer for Ubuntu 18.04 and 18.04.5 only. The installation was already performed if there are files in the `~/Installed_by_FISSURE/OpenBTS` directory. The commands executed during installation can be viewed in the FISSURE installer by running the `/FISSURE/install` file.

### OpenBTS Ubuntu 18.04 Installation
The FISSURE installer was derived from the following commands. Small adjustments could have been made in the installer from when these notes were first produced.

- Supporting Files:
  ```
  sudo apt-get install software-properties-common python-software-properties
  sudo add-apt-repository ppa:git-core/ppa
  (press enter to continue)
  sudo apt-get update
  sudo apt-get install git
  sudo apt-get install asterisk
  sudo apt-get install twinkle
  sudo apt-get install autoconf libtool libosip2-dev libortp-dev libusb-1.0-0-dev g++ sqlite3 libsqlite3-dev erlang 
  libreadline6-dev libncurses5-dev
  ```

- Download OpenBTS, install liba53, fakecoredumper:
  ```
  mkdir OpenBTS
  cd OpenBTS
  git clone https://github.com/RangeNetworks/dev.git
  cd dev
  ./clone.sh
  ./switchto.sh master
  cd liba53/
  sudo make install
  cd ..
  git clone https://github.com/tom-2015/fakecoredumper.git
  cd fakecoredumper
  chmod +x install.sh
  ./install.sh
  cd ..
  ```

- Edit ./build.sh:
  - Comment out line in ./build.sh with "python-software-properties"
  - Add * to end of "installIfMissing libuhd003"
  - Comment out these lines:
  ```
	#sayAndDo ./build.sh
	#sayAndDo mv libcoredumper* ../$BUILDNAME
	#sayAndDo sudo dpkg -i $BUILDNAME/libcoredumper*.deb
  ```
  - Comment out all the asterisk install lines:
  ```
	#sayAndDo cd asterisk
	#rm -rf range-asterisk* asterisk-*
	#sayAndDo ./build.sh
	#sayAndDo mv range-asterisk_* ../$BUILDNAME
	#sayAndDo cd ..
  ```

- Install gcc5:
  ```
  sudo apt install g++-5 -y
  sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-5 60 \
                         --slave /usr/bin/g++ g++ /usr/bin/g++-5 
  ```

- Build OpenBTS for USRP B210 and Initialize SQL Database
  ```
  ./build.sh B210
  sudo mkdir /etc/OpenBTS
  cd openbts
  sudo sqlite3 -init ./apps/OpenBTS.example.sql /etc/OpenBTS/OpenBTS.db ".quit"
  ```

- Get B210 Firmware (OpenBTS probably won't work with an existing UHD/firmware combination):
  - Download: https://files.ettus.com/binaries/images/uhd-images_003.010.003.000-release.zip
  - Unzip and move usrp_b210_fpga.bin to /usr/share/uhd/images/

- Create transceiver files:
  ```
  cd apps
  ln -s ../Transceiver52M/transceiver .
  ```

- Get SQLite Browser:
  ```
  sudo apt-get install sqlitebrowser
  sudo mkdir -p /var/lib/asterisk/sqlite3dir
  ```

- Install subscriberRegistry:
  ```
  cd ../../subscriberRegistry
  make
  cd apps
  ```
  - Copy contents into sipauthserve.example.sql: https://github.com/kacipbuah/openbts-range/blob/master/subscriberRegistry/trunk/sipauthserve.example.sql

- Install sipautherserve:
  ```
  sudo sqlite3 -init sipauthserve.example.sql /etc/OpenBTS/sipauthserve.db ".quit"
  sudo ./sipauthserv
  ```

- Install smqueue:
  ```
  cd ../../smqueue
  autoconf -i
  ./configure
  make
  ```
  - Copy contents into /smqueue/smqueue.example.sql: https://github.com/fairwaves/smqueue-2.8/blob/master/smqueue/smqueue.example.sql
  ```
  sudo sqlite3 -init smqueue/smqueue.example.sql /etc/OpenBTS/smqueue.db ".quit"
  cd smqueue
  sudo ./smqueue
  ```

<div id="running"/> 

## Running
1. OpenBTS
  ```
  cd ~/OpenBTS/dev/openbts/apps
  uhd_usrp_probe
  sudo ./OpenBTS
  ```

2. Sipauthserve
  ```
  cd ~/OpenBTS/dev/subscriberRegistry/apps
  sudo ./sipauthserve
  ```

3. SMQueue
  ```
  cd ~/OpenBTS/dev/smqueue/smqueue
  sudo ./smqueue
  ```

4. Asterisk
  ```
  sudo asterisk -vvvvvr
  ```

<div id="configuring_openbts"/> 

## Configuring OpenBTS
- Run OpenBTS:
  ```
  uhd_usrp_probe
  sudo ./OpenBTS
  ```
- In CLI:
  ```
  config GSM.Radio.Band 1900
  config GSM.Radio.C0 512
  config Control.LUR.OpenRegistration .*
  power 25
  rxgain 25 (25-47)
  config GSM.Cipher.Encrypt 1
  tmsis
  ```

<div id="adding_phone"/> 

## Adding a Phone to the Registry
- Add entry to Node Manager (while Sipauthserve is running):
  ```
  cd ~/OpenBTS/dev/NodeManager
  ./nmcli.py sipauthserve subscribers read
  ./nmcli.py sipauthserve subscribers create "Phone1" IMSI310260097464737 1111
  ./nmcli.py sipauthserve subscribers create "Phone2" IMSI901700000023687 2222
  ./nmcli.py sipauthserve subscribers create "Test-1" IMSI901550000000000 1234567 d360c2591de1bf61a11014c33d012246
  ./nmcli.py sipauthserve subscribers delete imsi IMSI310260097464737
  ```

https://github.com/RangeNetworks/dev/issues/44
https://github.com/RangeNetworks/dev/issues/47
https://gist.github.com/jlblancoc/99521194aba975286c80f93e47966dc5

- Edit /etc/asterisk/sip.conf:
  ```
	[IMSI310260097464737]
	callerid=1111
	canreinvite=no
	type=friend
	allow=gsm
	context=sip-external
	host=dynamic
	dtmfmode=info


	[IMSI901700000023687]
	callerid=2222
	canreinvite=no
	type=friend
	allow=gsm
	context=sip-external
	host=dynamic
	dtmfmode=info
  ```

- Edit /etc/asterisk/extensions.conf:
  ```
	[macro-dialGSM]
	exten => s,1,Dial(SIP/${ARG1},20)
	exten => s,2,Goto(s-${DIALSTATUS},1)
	exten => s-CANCEL,1,Hangup
	exten => s-NOANSWER,1,Hangup
	exten => s-BUSY,1,Busy(30)
	exten => s-CONGESTION,1,Congestion(30)
	exten => s-CHANUNAVAIL,1,playback(ss-noservice)
	exten => s-CANCEL,1,Hangup

	[sip-external]
	exten => 1111,1,Macro(dialGSM,IMSI310260097464737@127.0.0.1:5062)
	exten => 2222,1,Macro(dialGSM,IMSI901700000023687@127.0.0.1:5062)
  ```

<div id="asterisk"/> 

## Asterisk
- Starting Asterisk:
  ```
  sudo service asterisk start
  sudo asterisk -vvvvvr
  ```

- In Asterisk:
  ```
  core restart now
  core stop now
  ```

<div id="sim_programming"/> 

## SIM Programming
This is included as part of the OpenBTS installation in the FISSURE installer.
```
sudo apt-get install -y pcscd pcsc-tools libccid libpcsclite-dev
cd ~/Installed_by_FISSURE
git clone git://git.osmocom.org/pysim
cd pysim
sudo pip3 install -r requirements.txt
```

```
./pySim-read
./pySim-read -p 0
./pySim-read -p 1
./pySim-prog.py -p 0 -x 310 -y 070 -n test1 -t sysmoUSIM-SJS1 -i 901700000023688 -s 8988211000000236888 -o 1B0A4D434B184DE7BA88147E725C5AAD -k 0B7BBF089FD188EA0C64FEE245EB03E7 -a 12100237
```


