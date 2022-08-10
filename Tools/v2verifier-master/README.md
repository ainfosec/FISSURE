# V2Verifier
V2Verifer is an open-source project dedicated to wireless experimentation
focused on the security of vehicle-to-vehicle (V2V) communications.
Included are implementations of:
- Security features from the IEEE 1609.2 standard for V2V security
- WAVE Short Message Protocol (IEEE 1609.3)
- Dedicated Short Range Communication (DSRC) - adapted from 
the [WiME Project's](http://dx.doi.org/10.1109/TMC.2017.2751474)
IEEE 802.11p transceiver 

## Publications
If you use our testbed code, we would appreciate a reference to the following publication:

Geoff Twardokus, Jaime Ponicki, Samantha Baker, Peter Carenzo, [Hanif Rahbari](http://rahbari.csec.rit.edu/), and 
Sumita Mishra, "**Targeted Discreditation Attack against Trust Management in Connected Vehicles**," _IEEE International 
Conference on Communications (ICC 2021)_, Virtual/Montreal, June 2021 
[[PDF](http://rahbari.csec.rit.edu/papers/V2Verifier_ICC21.pdf)]

Additional publications related to the V2Verifier project are listed 
[here](https://github.com/twardokus/v2verifier/wiki/Publications).

## Requirements
Running V2Verifier requires a minimum of two USRP software-defined radios (B210 or N210 with 5.9 GHz daughterboards) 
and at least one PC capable of running Ubuntu 18.04. A virtual machine may be used, but is not recommended. We further 
recommend using two PCs with one USRP connected to each PC for best results.


## Installing V2Verifier
On each Ubuntu PC, you must install the following dependencies:

	sudo apt install -y git cmake libuhd-dev uhd-host swig libgmp3-dev python3-pip python3-tk python3-pil 
	python3-pil.imagetk gnuradio

Since V2Verifier incorporates open-source code from the [WiME project](https://www.wime-project.net/), 
you need to install two components from that project.  
    
    cd ~
    git clone https://github.com/bastibl/gr-foo.git
    cd gr-foo
    git checkout maint-3.7
    mkdir build
    cd build
    cmake ..
    make
    sudo make install
    sudo ldconfig

	cd ~
	git clone git://github.com/bastibl/gr-ieee802-11.git
	cd gr-ieee802-11
	git checkout maint-3.7
	mkdir build
	cd build
	cmake ..
	make
	sudo make install
	sudo ldconfig
		
Next, install some Python 3 libraries.

	pip3 install fastecdsa
	pip3 install -U pyyaml

## Running V2Verifier
Connect one USRP to each PC. On both PCs, launch GNURadio with the command `gnuradio-companion` from a terminal. 
On one PC, open the `wifi_tx.grc` file from the `v2verifier/grc` project subdirectory. On the other PC, open 
the `wifi_rx.grc` file from the same subdirectory. Click the green play button at the top of GNURadio to launch the 
flowgraphs on both PCs. You will need to configure the communication options (e.g., bandwith, frequency) to suit your 
needs. The default is a 10 MHz channel on 5.89 GHz.

On each PC, navigate to the v2verifier directory. For the receiver, run the command

    python3 main.py local dsrc [-g]

to launch the receiver (include the `-g` option for GUI support). For the transmitter, run the command

    python3 main.py remote dsrc
    
to begin transmitting messages.

*Note that V2Verifier also supports C-V2X communication, but this requires equipment capable of both cellular
communication and GPS clock synchronization (e.g., USRP B210 w/ GPSDO or 
[Cohda Wireless MK6c](https://cohdawireless.com/solutions/hardware/mk6c-evk/)) as well as access to either an outdoor
testing environment or synthesized GPS source.*

## Replay attack with V2Verifier
Conducting a replay attack requires three USRPs and three PCs.
One USRP, which will be used to conduct the attack, will require two antennas.

Set up two PCs as above and run the normal transmitter and receiver programs. Make sure to use the `-g` option with 
the `local` program to launch the receiver GUI.

    python3 ./main.py [local | remote] dsrc [-g]
    
On the third PC, connected to the USRP with two antennas, open the `wifi_rx.grc` and `wifi_tx.grc` flowgraphs in 
GNURadio. Also, open a terminal and navigate to the `replay_attack` directory in the V2Verifier directory.
- Run the `wifi_rx.grc` flowgraph
- Switch to the terminal and run `python3 ./replay_attack.py <seconds_to_collect>`
- When the script prompts to press Enter, *wait!* Go back to GNURadio, stop the `wifi_rx.grc` flowgraph and run 
the `wifi_tx.grc` flowgraph
- Return to the terminal and press Enter. The attacker will begin replaying messages.
- Look at the receiver you started at the beginning. You should see the effects of the replay attack (e.g., warning 
messages in yellow text on the message feed) on the GUI.
