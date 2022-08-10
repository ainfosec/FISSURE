# retrogram~rtlsdr 

	          _                                      /\/|    _   _ _________________ 
	         | |                                    |/\/    | | | /  ___|  _  \ ___ \
	 _ __ ___| |_ _ __ ___   __ _ _ __ __ _ _ __ ___    _ __| |_| \ `--.| | | | |_/ /
	| '__/ _ \ __| '__/ _ \ / _` | '__/ _` | '_ ` _ \  | '__| __| |`--. \ | | |    / 
	| | |  __/ |_| | | (_) | (_| | | | (_| | | | | | | | |  | |_| /\__/ / |/ /| |\ \ 
	|_|  \___|\__|_|  \___/ \__, |_|  \__,_|_| |_| |_| |_|   \__|_\____/|___/ \_| \_|
	                         __/ |                                                   
	                        |___/                                                    


Wideband Spectrum analyzer on your terminal/ssh console with ASCII art. 
Hacked from Ettus UHD RX ASCII Art DFT code for RTLSDR. Adapted from [retrogram~plutosdr](https://github.com/r4d10n/retrogram-plutosdr). 

![retrogram-rtlsdr-vhf](https://i.imgur.com/BGmYK5i.jpg)
[Tuning on VHF band while transmitting on 145.500 MHz with Handheld Radio]

![retrogram-rtlsdr-gsm](https://imgur.com/REhEnv2.jpg)
[Spotting FCCH (Freq. Correction) burst in the local GSM BCCH (Broadcast Control Channel) @ 938.2 MHz]

Pan & Zoom spectrum using keyboard controls [decrement-Increment]. [[Full feature demo](https://www.youtube.com/watch?v=JnrknBrvYjw)]

* Center Frequency 	using keys [f-F] 
* Sampling rate    	using keys [r-R]
* Gain 		   	using keys [g-G]
* Reference level  	using keys [l-L] 
* Dynamic Range    	using keys [d-D]
* Frame rate       	using keys [s-S]
* Tuning step	   	using keys [t-T]
* Hide/Show Controls 	using keys [c-C]
* Quit program		using keys [q-Q]

Tuning step applies for decrementing / Incrementing Center Frequency and Sampling Rate.

---
	retrogram~rtlsdr - ASCII Art Spectrum Analysis for RTLSDR

	Allowed options:
	  --help                   help message
	  --dev arg (=0)           rtl-sdr device index
	  --rate arg (=1000000)    rate of incoming samples (sps) [r-R]
	  --freq arg (=100000000)  RF center frequency in Hz [f-F]
	  --gain arg (=0)          gain for the RF chain [g-G]
	  --frame-rate arg (=15)   frame rate of the display (fps) [s-S]
	  --ref-lvl arg (=0)       reference level for the display (dB) [l-L]
	  --dyn-rng arg (=80)      dynamic range for the display (dB) [d-D]
	  --step arg (=100000)     tuning step for rate/bw/freq [t-T]
	  --show-controls arg (=1) show the keyboard controls
---

## Requires: librtlsdr, libcurses, libboost-program-options
	
	sudo apt install librtlsdr-dev libncurses5-dev libboost-program-options-dev

## Build:

For running on a Linux host with RTLSDR 

	make

## Run:

	./retrogram-rtlsdr --rate 1.8e6 --freq 100e6 --step 1e5

## TODO:

* Generic support for osmosdr / [soapysdr](https://github.com/r4d10n/retrogram-soapysdr) devices
* Direct Freq Entry / parameter change 
* Mouse tuning
* Modularize / Optimize with std::vector transform
* Waterfall (!) / Markers / Demodulators (!!) :)
* HTML output / Web(sockets)-server
