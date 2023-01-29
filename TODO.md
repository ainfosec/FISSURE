# To-Do List
The following are lists of ideas for the integration of additional third-party tools, upgrades to FISSURE, and new lesson topics. Most have yet to be investigated and may ultimately not be applicable due to things like installation requirements or license restrictions. These items are listed in no particular order and will be removed/adjusted as the project progresses. They are meant for idea generation only and do not represent a development schedule or the tasks currently in motion for the project. Refer to the Roadmap section in the README for high-priority items.

## Table of Contents
1. [Third-Party Tool Ideas](#third-party)
2. [FISSURE Upgrade Ideas](#upgrades)
3. [Lesson Ideas](#lessons)


## Third-Party Tool Ideas

<div id="third-party"/> 

- NOAA Satellite Images (only three times a day?)
- P25
- aircrack gui
- TV
- DVB-S2
- Key Fobs: ASK, FSK, PSK
- LoRaWAN
- Bastille MouseJack: https://www.bastille.net/research/vulnerabilities/mousejack/affected-devices
- Phillips Hue Worm
- Insteon
- Lutron Clear Connect
- GNUPlot for visualizing bits from multiple messages: https://lucsmall.com/2012/05/21/gnuplot-for-the-electronics-enthusiast-part-1-visualising-data-from-the-saleae-logic/
- AIS receiver and transmitter: https://www.reddit.com/r/RTLSDR/comments/1mcikt/for_the_nautical_set_rtlsdr_with_grais_and_opencpn/
- fm_tune for calibration
- liquid dsp? How many things use it? (fm_tune)
- 2G IMSI-catcher
- Try out SDR++ - needs >gcc-8, will other hardware dep. mess with stuff?
- sdrangel
- shinysdr
- sparrow wifi
- dumphfdl
- dxlAPRS
- rdzTTGOsonde
- CaribouLite
- gqrx-scanner, works with gqrx remote & bookmarks, not really sure what this could be used for
- limesdr_rfid
- limesdr_toolbox
- does stratux offer more?
- lime-tools, plotting could be repurposed, LTE detector didn't pick anything up
- AltiWx
- WWVB/WWV
- trunk-recorder
- signal-server
- GPS-SDR-SIM, bladeGPS, limeGPS, gnss-sdr, pluto-gps-sim
- hacktv
- FLEX, sdr-examples
- fm2text
- wireless m-bus
- BrakTooth attacks
- AIS-catcher
- krackattacks-scripts
- Any in Awesome Bluetooth Security?
- software that uses gpsd like airodump-ng
- whereami or equivalent
- sniff probes (probe requests)
- network mappers, something like BruteShark
- ez-sniff
- RFQuack, RFCat
- HelicopterDemod, what is this?
- LTE-ciphercheck
- High Quality Spectrum Painting with gr-paint, neat
- gr-reveng
- anything in sdr-examples (argilo)?
- pagers, POCSAG, FLEX, Golay/GSC, gr-mixalot, gr-pocsag
- SiK golay encoding and receiver/transmitter
- Tuning rtl to National Weather Service transmitter 162.400, 162.425, 162.450, 162.475, 162.500, 162.525, 162.550 MHz
- iSniff GPS
- EAPHammer
- TTGO LoRa ESP32 board
- OP25
- DUDE-Star, AMBE3000 based USB devices (ThumbDV, DVstick 30, DVSI, etc.)
- CNN-rtlsdr
- Ubuntu version of LocalRadio
- OpenWebRX, digiham
- qt-dab, seems like a mess
- spectrumzoomer
- Industrial-SMS github
- RF-Vital-Sensing, https://github.com/psharma15/RF-Vital-Sensing
- RF-Monitor
- wifiSpammer
- starlink
- js8call
- gps time synchronization for hams
- csdr for DSP
- are any of the Linux Morse Code programs good? morse, morse2ascii, morsegen, morse-simulator, morse-x
- gr-tempest
- Data Radio Channel (DARC)
- rad1o badge material
- https://hamwaves.com/linux.ham.packages/en/index.html, https://wiki.ubuntu.com/UbuntuHamsPackages
- https://web.archive.org/web/20191204163453/http://radio.linux.org.au/?sectpat=All&ordpat=title
- revisit: https://www.rtl-sdr.com/big-list-rtl-sdr-supported-software/
- WebSDR
- sdrangelove
- dsame
- gr-elster
- gr-atsc3
- MURS, goTenna
- gr-nwr
- gr-ham
- rtl_power_fftw
- pyradiotracking
- glrpt
- libacars
- linhpsdr
- Noaa-apt
- VDLM2DEC
- ACARSDEC, acarsdeco2
- CubicSDR
- dumpvdl2
- gr-iqbal
- hamlib
- PulseEffects
- EchoLink, qtel
- JAERO
- gr-isdbt
- meteor_decoder
- let's hack it NOAA page if it works
- aprs inject with xastir
- horusdemodlib
- Bluetooth-Proximity-Scanner or equivalent
- crackle
- InternalBlue
- Uberducky
- https://www.deepsig.ai/datasets
- OpenSniffer, sewio, Reith notes
- dump1090 offline plotting/mapping. Find a solution or dump coordinates into a cached Google Earth like planeplotter (Windows). Or plot it on an image. modes_rx into offline google earth. Can extract lat/lon and upload to google earth but not sure how to make it look nice or do it continuously.
- gr-satnogs
- opendigitalradio dab receive and transmit
- dshell github
- nRF51822
- hashcat, John the Ripper
- arp-scan, arp-fingerprint, Ethernet
- python-openzwave, pape?
- obtain ESSID of hidden network through deauth like in Kismet or aireplay-ng/airodump-ng combo
- LeanHRPT
- welle.io (dab/dab+)
- guglielmo v0.3
- w_scan_cpp, dvbv5-scan, w-scan (outdated?)
- UVB-76 Buzzer
- geowifi
- subdomain enumeration, dome? so many others...
- any tools from kali/katoolin/katoolin3? https://github.com/s-h-3-l-l/katoolin3/blob/master/katoolin3.py
- Espionage
- Packet Sniffer https://github.com/EONRaider/Packet-Sniffer
- netsniff-ng toolkit
- nmap? rustscan?
- legion
- nikto/nikto2
- credninja
- U.S. pet microchips operate on one of three frequencies: 125 kHz, 128 kHz, and 134.2 kHz. 134.2 kHz microchips are the International Standards Organization (I.S.O.) standard, and are recommended by the AVMA, AAHA, HSUS, and most other major humane organizations.
- nccgroup tools: Sniffle, BLESuite, BLESuite-CLI, BLE-Replay, holepuncher, BLEBoy, Pip3line
- bettercap, beef (update ruby) for airgeddon
- WifiPumpkin, couldn't install properly with 20.04, meant for 18.04
- test SSH DoS exploit
- packet sender
- WEF: Wi-Fi Exploitation Framework
- gamutRF
- osmo nitb
- M17, gr-m17
- nrsc5-dui
- hdfm
- Hobbits, https://github.com/Mahlet-Inc/hobbits
- rx_tools github
- waveconverter
- wavefinder
- Salamandra
- tar1090
- plotsweep
- ubertooth support and operations
- https://github.com/V0rt/pydroneid
- whisper.cpp, audio to text
- https://github.com/josevcm/nfc-laboratory
- direction finding scripts and GUIs, https://github.com/lmicro/hackrf-hunt
- Noise Adder, File Cat'er in Archive tab, open/save tables and file lists
- readsb


## FISSURE Upgrade Ideas

<div id="upgrades"/> 

- Make and test lua dissectors for all demodulation flow graphs and crafted packets
- Create more protocol discovery demodulation flow graphs for new protocols
- Make it an option to FFT shift IQ data
- Wi-Fi, Bluetooth, Zigbee signals in Archive
- Clean up custom gnu radio blocks lesson
- When replacing the log file, remove the extra log files that get produced as well, only the first log file will likely be loaded when parsing the logs. Save one big log file that overwrites itself or choose among multiple log files.
- radiosonde signals
- Search bar
- OS: Debian
- Google Summer of Code? End of January
- SigMF with Archive files
- Radar GUI Line of Sight tool
- Raster subplots. number of rows, time per row
- Move FISSURE Library into a database instead of the YAML
- Mapping and Direction finding for a sensor network, define sensor GPS coordinates, show which sensors pick up the detected data, define a sensor network
- PRI, PD, FM analysis on radar IQ data with a button press
- rtl_power, hackrf_sweep TSI detector
- fuzzing flow graphs still have to be added manually and not with GUI
- more warning/indication if there is something using the radio in another tab. popups? tab colors? button colors? statusbar?
- SDR function generator tools
- Alerts when detecting signals. detector alerts, classifier alerts. Define action (popup messagebox)
- Convert between IQ and wav files
- Hex viewer for Protocol Discovery buffer
- Remove the need to push the start button if operating in manual mode.
- Disable tabs/controls and provide more indication than just the status bar when a component fails
- Indicate the hardware you are using for detection and classification
- Add replay and progress bar for IQ viewer
- Improved attack error handling for flow graph with GUI when imported as flow graph without GUI.
- test DSRC from packet crafter
- Replay DSRC from wireshark capture
- Fine tune the new LimeSDR attacks that do not do as well as the USRPs
- Record DECT video
- Don't require every unused status message in the hiprfisr.yaml. Put in error handling to ignore unknown parsed messages.
- How do you catch the error if top_block.start() fails in the FGE?
- Fill out AntennaComparison spreadsheet. Record antenna results for different types, get models/pictures of antennas, put them on two USRPs a few feet apart and use the antenna test flow graphs, chart what they do every 100 MHz, take a picture of the setup
- folder button for udp_replay attack. Is it ok they are different sizes? Should the smaller one be centered? Leave it alone?
- Why is TSI crashing or showing XX in the statusbar every now and then? Dashboard needs a couple seconds to kill properly otherwise the ports/connections don't release in time?


## Lesson Ideas

<div id="lessons"/> 

- Detecting Signals
- X10
- Z-Wave
- Garage Door
- Clapper Plus
- Morse Code
- ADS-B
- NOAA
- Key fob attacks
