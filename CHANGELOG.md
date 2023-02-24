# Change Log
All notable changes to this project will be documented in this file.

## 2023-02-24

Dataset builder in Archive tab.
 
### Added

- Dataset tab in Archive tab for altering IQ files in a reproducible way
- dataset_builder flow graph for creating altered IQ files

## 2023-02-22

Links to FISSURE Videos.
 
### Added

- YouTube link to FISSURE Videos in Help menu
- Video thumbnails and links in README
- Comment about git submodule command in README
  
### Changed

- idea_list.md content to reflect rejected GSoC status

## 2023-02-19

CRC RevEng and development tools.
 
### Added

- htop to installer and Tools menu
- OpenWebRX to installer and Tools menu for Python3 branches
- guidus, Systemback, Arduino, Geany, QtDesigner, grip, TuneIn Explorer, WSPR Rocks!, wttr.in to Tools menu
- Development and Weather categories to Tools menu
- CRC RevEng to installer
- CRC RevEng algorithms to Protocol Discovery (PD) CRC tab
- Empty Direction Finding tab
- CRC RevEng, htop, OpenWebRX to Credits, About, SoftwareAndConflicts
  
### Changed

- Moved Open-weather link to Weather category in Tools menu

## 2023-02-13

Installer categories and submodule checks.
 
### Added

- Expand All, Collapse All buttons in installer
- Label for the current program being installed
  
### Changed

- Installer now warns if git submodules have not been activated for out-of-tree modules
- Installer software list grouped by categories
- Split apart Video Tools and Audio Tools items in the installer
- Moved QSSTV to Ham Radio menu
- Updated contact instructions in idea list

### Fixed

- rtl_433 install for Python2_maint-3.7 branch

## 2023-02-06

Updating DragonOS FocalX install and adding idea list.
 
### Added

- 2023 Project Idea List
  
### Changed

- Installer image in README
- Links to AIS job opportunity sites

### Fixed

- Added missing escape characters in fissure command install
- Set DragonOS FocalX programs that do not install to be unchecked by default
- Commented out lines in the installer for software that is already installed in DragonOS FocalX 
- Regenerated "instantaneous_frequency_hackrf.py" to stop errors when running from Inspection Flow Graphs tab

## 2023-02-02

Adding DragonOS FocalX (beta) to installer, more links to Tools menu
 
### Added

- Link to IQEngine in the Tools menu
- Link to rfidpics in the Tools menu
- Link to acars.adsbexchange.com in the Tools menu
- Link to Airframes in the Tools menu
- DragonOS FocalX to the installer for Python3\_maint-3.10 branch
- Listed DragonOS FocalX with beta status in README
- Created checks for DragonOS FocalX in the install script for all branches
  
### Changed

- Renamed "Mode S" to "Aircraft" in the Tools menu

## 2023-01-29

New tools and reference material, moving Lessons, fixing installer.
 
### Added

- Meld to installer and Tools menu
- Dire Wolf example in the Tools menu
- hfpropagation.com in the Tools menu
- WaveDrom editor in the Tools menu
- nwdiag/packetdiag in the Installer and Tools menu for Python3 branches
- Git submodule instructions to Built With menu item
- HamClock to installer and Tools menu
- ICE9 Bluetooth Sniffer to installer and Tools Menu
- pocsagtx Standalone Flow Graph
- dump978 to installer and Tools menu
- TODO.md containing a list of potential ideas
  
### Changed

- Repositioned Ham Radio tools in the Tools menu
- Moved Lessons into HTML folder to preserve relative links to images
- Updated About.md, Credits.md, SoftwareAndConflicts.md with the latest tools

### Fixed

- Python3\_maint-3.8 installer fixes: gr-air-modes, pyFDA, SdrGlut, monitor\_rtl433
- Commented out paramiko from RouterSploit install in Python2_maint-3.7 branch
- Reverting rtl\_433 to release 22.11 to avoid installer errors in Python2\_maint-3.7 branch
- Adding libitpp-dev to gr-mixalot install

## 2023-01-25

Adding Dire Wolf, gr-mixalot, systemback, guidus
 
### Added

- Dire Wolf to the installer
- systemback and guidus to Python2 and Python3_maint-3.10 branches
- gr-mixalot submodule and installation for all branches
  
### Changed

- Moved Help HTML files to /Help/HTML to use the same relative path for images in Markdown and HTML files

### Fixed

- Help markdown files now show images when viewed on GitHub
- Python3\_maint-3.10 installer fixes: gr-paint, gr-air-modes, pyFDA, SdrGlut, monitor\_rtl433

## 2023-01-09

Fixing GNU Radio and gr-osmosdr installation.
 
### Added

- gr-osmosdr to HackRF install for Python3-maint_3.10 branch
  
### Changed

- Changed GNU Radio repository to ppa:gnuradio/gnuradio-releases for Python3-maint_3.10 branch
- Changed GNU Radio version to 3.10.5.0-0~gnuradio~jammy-1 for Python3-maint_3.10 branch
- Changed GNU Radio repository to ppa:gnuradio/gnuradio-releases-3.8 for Python3-maint_3.8 branch
- Changed GNU Radio repository to ppa:gnuradio/gnuradio-releases-3.7 for Python2-maint_3.7 branch
- Clarified "U.S." at the end of the README

### Fixed

- Osmocom blocks should work for HackRF flow graphs. Soapy HackRF block was producing a bad output.

## 2023-01-08

Creating bootable USBs, copying FM attacks, README updates
 
### Added

- Lesson12: Creating Bootable USBs
- "From Wav File" attacks for USRP B2x0, B20xmini, HackRF, bladeRF 2.0
- Logo to README
- "Inspection Flow Graphs" Help menu item
- Help Menu items in README
- Videos section in README
- "Interested In Working For AIS?" section in README
  
### Changed

- Added audio rate variable to "FM Radio - From Wav File" attacks
- Roadmap items in README
- Renamed "Uploading Flow Graphs" and "Uploading Python Scripts" to "Attack Flow Graphs" and "Attack Python Scripts"
- Updated "Attack Flow Graphs" and "Attack Python Scripts" Help Menu items
- Updated "Built With" Help Menu item with Python3 code
- Inserted QtDesigner image in "Modifying Dashboard" Help Menu item
- Inserted QtDesigner image in "Adding Custom Options" Help Menu item
- Moved Ubuntu 22.04 out of beta category in README
- Updated "Software and Conflicts" for 22.04 Kismet
 
### Fixed

- Kismet installation for Python3_maint-3.10 branch

## 2022-12-27

Additional support for USRP X300, B200, and B200mini.
 
### Added

- More support for X300, B200, B200mini
- Bootable USB software to the installer (systemback, guidus) for Python3_maint-3.8 branch
  
### Changed

- References to "USRP X310" to "USRP X3x0"
- References to "USRP B210" to "USRP B2x0"
- References to "USRP B205mini" to "USRP B20xmini"
 
### Fixed

- Hardware Guess button for USRP B200
- Hardware Guess button for USRP B200mini
- Fixed Detector Start button error on System stop for Python3_maint-3.10 branch

## 2022-12-21

Fixing IQ Playback tab.
 
### Fixed

- Playback tab no longer pulls the wrong values from the table cell widgets
- Removed CRC reverse lookup print statements
- Upgrading scipy during install to avoid import errors for Python3_maint-3.8 branch
- Adjusted USRP B210/B205mini, HackRF frequency limits

## 2022-12-19

Fixing CRC reverse lookup.
 
### Added

- Added link to cryptii.com in the menu
  
### Changed

- Adjusted gr-paint converter command to flip the image
 
### Fixed

- CRC reverse lookup now allows for lowercase hex characters
- Repositioned IQ viewer toolbar in Python2_maint-3.7 branch

## 2022-12-12

Adding RTLSDR Soapy blocks and hardware parameter limits.
 
### Added

- Gain and frequency spin boxes in IQ Record tab
- Sample rate combo box in IQ Record tab for RTL2832U
  
### Changed

- Python3_maint-3.10 RTL2832U flow graphs now use Soapy RTLSDR blocks and sample rates
- RTL2832U TSI wideband detector sample rate defaults
- RTL2832U "FM Radio - Audio Sink" attack adjusted for variable sample rate
 
### Fixed

- Addressed rgb/rgba warnings in dashboard.ui
- RTL2832U Inspection flow graphs had an incorrect sample rate option for 0.5 MS/s
- RTL2832U frequency ranges for Inspection flow graphs adjusted to 64-1700 MHz
- Replaced Standalone flow graphs with latest examples from gr-rds for Python3_maint-3.10 branch

## 2022-12-04

Program size estimates for install.
 
### Added

- The difference in hard drive space before and after the install is listed for programs. This was calculated from a single install with every box checked so pieces may be partially installed from previous checkboxes.
- Rankings button in the installer to display the top 30 largest programs and estimate the total size for a full install.
- 20.04.5 to the Python3_maint-3.8 installer. Performs the same install as 20.04.4 until differences are found.
   
### Changed

- README and images to show Ubuntu 20.04.5 and file size estimates for installer
 
### Fixed

- gr-bluetooth installation errors for Python3_maint-3.8 branch
- SdrGlut installation errors

## 2022-12-01

Updating IQ Data functions, adding filtering.
 
### Added

- Absolute Value, Differential, Keep 1 in 2 buttons, Unwrap, and Phase buttons in IQ Data tab
- Lowpass and bandpass filtering capabilities in IQ Data tab
- Clicking Start label sets the text edit value to 1 in IQ Data tab Plot frame
   
### Changed

- Removed IF2 button from IQ Data tab
- Resized and moved buttons in IQ Data tab
- Removed FFT sample rate from options dialog
- IQ Data functions/buttons apply to data in the window instead of reloading the IQ file, must plot again to reset
- Morse Code button is applied to data in the window
- Updated iq.png in README
 
### Fixed

- Archive download not storing IQ files correctly for filepaths containing spaces
- Instantaneous frequency calculation in IQ Data tab

## 2022-11-28

Correcting SigMF formatting issues.
 
### Added

- Comment with fix in SdrGlut install for potential libliquid.a errors in Python3_maint-3.10 branch
- Link to Amateur Satellite Database in Tools menu
   
### Changed

- Adjusted sigmf_test.sigmf-meta with "annotations" and "captures" corrections
 
### Fixed

- Adding empty "annotations" array/list to SigMF JSON
- Putting "captures" dictionary values into an array/list in the SigMF JSON

## 2022-11-27

SigMF recording and other functionality.
 
### Added

- Guess X310 daughterboards on multiple clicks within Hardware buttons
- Inspectrum button in IQ Data tab
- Morse Code Translator link in the Tools menu
- SigMF configuration for recording IQ files
- SigMF metadata file viewing
- SigMF frequency and sample rate parsing on IQ file load
- PSK Reporter link to Ham Radio Tools
   
### Changed

- Resized IQ Record table
 
### Fixed

- Updated error handling for opening an IQ file with Gqrx

## 2022-11-20

Adding Inspection file source flow graphs.
 
### Added

- IQ Inspection View buttons to open flow graphs in GNU Radio Companion
- IQ Inspection File flow graphs and controls to start/stop inspection flow graphs with file sources
- Link to triq.org in the menu
- pyFDA menu item to Python3 branches
   
### Changed

- Removed Rebuild checkbox in Inspection flow graphs
 
### Fixed

- gr-dect2 cmake installation error for Python3_maint-3.8

## 2022-11-16

Fixing GNU Radio 3.7.13.5 errors and adding new Detector tab.
 
### Added

- Integrated a modified GNU Radio tutorial example into a new Detector tab for Python2 and Python3_maint-3.8 branches
- Another image showcasing the installer to the README
- Created a block in gr-ainfosec to pass strings over ZMQ PUB without extra bytes
   
### Changed

- Removed unused TSI GUI elements and code in dashboard.py and tsi_component.py
- Adjusted variable default values in TSI flow graphs
 
### Fixed

- Set FE Corrections to True in UHD:USRP Source blocks for Python2 branch to suppress 3.7.13.5 errors
- Replaced correlate acces code blocks with newer versions in Python2 branch to work with 3.7.13.5
- Renamed TSI Sweep detector for USRP N2xx
- TSI detector plot points colormap scaled to 1 (instead of 255) to map properly for Python3 branches

## 2022-11-06

Adding tools to help with GRCon22 CTF challenges and changing how inspection flow graphs are called.
 
### Added

- QSSTV to install and menu
- m17-cxx-demod to install and menu for Python3 branches
- multimon-ng example command for POCSAG in Tools menu
- Fldigi to installer and menu
- Generic frequency translating standalone flow graph
   
### Changed

- Inspection flow graphs show GNU Radio parameter blocks
- Can edit values in inspection flow graph table
- GRCon22 video link in README
- Removed tools from IQ Data Inspection tab and added future space for running flow graphs on selected IQ files
 
### Fixed

- Inspection flow graphs loaded whatever was selected in the listbox instead of what was loaded in the table
- Inspection flow graphs can have channel, serial, and IP address values updated before runtime
- Added libpulse-dev to multimon-ng install

## 2022-10-30

Updating install to avoid potential errors.
 
### Added

- List widget, progress bar examples in Modifying Dashboard Help
- tpms_rx to the Tools menu of Python3_maint-3.10 branch
   
### Changed

- Updated About page with the latest credits
 
### Fixed

- Switched rtl-sdr.git address to https
- Updated install verification method for OOT modules to check for folders. Previously showed failures following the first instance of installing GNU Radio due to the Python paths not getting sourced in a running Python program.

## 2022-10-24

Adjusting install for RTL devices, adding links to lessons, and modifying README. Still need to replace RTL blocks with SoapySDR blocks in Python3_maint-3.10 branch flow graphs.
 
### Added

- Programming SDRs with GNU Radio link in Lessons
- Learn SDR link in Lessons
- Hack Chat Transcript link in README
   
### Changed

- Created links to FISSURE lessons in README
 
### Fixed

- Added gr-osmosdr install from source for Python3 branches so RTL-SDR blocks work for newer GNU Radio versions, but kept `sudo apt-get install -y gr-osmosdr` to avoid errors for now
- Added rtl-sdr install before gr-osmocom and rtl blacklist rules to get RTL devices working for the latest GNU Radio and gr-osmocom versions

## 2022-10-09

Updating GNU Radio and HackRF versions. Integrating a few more links, tools, and fixes.
 
### Added

- Software Defined Radio with HackRF in Lessons menu
- GNU Radio Tutorials in Lessons menu
- Sample rate and frequency edit boxes for IQ data
- Gqrx IQ data button for loading a file into Gqrx when sample rate and frequency is supplied
- SigDigger to installer, menu, CREDITS.md, SoftwareAndConflicts for Python3 branches (Python2 branch avoids PyQt5 programs)
- ham2mon for Python3 branches in installer, menu, CREDITS.md, SoftwareAndConflicts
- Links in README to GRCon22 slides, paper, video and AIS page
- HackRF to CREDITS.md and SoftwareAndConflicts
   
### Changed

- Moved PySDR menu item to Lessons menu
- Updated GNU Radio versions for each branch (3.7.11.0->3.7.13.5, 3.8.1.0->3.8.5.0, 3.10.1.1->3.10.4.0)
- Updated SoftwareAndConflicts help page with GNU Radio versions
- Removed old copy of HackRF release, downloading the latest as part of the install
- Edited Updating HackRF Firmware instructions in the help menu
 
### Fixed

- Launch Wireshark button in the Sniffer tab did not work for Python3 branches
- Added python-qwt5-qt4 to installer for enabling GNU Radio Filter Design Tool in Python2 branch
- Added RX1 antenna option for X3xx devices with TwinRX daughterboards to: TSI Wideband Detector settings, IQ Record settings
- Added pkg-config to HackRF install to fix cmake errors for Python2 branch
- Removed duplicate code in GNU Radio install for Python3_maint-3.8 branch

## 2022-09-25

Disabling IIO-Oscilloscope for Python2_maint-3.7 branch.
   
### Changed

- Disabled IIO-Oscilloscope for Python2_maint-3.7 due to its failure to install

## 2022-09-23

Adding support for bladeRF 2.0 micro and updating existing bladeRF content.
 
### Added

- bladeRF 2.0 micro support (Dashboard, Hardware Selection GUI, TSI Detector, Inspection flow graphs, IQ record/playback, Archive playback, adding attacks to library)
- adsb_parser block in gr-ainfosec for Python2_maint-3.7, Python3_maint-3.8 branches
- Added more bladeRF firmware support to the installer for: 40, A4, A9
- Guess button functionality for original bladeRF, serial number passed to flow graphs
- Added bladeRF 2.0 micro to hardware list in README
   
### Changed

- Moved gain variables for osmocom source/sink blocks to IF gain location for bladeRF flow graphs
- Installing bladeRF and gr-osmocom software from source for Python2_maint-3.7 branch to support bladeRF 2.0
- Resized bladeRF probe button window size
 
### Fixed

- Added missing ".py" for USRP N2xx TSI wideband detector name
- Resized hardware selection GUI for Python2_maint-3.7 branch
- Added missing hardware types in combobox for adding new demodulation flow graphs to library
- Changed bladeRF icon from a bladeRF 2.0 image

## 2022-09-18

USRP2 and USRP N2xx support was added but not tested against real devices. Please report any issues.
 
### Added

- USRP2, USRP N2xx support (Dashboard, Hardware Selection GUI, TSI Detector, Inspection flow graphs, IQ record/playback, Archive playback, adding attacks to library)
- Added more USRP daughterboards for hardware selection
   
### Changed

- Removed openHAB as a default option for DragonOS until further examination is completed
- Listed new hardware in the README
 
### Fixed

- Added a missing package in the DragonOS install for Viking

## 2022-09-13

The DragonOS Focal install has only a few more tools that need to be examined.
   
### Changed

- Updated installer for DragonOS Focal with more tools
- Formatted Credits.md
- Updated README with branch information
 
## 2022-09-10

Ubuntu 22.04 and the 3.10 OOT modules have been moved to a new branch: Python3_maint-3.10.
 
### Added

- Python3_maint-3.10 branch with 3.10 flow graphs, OOTs, and submodules
- Discord link to README
- Python3_maint-3.10 installer image to README
- Discord link to Help menu
   
### Changed

- Removed 3.10 OOT modules and submodules from Python3_maint-3.8 branch
- Python3_maint-3.8 installer image in README
- Branch information throughout the README
- Removed Ubuntu 22.04 from Python3_maint-3.8 installer
- Python2_maint-3.7 installer warnings and checks for other operating systems
- Disabled broken 22.04 tools in the Dashboard menu for Python3_maint-3.10 branch
 
### Fixed

- Removed attack history debug messages in Python3_maint-3.8 branch
- Check for KDE neon/Ubuntu 22.04 in the initial install script in Python3_maint-3.8 branch
- Updated commands for 802.11 Monitor Mode Tool for Ubuntu 22.04 in Python3_maint-3.10 branch
- Converted Monitor Mode Tool to Python3/PyQt5 for 3.8, 3.10 branches

## 2022-09-07

The new KDE neon install follows the same steps as Ubuntu 20.04.4. The GUIs look a little wonky due to the differences in Qt.

### Added

- Added KDE Neon (User - 5.25/20.04) option to the installer for the Python3 branch. Will be the same steps as 20.04.4 until a difference is found.

### Fixed

- Modified ESP32 Bluetooth Classic Sniffer installation to work with Wireshark 3.6.5.

## 2022-09-05

Ubuntu 22.04 is still not fully supported. The 3.10 flow graphs need to be integrated and tested. There are also a few issues remaining with the install.

### Changed

- Set installer checkbox defaults to False/unchecked for 22.04 tools that are known to not install properly
 
### Fixed

- "Verify" checks for 22.04 OOTs (Python3 imports)
- Clone command in README was not capitalized (changed fissure to FISSURE)
- PlutoSDR blocks with 'int' errors for Python2 branch
- Grip "Verify" check runs a different command

## 2022-09-04

Run these commands to download the Git submodules for the GNU Radio out-of-tree modules:
```
cd ./FISSURE
git submodule update --init
```
 
### Added

- Submodules to FISSURE repository for most of the out-of-tree modules
- Initial PlutoSDR support:
  - PlutoSDR installation with IIO Oscilloscope
  - ZWAVE PlutoSDR attack for testing
  - PlutoSDR Inspection flow graphs
  - PlutoSDR TSI Detector flow graph
  - PlutoSDR IQ Recording and Playback flow graphs
  - PlutoSDR Archive Playback flow graph
- IIO Oscilloscope and gr-iio to CREDITS.md, SoftwareAndConflicts.md
- IIO Oscilloscope to menu (SDR)
- Fork locations for OOTs to Credits.md
- 3.10 OOTs: gr-ainfosec, gr-fuzzer, gr-bluetooth, gr-limesdr, gr-tpms
   
### Changed

- Inserted command to download submodules (Out-of-Tree Modules) prior to installation in README.md
- Removed OOT modules to replace with submodules
- Made dashboard.py executable
- Moved install location for libbtbb (gr-bluetooth)
- Updated OOT folder names in the installer
 
### Fixed

- Python3 error when adding a new attack to the library
- A couple install issues and some of the missing items with the DragonOS install (not complete yet)
- OOT Versions in Ubuntu 22.04 SoftwareAndConflicts.md

## 2022-08-28

We are grateful to all developers whose software is installed and accessed with FISSURE.

### Added

- CREDITS.md
   
### Changed

- baudline install, removing local software copy
- Bless website in Software list
- Credits section to README
- Credits in About page

## 2022-08-27

DragonOS and Ubuntu 22.04 are still in beta status. They are under development and several features are known to be missing. Several items in the installer might conflict with existing programs or fail to install until the status is removed.
 
### Added

- maint-3.10 out-of-tree modules in Custom Blocks folder and the installer; still missing: gr-ainfosec, gr-fuzzer, gr-bluetooth, gr-limesdr(?)
- Ask to proceed before installing PyQt4/5 and other programs with the first installer program
- DragonOS Focal install option, software items are still being tested, check back later for a full verified list
   
### Changed

- SoftwareAndConflicts 22.04 OOT status
- README to expand on beta status for operating systems
 
### Fixed

- Updated Python2 branch to the latest gr-tpms_poore for better error handling
- Fixed 20.04 variable for Enscribe in 22.04 section of the installer

## 2022-08-25
 
### Added

- LTE-ciphercheck in installer, menu, software list, example ciphercheck.conf copied from Tools folder during install
- unihedron Electromagnetic Radiation Spectrum Poster v2 in menu
 
### Fixed

- Attack/Fuzzing Apply buttons were causing errors when adding entries to Attack History for the Python3 branch
- Link in README for Discussions and Issues pages
- Commented out `drb_config = drb.conf` in enb.conf for srsRAN in Python2 branch

## 2022-08-21

Impacts the Dashboard, Hardware Select UI, and flow graph library.
 
### Added

- Shortcut to Open-weather.community in the Tools Menu
- Serial number option for HackRFs in flow graphs (does not work with Inspection flow graphs) and Hardware Select UI, added Guess and Probe button functionality
   
### Changed

- Updated the Tab Help to better reflect all the tabs
- Serial number variable to HackRF flow graphs, requires `"hackrf=" + str(serial)` in source/sink blocks
- Hardware Selection UI width to show longer serial numbers and interface names
 
## 2022-08-15

Pull the latest *dashboard.py* to access future archive IQ files at a new address (https://fissure.ainfosec.com).
 
### Added

- CHANGELOG.md file
- Standalone flow graphs for generating J2497 signals with gr-j2497
- *Enscribe* to installer, menu, and Supported Software 
   
### Changed

- Archive file location moved to https://fissure.ainfosec.com
 
### Fixed

- Packet Crafter "Open" button was looking for a "Custom" protocol to populate. Now it only fills in the "Constructed Sequence" text edit box.

