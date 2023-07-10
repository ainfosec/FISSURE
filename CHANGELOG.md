# Change Log
All notable changes to this project will be documented in this file.

## 2023-07-09

Installer, style, and Kali fixes.
 
### Added

- Check for Kali upon starting Dashboard
- Swapping gnome-terminal commands for qterminal in Kali
- Disabling Kali menu items that fail to install

### Changed

- Disabled radiosonde auto_rx for DragonOS FocalX install

### Fixed

- trackerjacker install
- ice9-bluetooth-sniffer, rehex install for Kali
- ComboBox font color of selected item set properly for Python3 branches
- Dynamic checkboxes set to follow stylesheets

## 2023-07-03

Miscellaneous style updates.
 
### Added

- Custom pushbutton/combobox text color option
- Disabled text color option
- Icon style (light/dark) color option
- Autofill combobox to populate custom color values (light/dark/custom)
- New color defaults to Options dialog

### Changed

- Assigned global combobox styles and removed extra lines for the exceptions
- Selection font and background colors
- Resized data type combobox in IQ Recording table

### Fixed

- Table comboboxes not resizing to the full height
- Table font size styling
- Combobox font color not set to a defined color
- Disabled doublespinbox/spinbox background color
- Removed extra padding in comboboxes
- Restored right align for certain comboxes
- Menu item shortcuts added to top level items
- Missing custom color replacements in the installer
- Added default values in CRC Calculator tab for Python3_maint-3.10 and Python2_maint-3.7 branches
- Constructed Sequence position in Packet Crafter tab for Python2_maint-3.7 branch

## 2023-06-28

Terminals for menu items, Read the Docs test files.
 
### Added

- Documentation section added to README
- Read the Docs test files for Python3_maint-3.10 branch
- Added FISSURE logo to all FISSURE .ui icons

### Changed

- Opening more menu items in terminal with expect script rather than launching them directly
- Removed beta designation in the installer and README from DragonOS FocalX
- Disabling LTE menu items requiring specific srsRAN configurations and locations for DragonOS FocalX

### Fixed

- Changed directory in command for \_slotMenuRdsRx2Clicked() for Python3_maint-3.8 branch

## 2023-06-25

Additional color options.
 
### Added

- Gpick to menu for DragonOS FocalX, disabled wl-color-picker
- Color options for buttons, comboboxes, disabled widgets, and hovered widgets
  
### Changed

- Disabling menu items on Dashboard launch based on operating system

### Fixed

- Set styles for disabled menu items
- Adjusting some single and double quotes to be consistent
- Removing trailing whitespace from main components

## 2023-06-23

DragonOS Focal/FocalX fixes.
 
### Added

- Checks for DragonOS in dashboard.py, fg_executor.py
- Replaced gnome-terminal commands with qterminal for DragonOS
- Added @menu_hover_padding to stylesheets to remove menubar item hover padding for DragonOS
  
### Changed

- ais_rx menu item opens a terminal with an example command instead of executing immediately
- Updated the Online Archive picture in README
- Removed ICE9 Bluetooth Sniffer from DragonOS FocalX install and changed the filepath for running the command

### Fixed

- Fixed wrong branch warning message during the install
- Removed extra line in \_slotMenuQtDesignerOptionsUiClicked()
- Updated DragonOS installer with fix for the expect_script (used to populate a terminal with text)
- Path locations for ais_rx, rds_rx, Iridium Extractor, Iridium Parser, and IridiumLive commands in Python3_maint-3.10 branch
- Executing btclassify.py with Python2
- Removed directory for kal example in the menu for DragonOS
- Replaced evince commands with open command for DragonOS
- Added extra '/' to qFlipper command for DragonOS to prevent extra text in terminal
- Moved default directories for srsRAN commands for DragonOS
- Changed where FalconGUI is called for DragonOS
- Changed where SDRTrunk is called for DragonOS
- Changed Python2 scapy2 version to 2.4.5 to avoid import errors with version 2.5.0

## 2023-06-19

Updating Archive collection functionality.
 
### Added

- Download of IQ collections and files from the FISSURE online archive in the Archive tab
- Filter Archive files by file extension
- Archive Collapse All, New Folder, Folder buttons
  
### Changed

- Updated library.yaml with Archive collection information
- Renamed "Folder" button to "Choose" in Archive tab
- Replaced Archive ListWidget with ListView
- Replaced Archive Collection TableWidget with TableView

### Fixed

- Minor styling changes
- Added missing <tr> to README

## 2023-06-12

Initial X410 support, gr-osmosdr fix, crop exclude, moving files into docs folder.
 
### Added

- Initial USRP X410 support (not tested yet, need examples)
- Exclude checkbox in Crop tab for removing the samples within a range
- Suggested .gitignore file extensions
  
### Changed

- Moved Gallery, Help, Icons, and Lessons folders to docs folder
- Applying style sheets for Python3_maint-3.8 and Python2_maint-3.7 installer dialogs

### Fixed

- Corrected the check for no IP address in TSI Detector tabs
- Minor GUI styling inconsistencies
- Replaced gr-osmosdr with a fork for Python3_maint-3.8 branch to fix osmocom and RTL GNU Radio blocks
- Inserting port value checks

## 2023-05-28

Append tab upgrade, qFlipper, renamed Clip tab, more Archive Dataset Builder buttons.
 
### Added

- Flipper Zero qFlipper in menu and installer for Python3 branches
- Regenerate button for Archive Dataset Builder table to update checkbox values
- Copy button for Archive Dataset Builder to avoid importing the same files over and over
  
### Changed

- Renamed clip tab to strip (to align with Python strip command)
- Clear "x" button for clip tab list widget
- Import multiple files for Append tab
- Remove multiple files for Archive Dataset Builder table

### Fixed

- Error handling for plotting unloaded IQ files in Plot All and Morse Code buttons
- Clip/Strip tab not changing color when changing style sheets

## 2023-05-14

Compile flow graphs option and Clip tab.
 
### Added

- Installer option to compile FISSURE flow graphs with grcc
- IQ Clip button to remove samples from an IQ file before and after a signal
  
### Changed

- Moved gr-ainfosec from Out-of-Tree Modules to Minimum Install category

### Fixed

- Styles for line widgets and list widgets
- Right align for certain comboboxes in Python3 branches

## 2023-05-01

Updating style sheets.
 
### Added

- GHex to the installer and menu
- ComboBox dark icon
- Ubuntu font installation to the install script
  
### Changed

- README with a sentence describing the minimal install items
- Setting font to Ubuntu for style sheets
- Removing default text for QTextEdits in .ui files/Qt Designer so style sheet font takes effect, setting values in init()
- Style sheets to match Python3_maint-3.10 branch style sheets

### Fixed

- Typo in Install UI and README image
- Adding transparent background to light-down-arrow icons for Python3_maint-3.10 branch
- Inserted missing custom color options in Options dialog for Python2_maint-3.7 and Python3_maint-3.8 branches
- IQ viewer button errors for Python2_maint-3.7 branch
- Changed blank sample rate value for FFT to a float from an int

## 2023-04-24

Adding support for Parrot OS and BackBox.
 
### Added

- Parrot OS, BackBox to installer as beta
- Kali software sizes
- Adding fonts-ubuntu to Kali install
  
### Changed

- README install icons and tables
- Unchecking RTLSDR-Airband in Kali install

### Fixed

- Installing VLC with apt-get for Kali

## 2023-04-17

Installer fixes and GUI style changes.
 
### Added

- Matplotlib toolbar icons
  
### Changed

- Manually setting icons for matplotlib toolbar to avoid color inversion
- Changing where the installer checks for DragonOS FocalX version (/etc/os-dragonos)

### Fixed

- Adding missing packages for Kali install: eog, Python2 cryptography, Python2 setuptools, xxd
- Removed freeglut3 for Kali install
- Downloading Anki from source for Kali
- Font color set to black for current program label in the installer
- Background color for inspection flow graph frame in Python3_maint-3.10 branch
- Removed wl-color-picker from DragonOS FocalX install and added Gpick
- Changing QTextEdit borders to avoid undesired scrollbars
- QComboBox padding-left adjusted in style sheets

## 2023-04-08

GUI styling fixes for Python3_maint-3.10 branch.
 
### Added

- Kali 23.1 install option for Python3_maint-3.10 branch (still in beta, needs additional adjustments)
- Random color scheme in menu
- Icons for light color scheme
  
### Changed

- Clicking Sample Rate and Frequency column header in dataset builder table applies first row value to all rows
- Kali 23.1 added to the README

### Fixed

- Frequency shift is no longer disabled in Archive dataset builder table for non-archive IQ files in Python3_maint-3.10 branch
- Applying stylesheets to Installer GUIs
- Inserting some of the missing elements in light mode style sheet
- Improved error handling for empty dataset builder values when start is clicked
- Clicking cancel on Custom Mode color picker keeps previous value instead of #000000
- get_xdata() error handling in dashboard.py to support more matplotlib versions

## 2023-04-03

Updating software sizes and fixing Python3_maint-3.10 installation.
 
### Added

- Solve Crypto with Force/scwf.dima.ninja to Tools Menu
- CrackStation.net to Tools Menu
  
### Changed

- Updated Python3_maint-3.10 software sizes for the installer

### Fixed

- Location of osmo-fl2k.git for fl2k install
- GNU Radio version that gets installed for Python3_maint-3.10 branch
- ESP32 BT Classic Sniffer install for Python3_maint-3.8 branch (Wireshark version is now 4.0.3)

## 2023-03-29

Updating software sizes and fixing Python3_maint-3.8 installation.
 
### Added

- 20.04.6 to the installer and README (same steps as 20.04.4)
  
### Changed

- Updated Python3_maint-3.8 software sizes for the installer
- Commented out gr-osmosdr from source in the installer for Python3_maint-3.8 branch and changed verify command

### Fixed

- ESP32 BT Classic Sniffer install for Python3_maint-3.8 branch (Wireshark version is now 4.0.3)
- radiosonde_auto_rx dependency python3-flask influenced pip through python3-openssl and is now commented out (fixes: sudo apt-get remove python3-openssl or delete /usr/lib/python3/dist-packages/OpenSSL)
- QSpectrumAnalyzer and Universal Radio Hacker install for Python3_maint-3.8 branch as a result of pip being corrupted by python3-flask/python3-openssl (see previous line)

## 2023-03-26

Preparing for Archive collections.
 
### Added

- File and Collection tabs for Archive Download
  
### Changed

- Updated Python2_maint-3.7 software sizes for the installer
- Moved noise source after scaling for dataset builder flow graph

### Fixed

- Added libuhd-dev to ICE9 Bluetooth Sniffer install

## 2023-03-19

Styling changes for Python2_maint-3.7 branch.
 
### Added

- Gpick to the Tools menu and installer for Python2_maint-3.7 and Python3_maint-3.8 branches
- wl-color-picker to the Tools menu and installer for Python3_maint-3.10 branch
- complextoreal.com to the Lessons menu
  
### Changed

- Small GUI style adjustments 

### Fixed

- Wideband detector plot background matches style when plotting points

## 2023-03-13

Styling changes for Python3_maint-3.10 branch.
 
### Added

- Light, Dark, and Custom modes for GUI styling for Python3_maint-3.10 branch

### Fixed

- Correcting PyQt widgets that were not updating colors for different styles for Python3_maint-3.8 branch
- Default widget styles updated to match light mode theme for Python3_maint-3.8 branch

## 2023-03-05

Styling changes for Python3_maint-3.8 branch.
 
### Added

- Light, Dark, and Custom modes for GUI styling for Python3_maint-3.8 branch
- View menu items for changing color modes for Python3_maint-3.8 branch
- light.css, dark.css, and custom.css files for Python3_maint-3.8 branch
- Color variables in options/default.yaml for Python3_maint-3.8 branch
- Truth column to Archive Dataset Builder table
- Dark Mode image to README
  
### Changed

- Removed stylesheets assigned to individual items in .ui files and inserted all styling into .css files for Python3_maint-3.8 branch.
- Stylesheet values for widgets in dashboard.py are pulled from options dialog for Python3_maint-3.8 branch
- Widget object names are used to apply stylesheets for Python3_maint-3.8 branch
- example.csv to match updated Dataset Builder table

### Fixed

- Several miscellaneous GUI adjustments for Python3_maint-3.8 branch
- Checking disabled columns in Dataset Builder table no longer toggles checkboxes

## 2023-02-25

Import/Export for Archive playlists, adding README images.
 
### Added

- Dataset Builder, Online Archive, Third-Party Tools images in README
- RF Reverse Engineering diagram in README
- Import/Export CSV buttons in Archive Replay tab
- Remove All button in Archive Replay tab
  
### Changed

- CRC Calculator image in README
- Name of archive.png to signal_playlists.png in README

### Fixed

- Removing an Archive playlist row keeps the selection at the current row
- Removing an Archive downloaded file keeps the selection at the current row

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

