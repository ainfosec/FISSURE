# Change Log
All notable changes to this project will be documented in this file.

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

