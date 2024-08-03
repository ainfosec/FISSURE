==========
Components
==========

FISSURE is a tool suite and RF framework consisting of dedicated Python components networked together for the purpose of RF device assessment and vulnerability analysis.

Overview
========

FISSURE stemmed from the need to quickly identify and react to unknown devices or devices operating in unidentified modes in a congested RF environment. Over the years it has grown into an in-house laboratory tool used by AIS for nearly all things RF.

Communications
--------------

(Updates coming soon)

Library
-------

Library utilities for browsing; searching; uploading images; adding/removing modulation types, packet types, signals of interest, statistics, demodulation flow graphs, and attacks.

File Structure
--------------

(Updates coming soon)

::

    FISSURE
    ├── Archive          
    │   ├── Datasets
    │   └── Playlists
    ├── Attack Recordings    
    ├── Crafted Packets
    │   ├── Defaults
    │   └── Scapy
    ├── Custom_Blocks
    │   └── maint-3.x
    │       ├── gr-a...
    │       ├── ...
    │       └── gr-z...        
    ├── Dissectors
    ├── docs
    │   ├── Gallery
    │   ├── Help
    │   ├── Icons
    │   ├── Lessons
    │   └── RTD
    ├── Flow Graph Library
    │   ├── Archive Flow Graphs
    │   ├── Fuzzing Flow Graphs
    │   ├── Inspection Flow Graphs
    │   ├── IQ Flow Graphs
    │   ├── PD Flow Graphs
    │   ├── Single-Stage Flow Graphs
    │   ├── Sniffer Flow Graphs
    │   ├── Standalone Flow Graphs
    │   └── TSI Flow Graphs   
    ├── Installer
    ├── IQ Recordings
    ├── Logs
    │   └── Session Logs
    ├── Multi-Stage Attack Files
    ├── Protocol Discovery Data
    ├── Tools
    ├── UI
    │   └── Style_Sheets
    └── YAML
        ├── Library Backups
        └── User Configs  

Archive/
    Default location for downloading IQ files from the online signal archive.
               
Archive/Datasets/
    Default location for storing generated IQ datasets and .csv files from the Archive Datasets tab.
    
Archive/Playlists/
    Default location for storing signal playlists for the Archive Replay tab.
    
Attack Recordings/
    Default location for storing any recordings produced from attacks.

Crafted Packets/
    Default location for storing packet data from the Packet Crafter tab.

Crafted Packets/Defaults/
    Location for default packet types listed in the Packet Crafter. Used to send data to UDP ports in the Sniffer tab. Not used to populate the Packet Crafter as defaults for packet types are acquired from the FISSURE library.

Crafted Packets/Scapy/
    Location for temporarily storing loaded Scapy data used by the Scapy Injector in the Packet Crafter. 

Custom_Blocks/
    Contains GNU Radio out-of-tree (OOT) modules used by FISSURE. These include git submodules of specific compatible branches from online repositories. Any updates to these branches will be reflected in the contents of this folder. A few OOT modules are not git submodules and reside locally.

Custom_Blocks/maint-3.x/
    Subfolder named after the major version of GNU Radio supported by the current branch.

Dissectors/
    Default location for saving and editing Lua dissectors created by the Protocol Discovery Dissectors tab. Dissector files in this folder get copied to the Wireshark plugins folder during the FISSURE install and after clicking the Update Wireshark button in the Dissectors tab.

docs/
    Contains static files used by FISSURE for display and documentation.

docs/Gallery/
    Location of images of note that can be assigned to a protocol found in the FISSURE library. The image file must begin with the same name as the protocol to be displayed in the Library Gallery tab.

docs/Help/
    Location of FISSURE help pages written in Markdown and HTML. Contents will eventually be folded into this Read the Docs project.

docs/Icons/
    Location of icons used by the FISSURE GUI widgets and README. 

docs/Lessons/
    Location of FISSURE lesson pages written in Markdown and HTML. Contents will eventually be folded into this Read the Docs project.

docs/RTD/
    Contains the HTML and PDF versions of this Read the Docs project. The Python3_maint-3.10 branch of FISSURE contains the files needed to populate and build the project.

Flow Graph Library/
    Contains the flow graphs and Python scripts that are called by the main FISSURE components.

Flow Graph Library/Archive Flow Graphs/
    Location of flow graphs used by the Archive tab for IQ file replay and building datasets from altered IQ files.

Flow Graph Library/Fuzzing Flow Graphs/
    Location of special Attack flow graphs containing Fuzzer blocks that periodically change message contents during transmission.

Flow Graph Library/Inspection Flow Graphs/
    Location of inspection flow graphs used by the IQ Data tab for analyzing signal data sourced from streaming SDRs and file captures ("File" folder). 

Flow Graph Library/IQ Flow Graphs/
    Location of flow graphs used by the IQ Data tab for recording and playback of signals. Contains two types of playback flow graphs: single playback and repeating playback.

Flow Graph Library/PD Flow Graphs/
    Location of flow graphs used by the Protocol Discovery tab for signal analysis and demodulation.

Flow Graph Library/Single-Stage Flow Graphs/
    Location of flow graphs and Python scripts for the single-stage attacks listed in the Attack tab tree widget. Support files for the single-stage attacks are stored in the "Attack Files" folder.

Flow Graph Library/Sniffer Flow Graphs/
    Location of flow graphs that tap into a running Protocol Discovery demodulation flow graph to pass data to a UDP port for Wireshark viewing.

Flow Graph Library/Standalone Flow Graphs/
    Location of flow graphs that are accessed from the Standalone menu. These flow graphs are copies and can be modified without impacting FISSURE or the out-of-tree modules.

Flow Graph Library/TSI Flow Graphs/   
    Location of flow graphs used by the TSI component for slow scanning detection and fixed frequency detection.

Installer/
    Location of the primary FISSURE installation script and its support files. It is called by the "install" bash script after checking for prerequisites.

IQ Recordings/
    Default location for storing IQ files captured with the IQ Data tab recorder. Contains example files for testing purposes.

Logs/
    Default location for event logs saved by FISSURE.

Logs/Session Logs/
    Default location for session logs saved by the user.

Multi-Stage Attack Files/
    Default location for storing multi-stage attack playlists from the Attack Multi-Stage tab.

Protocol Discovery Data/
    Default location for storing data during the process of protocol discovery.

Tools/
    Additional scripts, patches, configuration files, reference material, or standalone programs used to support FISSURE and the installer. These files are generally not modified during the install or while operating FISSURE. Installed third-party tools are located elsewhere in the "~/Installed_by_FISSURE" directory.

UI/
    Default location for PyQt .ui files.

UI/Style_Sheets/
    Default location for FISSURE style sheets which control UI appearance and color schemes.

YAML/
    Location of the FISSURE library, logging configuration, and component messaging definitions and input sanitization.

YAML/Library Backups/
    Location for storing backups and temporary copies of the FISSURE library before performing library operations.

YAML/User Configs/
    Location of default settings for FISSURE including hardware configurations, component networking, and default options.
    
Supported Protocols
-------------------

**Tools, Scripts, FISSURE Library Data**

- 802.11
- ACARS
- Bluetooth
- Clapper Plus (433 MHz)
- DECT
- DSRC
- FM Radio
- Garage Door (Stanley)
- GSM
- J2497
- LTE
- Mode S (ADS-B)
- Morse Code
- Radiosonde
- RDS
- SimpliciTI
- TPMS
- X10
- Z-Wave

**FISSURE Packet Crafter**

- 802.11
- DECT
- DSRC
- Mode S (ADS-B)
- RDS
- SimpliciTI
- TPMS
- X10
- Z-Wave

Dashboard
=========

.. _Dashboard Concepts:

Concepts
--------

The User Dashboard is the means for the operator to configure FISSURE and communicate with and view information from the other components. It offers several other features that do not require their own dedicated component including:
  
- A packet crafter for protocols found the FISSURE library. It includes Scapy integration for transmitting different types of 802.11 packets while in monitor mode.
- Library utilities for browsing; searching; uploading images; adding/removing modulation types, packet types, signals of interest, statistics, demodulation flow graphs, and attacks.
- Menu items for launching standalone GNU Radio flow graphs.
- Third-party and online tools as menu items organized by protocol or application.
- Lessons and tutorials for interacting with various RF protocols.
- Help pages for operation and development, protocol reference material, calculators, and hardware instructions.
- Buttons for: assigning RF-enabled hardware to individual components (USRP B205mini, B210, X300 series; HackRF; bladeRF; LimeSDR; 802.11x Adapters; RTL2832U; Open Sniffer); probing the hardware for diagnostics; and acquiring IP address, daughterboard, and serial number information. 

Communication
-------------


Modification
------------


Target Signal Identification
============================

The Target Signal Identification (TSI) component runs four subcomponents: a detector, a signal conditioner, a feature extractor, and a classifier. 

The Detector subcomponent allows the operator to configure scan parameters for multiple search bands with the goal of reporting the power, frequency, and time of observed signals. 

The Signal Conditioner subcomponent will be responsible for isolating and conditioning signals from a stream of raw I/Q data for more detailed analysis. 

The Feature Extractor subcomponent will accept the conditioned signals and extract a predetermined list of signal characteristics dependent on the AI/ML method chosen for classification. 

The Signal Classifier subcomponent will interpret the feature sets and make specific conclusions such as the confidence levels for protocol and emitter classification. 
   
Protocol Discovery
==================

The Protocol Discovery component is responsible for identifying and reversing RF protocols to help extract meaningful data from unknown signals. It is designed to: accept signal of interest information, iterate flow graphs to perform recursive demodulation techniques, deduce protocol methods, assign confidence levels, analyze a bitstream, calculate CRC polynomials, and create custom Wireshark dissectors.

HIPRFISR
========

The Central Hub receives commands from the User Dashboard to distribute to other components, manages automation and editing of the main library - which contains RF protocol information, script and flow graph mappings, and observation data. 

Sensor Nodes
============

Sensor Node Description
-----------------------

FISSURE transitioned to a sensor node deployment scheme capable of connecting multiple computers with their own radios and peripherals that can be controlled remotely or run autonomously. This will facilitate many geospatial scenarios such as direction finding, tracking, perimeter defense, remote access for employees who need to do RF testing, and providing a global gateway for advanced laboratory environments. The automated scripts combined with lightweight, compact computing options will unlock several more possibilities for subjects like wardriving, warshipping, UAS payloads, and logging/tracking at key locations of interest.

The Sensor Node component is responsible for interacting with the radio peripherals, receiving commands from the Dashboard/HIPRFISR, and returning status messages and data. Sensor nodes consist of the sensor_node.py code running any type on computing hardware. Each sensor node has a copy of the entire FISSURE flow graph library. Sensor nodes can be run remotely or locally on the same computer as the rest of the FISSURE components. Only one local sensor node can be run at a time and up to five remote sensor nodes can be deployed. Actions within the Dashboard tabs will usually only impact one sensor node at a time dictated by selection (through right-clicking) of one of the sensor node buttons at the top of the Dashboard. Additionally, sensor nodes can be configured with autorun playlists (created through the Dashboard) that run scripts independently of the FISSURE Dashboard.

Sensor Node Networking
----------------------

Sensor Node Inner Workings
--------------------------

Upon starting the sensor_node.py file, it reads the default.yaml file and then creates the ZMQ sockets. It continuously enters a loop where it checks for messages from the HIPRFISR and sends heartbeats to the rest of the FISSURE components. If the autorun feature is set to "True" in the sensor node configuration file, it will begin running the default playlist after the specified timeout has been surpassed. Otherwise, the sensor node will be idle and wait for the Dashboard to initiate a playlist. The autorun playlists can be configured to run once or at regular intervals (in seconds).

To take advantage of multiple radio peripherals connected to a sensor node, the autorun playlist items are run in their own threads at the same time. There are two types of playlist items: single-stage and multi-stage. Single-stage items only have one file that is executed. Multi-stage items contain multiple files that are run in succession. For both item types there are options to specify a timeout, to choose whether to repeat the operation if completed before the timeout, and to have a delayed start time.

The sensor node also run commands from the Dashboard beyond the autorun playlists. There are several tabs within the Dashboard that require the user to choose a hardware option among those assigned to the active sensor node. Such examples include: Target Signal Identification detector scripts, Protocol Discovery demodulation flow graphs, Attack scripts, IQ recording, IQ playback, IQ inspection, and Archive playlists. Archive playlists are a more on-demand and simplified solution compared to the autorun playlists.

Sensor Node Config File
-----------------------

The sensor node config file is comprised of sensor node descriptors (nickname, location, notes), autorun settings, networking settings, and default hardware assignments for all the FISSURE components. The user has the option to recall the default hardware assignments upon establishing a connection from the Dashboard and do not impact the sensor_node.py file directly. The following is a sample sensor node configuration file:

.. code-block:: console

    Sensor Node:
        archive:
            0:
                daughterboard: ''
                ip_address: ''
                network_interface: ''
                radio_name: ''
                serial: 30FE2D1
                type: USRP B2x0
                uid: ''
        attack:
            0:
                daughterboard: ''
                ip_address: ''
                network_interface: ''
                radio_name: ''
                serial: 30FE2D1
                type: USRP B2x0
                uid: ''
        autorun: false
        autorun_delay_seconds: 3
        autorun_interval_seconds: 3
        enabled_disabled: enabled
        ip_address: '192.168.1.123'
        iq:
            0:
                daughterboard: ''
                ip_address: ''
                network_interface: ''
                radio_name: ''
                serial: 30FE2D1
                type: USRP B2x0
                uid: ''
        local_remote: remote
        location: fgh
        nickname: Node 1
        notes: fdh
        pd:
            0:
                daughterboard: ''
                ip_address: ''
                network_interface: ''
                radio_name: ''
                serial: 30FE2D1
                type: USRP B2x0
                uid: ''
        msg_port: '5052'
        hb_port: '5051'
        tsi:
            0:
                daughterboard: ''
                ip_address: ''
                network_interface: ''
                radio_name: ''
                serial: 30FE2D1
                type: USRP B2x0
                uid: ''
        console_logging_level: 'INFO'
        file_logging_level: 'DEBUG'

Autorun Playlist Format
-----------------------

Autorun playlists can be imported and exported from the Dashboard. Upon building a new playlist and clicking the "Start" button in the Autorun tab, the table contents will be converted to a dictionary with the same format as those found in the import/export YAML files. Autorun playlist files can be edited outside of the Dashboard in any text editor. The following is an example of an autorun playlist YAML file:

.. code-block:: console

    delay_start: 'False'
    delay_start_time: '2024-07-31 12:26:58'
    repetition_interval_seconds: '-1'
    0:
        delay: 'False'
        details: '[''X10 - Off'', ''X10'', ''OOK'', ''USRP B2x0 - 30AD2E1'', ''/home/user/Videos/testprivaterepo/Flow
            Graph Library/maint-3.8/Single-Stage Flow Graphs/X10_OOK_USRPB210_X10_Off.py'',
            ''Flow Graph'', False]'
        repeat: 'False'
        start_time: '12:30:46'
        timeout_seconds: '5'
        type: Single-Stage
        variable_names: '[''tx_usrp_gain'', ''tx_usrp_frequency'', ''tx_usrp_channel'',
            ''tx_usrp_antenna'', ''string_variables'', ''serial'', ''sample_rate'',
            ''press_repetition_interval'', ''press_duration'', ''data_code'', ''address_code'']'
        variable_values: '[''60'', ''310.8e6'', ''A:A'', ''TX/RX'', ''[address_code,data_code]'',
            ''serial=30AD2E1'', ''1e6'', ''10'', ''4'', ''0x20'', ''0x60'']'
    trigger_values:
    -    - x10_demod.py
        - Python3 Script
        - '[''hardware'', ''matching_text'']'
        - '[''USRP B2x0 - 30AD2E1'', ''Bits: 01100000100111110000000011111111'']'
