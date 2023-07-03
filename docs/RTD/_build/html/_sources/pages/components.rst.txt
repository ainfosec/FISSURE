==========
Components
==========

FISSURE is a tool suite and RF framework consisting of dedicated Python components networked together for the purpose of RF device assessment and vulnerability analysis.

Overview
========

FISSURE stemmed from the need to quickly identify and react to unknown devices or devices operating in unidentified modes in a congested RF environment. Over the years it has grown into an in-house laboratory tool used by AIS for nearly all things RF.

Communications
--------------

The major components for FISSURE are written in Python/PyQt and communicate over an IP network to a central hub using ZeroMQ. Each component has a direct connection to the hub but can also have an unlimited number of one-to-many connections to broadcast status messages to other components. Any number of custom components can be added to the framework as long as the inputs/outputs are clearly defined in YAML and adhere to a simple message schema that allows for input sanitization and error handling.

Library
-------

Library utilities for browsing; searching; uploading images; adding/removing modulation types, packet types, signals of interest, statistics, demodulation flow graphs, and attacks.

File Structure
--------------



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
    sdfdsfsd

Flow Graph Library/Archive Flow Graphs/
    sdfdsfsd

Flow Graph Library/Fuzzing Flow Graphs/
    sdfdsfsd

Flow Graph Library/Inspection Flow Graphs/
    sdfdsfsd

Flow Graph Library/IQ Flow Graphs/
    sdfdsfsd

Flow Graph Library/PD Flow Graphs/
    sdfdsfsd

Flow Graph Library/Single-Stage Flow Graphs/
    sdfdsfsd

Flow Graph Library/Sniffer Flow Graphs/
    sdfdsfsd

Flow Graph Library/Standalone Flow Graphs/
    sdfdsfsd

Flow Graph Library/TSI Flow Graphs/   
    sdfdsfsd

Installer/
    sdfdsfsd

IQ Recordings/
    sdfdsfsd

Logs/
    sdfdsfsd

Session Logs/
    sdfdsfsd

Multi-Stage Attack Files/
    sdfdsfsd

Protocol Discovery Data/
    sdfdsfsd

Tools/
    sdfdsfsd

UI/
    sdfdsfsd

UI/Style_Sheets/
    sdfdsfsd

YAML/
    sdfdsfsd

YAML/Library Backups/
    sdfdsfsd

YAML/User Configs/
    sdfdsfsd




Dashboard
=========

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

Flow Graph/Script Executor
==========================

The Flow Graph/Script Executor component runs flow graphs or Python scripts to perform single-stage attacks, multi-stage attacks, fuzzing attacks, IQ recording and playback, live signal inspection/analysis, and transmit playlists of signal data constructed with files downloaded from an online archive.

HIPRFISR
========

The Central Hub receives commands from the User Dashboard to distribute to other components, manages automation and editing of the main library - which contains RF protocol information, script and flow graph mappings, and observation data. 


