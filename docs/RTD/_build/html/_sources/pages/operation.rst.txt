=========
Operation
=========

FISSURE is meant for people of all skill levels. Students or beginners can navigate through lessons and tutorials on how to interact with various wireless technologies. The User Dashboard offers friendly visual aids that demonstrate the RF device assessment process from start to finish. Beginners can also evade the hurdle that is traditionally associated with installing open-source tools - as the installer consists of a list of checkboxes for installing programs and dependencies. Meanwhile developers, educators, and researchers can use the framework for their daily tasks or to expose their cutting-edge solutions to a wider audience. Future development will draw heavily from feedback and interaction with the open-source community. 

Start-Up Procedures
===================

1. Open a terminal and enter `fissure`
2. Attach hardware and assign to components using the hardware buttons (see below)
3. Click the "Start" button to kick off automation and access remaining tabs
4. Click the "Start" buttons for individual components such as TSI or PD to trigger operations


Hardware Buttons
----------------

The hardware buttons located at the top of the FISSURE Dashboard assign radio equipment to functionality that can benefit from hardware separation. This includes:

- TSI
- PD
- Attack
- IQ
- Archive

A new dialog will open upon clicking the hardware button. The user must select the supported hardware type and can provide optional serial number, IP address, interface name, or daughterboard information which is used to auto-populate various fields while operating FISSURE. Some features such as IQ recording will remain disabled until the hardware type is assigned.

The "Guess" button will attempt to populate the field information based on the hardware type selected. Clicking the button a second time will cycle through other potential values that may be available.

The "Probe" button will attempt to reach out to the hardware and return information that could be useful in populating the missing fields. Some probe actions may take minutes to perform depending on the hardware type.

Networking Configuration
------------------------

FISSURE was originally designed to run its major Python components on different computers across a network. The network connections were simplified to run every component locally on one computer. Future updates may restore this functionality if the components are matured enough to require simultaneous operation and distributions in processing.

Menu Items
==========

Lessons
-------

Lesson 1
Lesson 2
Online Resources

Standalone Flow Graphs
----------------------

Tools
-----

Options
-------

View
----


Automation Tab
==============

1) Select Automation Mode

Manual
------

User confirms all phases and can edit parameters

Discovery (Disabled)
--------------------

Mostly automated, system chooses which signals to target and process

Target (Disabled)
-----------------

User-defined specifications, only pursue targets fitting certain criteria

1) Select target protocol
2) Configure SOI auto-select criteria (optional)
3) Lock search band (optional)
4) Check RF hardware connections
5) Click Start

Custom (Disabled)
-----------------

1) User creates any combination of settings

TSI Tab
=======

Detector/Sweep
--------------

1) Click Start
2) Add search bands to table
3) Adjust Advanced Settings
4) Click Update TSI Configuration
5) Blacklist frequency ranges
6) View detected signals
7) Search signals by frequency in library

Conditioner (Future)
--------------------

Tune, filter, separate, record, isolate

Feature Extractor (Future)
--------------------------

Select AI/ML technique, acquire feature set

Classifier (Future)
-------------------

Choose AI/ML models, classify protocols/emitters, compare results

PD Tab
======

Status
------

1) Start Protocol Discovery (PD)

Demodulation
------------

1) Search library for flow graphs
2) Start demodulation flow graph

Bit Slicing
-----------

1) Search for preambles
2) Slice buffer by preamble
3) Determine field delineations

Data Viewer
-----------

1) Enter binary or hex data, perform binary operations
2) Fill Protocol Matching table, apply against protocols in library
3) Manually send hex data to PD buffer for analysis

Dissectors
----------

1) Create Lua sissectors for new packet types
2) Follow lesson on Lua dissectors
3) Click Update Wireshark to copy all FISSURE dissectors to Wireshark folder

Sniffer
-------

1) Start demodulation flow graph with sniffer sink
2) Launch sniffer flow graph created for packet type
3) Manually send data to sniffer port

CRC Calculator
--------------

1) Enter hex, select configuration, calculate CRC
2) Enter two messages with known CRCs, find polynomial

Attack Tab
==========

Single-Stage
------------

1) Select protocol, modulation type, hardware combination
2) Double-click attack in tree widget
3) Configure attack variables
4) Start Attack
5) Apply changes while running flow graphs

Multi-Stage
-----------

1) Double-click attack in tree widget or click Add button
2) Adjust durations and reorder attacks
3) Click Generate
4) Adjust variables, Save, Load, select Repeat
5) Click Start

Fuzzing (Fields)
----------------

1) Choose fuzzing Fields attack (if available)
2) Choose protocol subcategory
3) Check fields, select type, enter limits
4) Start Attack

Fuzzing (Variables)
-------------------

1) Choose fuzzing Variables attack
2) Load flow graph
3) Select variable
4) Start Attack

History
-------

1) View attack history, delete rows

IQ Data Tab
===========

Record
------

1) Assign device to IQ hardware button
2) Adjust settings in reference to applicable GNU Radio sinks
3) Record signals to IQ file(s)

Playback
--------

1) Configure settings or copy Record settings
2) Click Play

Inspection
----------

1) Double-click flow graph or click Load, Start
2) Adjust variables in GUI

Crop
----

1) Double-click IQ file in Viewer
2) Enter name for cropped IQ file
3) Adjust Start/End samples in Viewer
4) Click Crop

Convert
-------

1) Choose input file, name output file
2) Select file types
3) Click Convert

Append
------

1) Choose/enter file 1, file 2, output file
2) Check Null to append samples to the front or end
3) Click Append

Transfer
--------

1) Copy folders or files to new locations

Timeslot
--------

Makes copies of a message at regular intervals

1) Choose input file with zeros before and after signal
2) Adjust sample rate, period, and number of copies
3) Click Pad Data

Overlap
-------

1) Plot data, store data, shift data, add data together

Resample
--------

1) Select input file, specify output file, choose rates, resample

OFDM
----

Experimental

Normalize
---------

1) Select input file, speciy output file, choose min/max, normalize

Viewer
------

1) Choose data folder
2) Double-click/Load File to read data
3) Plot All, plot range, click End to detect last sample
4) Use toolbar to zoom, pan, save
5) Click Cursor, select two points on plot, Get Range
6) Use functions and analysis buttons
7) Click gear icon to adjust options

Archive Tab
===========

Download
--------

1) Select row in Online Archive table
2) Click Download
3) Plot or delete

Replay
------

1) Double-click downloaded file or press Add button
2) Build and configure playlist
3) Check Repeat, click Start

Packet Crafter Tab
==================

Packet Editor
-------------

1) Select protocol and packet type
2) Edit field values
3) Calculate CRC (when applicable)
4) Assemble message
5) Construct packet sequence
6) Save sequence to file

Scapy
-----

1) Put wireless interface in monitor mode
2) Select 802.11x and packet type
3) Edit field values
4) Click Load Data
5) Click Refresh, enter interval, choose interface
6) Click Start

Library Tab
===========

Browse
------

1) Choose FISSURE YAML file
2) Look at the contents

Gallery
-------

1) Select protocol
2) Click through pictures

Search
------

1) Enter information for signals of interest (SOIs)
2) Enter data values for messages in library
3) Choose the checkboxes to use during search
4) Search Library

Remove
------

1) Select Protocol
2) Choose types to remove from library
3) Click associated Remove button

Add
---

1) Create new protocol
2) Add modulation type, packet type, signal of interest, statistics, demodulation flow graph, and attacks to existing protocol

Log Tab
=======

System Log
----------

1) Filter messages to view from log, click Refresh

Session Notes
-------------

1) Make notes and save attack history, system log, and session notes

Status Bar
==========







