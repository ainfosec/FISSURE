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


TSI Tab
=======


PD Tab
======


Attack Tab
==========


IQ Data Tab
===========

Packet Crafter Tab
==================

Archive Tab
===========


Library Tab
===========

Log Tab
=======

Status Bar
==========







