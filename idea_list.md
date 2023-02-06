# 2023 Project Ideas

AIS has mentored projects in the Google Summer of Code program for several years by partnering with organizations that have championed open source software. This year we will apply to be our own mentor organization with the hopes of supporting FISSURE and some of our other open source projects for years to come. We will update this page and the README upon learning if we are accepted to the program. For now, only consider the ideas until the list of accepted mentoring organizations is published February 22, 2023. Whether we are accepted or not, please consider taking on these project ideas to become familiar with the technology and to gain experience with open source software.

This list of project ideas are suggestions only. Contact the developers if you have additional ideas for yourself or others.

### Project Idea List

1. [PyQt GUI Development](#pyqt_gui_development)
2. [Capture-the-Flag Design](#ctf_design)
3. [Signal Detection Methods](#signal_detection)
4. [Signal Conditioning Methods](#signal_conditioning)
5. [Feature Extraction Methods](#feature_extraction)
6. [Signal Classification](#signal_classification)
7. [Recursive Demodulation Mechanisms](#recursive_demodulation)
8. [Bitstream Analysis](#bitstream_analysis)
9. [Protocol Integration](#protocol_integration)
10. [Lesson Material](#lesson_material)
11. [Tool Research](#tool_research)
12. [Database Creation](#database_creation)
13. [Plugin Support](#plugin_support)
14. [Grouping Capabilities](#grouping_capabilities)
15. [Roadmap Items/Other](#roadmap_items)

---

<div id="pyqt_gui_development"/>   

### 1. PyQt GUI Development

**Summary:** Improve the look and feel of FISSURE through customization and upgrades to the user interface.  
**Mentor:**  Chris Poore  
**Backup Mentor:** Eric Thayer  
**Skills Required:** Python, PyQt, CSS  
**Expected Size:** 175h  
**Level of Difficulty:** Medium  
**Expected Outcome:** Dark mode support, resizing support, support for more screen resolutions, better status depictions, improved GUI elements for plotting and data visualization   

**Description:**  
The FISSURE Dashboard is written in PyQt4/5 and lacks many features that would improve user experience. Stylesheets are applied to individual elements in the .ui files. Updates are needed to change values programmatically to support new styling options like dark mode. Considerations have not been made thus far to account for resizing windows or running under different screen resolutions. Status messsages and alerts to the user need to be upgraded to increase usability and reduce conflicts between components sharing the same hardware. The matplotlib plots need to be improved upon to display data better for the TSI and IQ Data tabs.

---

<div id="ctf_design"/>   

### 2. Capture-the-Flag (CTF) Design

**Summary:** Test CTF software and construct challenges utilizing FISSURE for remote participants.  
**Mentor:**  Chris Poore  
**Backup Mentor:** Eric Thayer  
**Skills Required:** Python, RF Knowledge, CTF Experience  
**Expected Size:** 175h  
**Level of Difficulty:** Easy  
**Expected Outcome:**  Steps for hosting a remote CTF, lists of challenges, methods to access signal data  

**Description:**  
An in-person FISSURE CTF was trialed in December 2022 and the lessons learned can be used to familiarize more people with FISSURE. The creation of a 100% remote CTF is needed to showcase all that FISSURE can do to a much larger audience. Popular CTF software like CTFd needs to be researched and tested to support an event towards the end of 2023. Past in-person challenges must be retrofitted for remote participation. New challenges are desired to showcase all the features of FISSURE. Methods for streaming or presenting IQ signal files for download will need to be investigated. 

---

<div id="signal_detection"/>   

### 3. Signal Detection Methods

**Summary:** Research and integrate new signal detection methods for FISSURE.  
**Mentor:**  Chris Poore  
**Backup Mentor:** Eric Thayer  
**Skills Required:** Python, C++, Software-Defined Radios, Digital Signal Processing  
**Expected Size:** 175h  
**Level of Difficulty:** Hard  
**Expected Outcome:** GNU Radio flow graphs, hackrf_sweep visualizations, direction finding tools, results summarization  

**Description:**  
FISSURE is equipped with slow-scanning and fixed-frequency detectors as part of its Target Signal Identification tab. Additional methods such as a fast-scanner using *hackrf_sweep* or *rtl_power* are desired. Additional techniques beyond a simple amplitude threshold can be utilized to filter out certain types of signals based on user input. Alternative target location approaches such as direction finding or tracking can also be developed. The results of the initial signal detection need to feed into other FISSURE components in the form of signals of interest or to tune the signal conditioner to a set of frequencies. Detection results and summarization need to be presented in a better manner to the user.

---

<div id="signal_conditioning"/>   

### 4. Signal Conditioning Methods

**Summary:** Improve upon methods for automatically isolating signals from large streams of raw IQ data.  
**Mentor:**  Chris Poore  
**Backup Mentor:** Eric Thayer  
**Skills Required:** Python, C++, Software-Defined Radios, Digital Signal Processing  
**Expected Size:** 175h  
**Level of Difficulty:** Hard  
**Expected Outcome:** User-selected techniques, configurable options, automated filtering, IQ data files with isolated signals  

**Description:**  
The Signal Conditioner offers techniques to the user to isolate signals from large streams of IQ data – whether that is from a file, a folder, or a running SDR. Given a set of parameters for any user-provided isolation technique, the Signal Conditioner will output individual files containing either a single burst or snippet of a signal. The signals present in the streams can be filtered or separated from each other to improve quality and provide input for the Feature Extractor and Signal Conditioner. Advanced techniques in filtering, edge detection, blind signal separation are desired as additional options to the user.

---

<div id="feature_extraction"/>   

### 5. Feature Extraction Methods

**Summary:**  Research signal parameters to be used in conjunction with AI/ML techniques for protocol and emitter classification. Create algorithms to extract feature sets from conditioned IQ data.    
**Mentor:**  Chris Poore  
**Backup Mentor:** Eric Thayer  
**Skills Required:** Python, C++, Software-Defined Radios, Digital Signal Processing, AI/ML  
**Expected Size:** 175h    
**Level of Difficulty:** Hard  
**Expected Outcome:** Feature extractions algorithms, feature extraction methods enabled via checkboxes, visualizations of results for multiple input signals  

**Description:**  
The Feature Extractor loops through a folder of isolated signals and extracts various time and frequency measurements selected by the user. Preset options for feature sets are assigned to specific methods found in the Signal Classifier or they can be customized to any combination selected by the user. New features/measurements and algorithms to extract those features are requested to improve upon the analysis of the data and further the development of AI/ML techniques for classification of emitters and protocols. Choosing optimal features sets for different signal environments can also be researched.

---

<div id="signal_classification"/>   

### 6. Signal Classification

**Summary:**  Research and implement AI/ML techniques for protocol and emitter classification.  
**Mentor:**  Chris Poore  
**Backup Mentor:** Eric Thayer  
**Skills Required:** Python, C++, Digital Signal Processing, AI/ML  
**Expected Size:** 175h  
**Level of Difficulty:** Hard  
**Expected Outcome:** AI/ML classification algorithms, training data, models, confidence levels  

**Description:**  
The Signal Classifier offers AI/ML methods for classifying protocols and emitters using signal feature sets provided by the Feature Extractor. Techniques such as decision tree or deep neural networks can be customized and compared against each other. Given a limited set of training data, new techniques and models are desired to improve classification. The classification results need to be fed into other FISSURE components to expedite the processing of signals belonging to known or unknown protocols.

---

<div id="recursive_demodulation"/>   

### 7. Recursive Demodulation Mechanisms

**Summary:**  Given a list of parameters for signals of interest, continuously launch scripts to identify the missing details needed for demodulation until a bitstream can be produced.  
**Mentor:**  Chris Poore  
**Backup Mentor:** Eric Thayer  
**Skills Required:** Python, C++, Software-Defined Radios, GNU Radio  
**Expected Size:** 175h  
**Level of Difficulty:** Hard  
**Expected Outcome:** Algorithms to extract signal parameters and protocol information, decision tree for executing scripts, confidence levels, bitstreams for known and unknown RF protocols  

**Description:**  
The Protocol Discovery component is designed to help identify and reverse unknown RF protocols. Provided with signal of interest information, the component will demodulate signals to a bitstream that gets inserted into a circular buffer. Pieces are missing to evaluate unknown signals. The ability to automatically set flow graph variables and load specific flow graphs based on measurements is desired. An example could be detecting/assuming FM modulation, measuring frequency deviation and baud rate, applying Manchester decoding, and scanning the remaining bits for messages fields such as preambles or CRCs. This is also an area where AI/ML techniques can inserted into FISSURE. A decision tree for loading flow graphs and progress visualization is needed to help the user. 

---

<div id="bitstream_analysis"/>   

### 8. Bitstream Analysis

**Summary:** Research and develop techniques for analyzing a bitstream to detect patterns, encryption, scrambling, encoding, message fields, and protocols.  
**Mentor:**  Chris Poore  
**Backup Mentor:** Eric Thayer  
**Skills Required:** Python, Digital Communications  
**Expected Size:** 175h  
**Level of Difficulty:** Hard  
**Expected Outcome:** User-selectable techniques to apply against streams of input data, protocol identification confidence levels   

**Description:**   
The Protocol Discovery component currently performs limited operations on a circular buffer of demodulated bits. It looks for preambles and then slices fixed-length messages for further evaluation. There needs to be more types of analysis that can work against variable-length messages. This can be in the form of more advanced pattern analysis or detecting/reversing encryption, scrambling, and encoding. There also needs to be a mechanism to compare message bits to protocol information already stored in the FISSURE library to help identify protocols with different levels of confidence. Status information for analysis progress and confidence levels needs to be inserted into FISSURE to aid the user.

---

<div id="protocol_integration"/>   

### 9. Protocol Integration

**Summary:**  Choose RF protocols and targets of interest and integrate the following into FISSURE: signal parameters, demodulation flow graphs, attack scripts, message types, fuzzing attacks, Wireshark dissectors, lesson material, IQ recordings, etc.  
**Mentor:**  Chris Poore  
**Backup Mentor:** Eric Thayer  
**Skills Required:** Python, C++, GNU Radio, Wireshark  
**Expected Size:** 175h  
**Level of Difficulty:** Medium  
**Expected Outcome:**  Understanding of a new RF protocol, integration into the FISSURE library, support for all possible FISSURE hardware/SDRs  

**Description:**  
FISSURE contains a library of RF protocol information that allows users to quickly recall techniques and visualizations that have been proven to be accurate and reliable. A limited number of RF protocols are currently integrated into the framework. FISSURE contains a list of hundreds of RF protocols that have yet be evaluated. Candidates can suggest their own RF protocol/application of interest or be provided with one. It is expected they will work with a physical device and capture, analyze, demodulate, and modulate signals for that protocol. Message structure and target behavior will be evaluated to aid in developing attacks. A description of the protocol and the generation of lesson material is desired along with knowledge of any existing tools for working with the protocol.

---

<div id="lesson_material"/>   

### 10. Lesson Material

**Summary:** Choose a topic related to RF or reverse engineering that would benefit others and create lesson material that involves FISSURE.  
**Mentor:**  Chris Poore  
**Backup Mentor:** Eric Thayer  
**Skills Required:** RF/Reverse Engineering Interests, Linux  
**Expected Size:** 175h  
**Level of Difficulty:** Easy  
**Expected Outcome:** New FISSURE lessons, background information, detailed steps and instructions  

**Description:**  
FISSURE contains lesson material with background information and examples for a wide range of topics. These lessons need to be improved and expanded upon as FISSURE develops more capabilities. There are several topics that can be added that would help those who are new to certain technical areas. One day, students/professionals will use FISSURE in a classroom setting and these lessons could go towards the making of a curriculum. Lessons are written in markdown, converted to HTML, and added to the FISSURE menu.

---

<div id="tool_research"/>   

### 11. Tool Research

**Summary:** Research the latest open source tools for RF, signals, data, reverse engineering, and integrate examples of their usage into FISSURE.  
**Mentor:**  Chris Poore  
**Backup Mentor:** Eric Thayer  
**Skills Required:** Python, Linux  
**Expected Size:** 175h  
**Level of Difficulty:** Easy  
**Expected Outcome:** Summary of popular items, tool installation steps, menu items to launch or show command line examples, updated FISSURE installation scripts, author credits  

**Description:**  
FISSURE contains many methods for working with RF, data, and reverse engineering. However, there are cases where it is helpful to use third-party tools that are proven and trusted in the community. These tools may offer better visualization and provide more information than FISSURE. They are also helpful in verifying, understanding, and developing new capabilities for FISSURE. New tools are sought for integration into FISSURE via the installation scripts, menus, attacks, and lesson material. A list of potential items can be provided or research can be done to see what is frequently used by the community.

---

<div id="database_creation"/>   

### 12. Database Creation

**Summary:** Research the best options for transitioning the FISSURE library from a YAML file to a database. Replace existing library functions with database commands.  
**Mentor:**  Chris Poore  
**Backup Mentor:** Eric Thayer  
**Skills Required:** Python, Database Experience  
**Expected Size:** 175h  
**Level of Difficulty:** Medium  
**Expected Outcome:** Database selection reasoning, installation steps, library functions, test procedure and verification  

**Description:**  
FISSURE contains all of its stored library information in the *library.yaml* file. As the library grows and more types of information must be stored, it makes sense to use a database for accessing and searching information. This task encompasses database research, installation, creation, and rewriting existing functions for interacting with the FISSURE library.

---

<div id="plugin_support"/>   

### 13. Plugin Support

**Summary:** Upgrade FISSURE to accept plugins/add-ons containing select protocol and library information to be used outside of a standard installation.  
**Mentor:**  Chris Poore  
**Backup Mentor:** Eric Thayer  
**Skills Required:** Python  
**Expected Size:** 175h  
**Level of Difficulty:** Easy  
**Expected Outcome:** A standard format for plugins; example plugins; controls to enable/disable, import/export plugins   

**Description:**  
The library information for FISSURE is highly modular and is stored across several dictionaries in a YAML file. There is a desire to create plugins/add-ons to help integrate solutions developed by other contributors. This may be done to protect data privacy or help with integration into other platforms. The format and information contained within a plugin needs to be defined along with a mechanism for loading it with the rest of the library.

<div id="grouping_capabilities"/>   

---

### 14. Grouping Capabilities

**Summary:** Identify capabilities included in FISSURE and third-party tools to group them by categories like supported hardware and protocol.  
**Mentor:**  Chris Poore  
**Backup Mentor:** Eric Thayer  
**Skills Required:** Linux, RF Background  
**Expected Size:** 175h  
**Level of Difficulty:** Medium  
**Expected Outcome:** Updated documentation; organized lists of material for new users containing protocol information, attacks, tools, lessons; marketing material  

**Description:**  
FISSURE contains help material that lists installed software programs, instructions for modifying FISSURE, protocol information, and more. However, there is limited material available to users to know where to go to use their SDRs for the first time or a single document that summarizes all capabilities for the different RF protocols included in FISSURE. The user must manually go through FISSURE and examine the list of tools, standalone flow graphs, attacks, demodulation flow graphs, packet types, etc. A document that summarizes FISSURE capabilities and guides new users towards them is requested.

---

<div id="roadmap_items"/> 

### 15. Roadmap Items/Other

**Summary:** Choose any roadmap item not already covered or present your own ideas.  
**Mentor:**  Chris Poore  
**Backup Mentor:** Eric Thayer  
**Skills Required:** TBD  
**Expected Size:** 175h or 350h  
**Level of Difficulty:** Easy/Medium/Hard  
**Expected Outcome:** Detailed plan, status updates, new features, summary of results  

**Description:**  
Roadmap items are listed in the README and are grouped in phases. Participants may choose a roadmap item of interest as long it is feasible to accomplish within the allocated time period. Additionally, any topic of interest that is not included in this idea list can be proposed and discussed for relevance to FISSURE. 
