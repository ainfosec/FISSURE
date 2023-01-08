# Inspection Flow Graphs

Inspection flow graphs can be added to FISSURE to perform frequently used analysis on live streams from SDRs or directly on prerecorded data files. Flow graph Python files (.py) are called directly with Python2/3 and use the GNU Radio "parameter" block as arguments to the Python call. This enables variables found in blocks that do not utilize callbacks (like IP address or serial number) to be changed prior to runtime. The following are instructions for creating a new inspection flow graph within the _IQ Data>>Inspection_ tab.

![inspection1](./Images/inspection1.png)

## Location

Inspection flow graphs must be placed in the _/FISSURE/Flow Graph Library/Inspection Flow Graphs/_ or _/FISSURE/Flow Graph Library/Inspection Flow Graphs/File/_ directories. Refer to other inspection flow graphs as examples when creating new flow graphs. 

## library.yaml
The names of inspection flow graphs are assigned to Python files within the _library.yaml_ file. Assign names under the applicable hardware type or under "File" if the new flow graph will be used on IQ files. 
```
Inspection Flow Graphs:
     802.11x Adapter:
     - None
     Computer:
     - None
     File:
     - instantaneous_frequency.py
     - signal_envelope.py
     - waterfall.py
     HackRF:
     - instantaneous_frequency_hackrf.py
     - signal_envelope_hackrf.py
     - time_sink_hackrf.py
     - time_sink_1_10_100_hackrf.py
     - waterfall_hackrf.py
```

## GNU Radio

The following are helpful tips for configuring the GNU Radio flow graph:
- The "Options" block ID must match (without the extension) what is entered in the _library.yaml_ file
- Keep the parameter blocks as a string type and apply conversions within other blocks
- Add "QT GUI Chooser" blocks for variables that will be changed during runtime such as frequency and sample rate. Fill out the GUI Hints to make it look nice.
- Follow examples of other flow graphs on how to configure device/IP addresses, serial numbers, and similar arguments for SDR blocks. This will allow FISSURE-specific features like the IQ hardware button to pass information into the flow graph properly.
- Parameter blocks will replace '_' with '-' when using variables names as command line arguments for the flow graph Python call (FISSURE will handle this)
- Enter filepath and sample rate as "filepath" and "sample_rate" in GNU Radio variable names

## Dashboard

Double-click/load an IQ file in the IQ Data tab Data Viewer and enter sample rate and frequency information prior to loading a file-based inspection flow graph. These values will automatically copy over to the table if available.
