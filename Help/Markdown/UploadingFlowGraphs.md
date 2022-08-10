# Uploading Flow Graphs

## Flow Graph Configuration
A new Python file is generated each time a .grc file is executed in GNU-Radio Companion. The format of this auto-generated Python file is used by the FISSURE system to perform actions like: displaying variable names, starting attacks, changing values for a running flow graph, etc. Editing the Python file may cause the FISSURE system to not function properly.

### GUI vs. No GUI

Flow graph variables can be changed from within the Dashboard on a running flow graph as long as the flow graph is configured to "No GUI" mode in the "Options" block. Flow graphs with GUIs can still be run in the Dashboard, but variables can only be changed from the GNU Radio GUI in the form of GUI widgets. Additionally, the default values for variables cannot be changed from within the Dashboard prior to running a flow graph containing a GUI. They must be edited in GNU Radio Companion.

### Options Block (No GUI)

Within the "Options" block:
*  "ID" must match the file name
*  "Generate Options" must be set to "No GUI"

### ip_address

The Dashboard assumes flow graphs with a variable name of "ip_address" match the IP address of the network interface controlling the PD/Attack hardware. The default "ip_address" value for the flow graph will automatically be updated to reflect the IP address of the hardware specified in the hardware buttons located at the top of the Dashboard.

### Numerical Strings

To specify that a string variable containing only numerical values is indeed a string and not to be interpreted as a float, a new variable named "string_variables" must be added to the flow graph. Its value must be a list with the names of the variables to be considered as exceptions: ["variable_name"]

For example:
![string_variables](./Images/string_variables.png)


## Uploading Attack Flow Graph
The Python file can be uploaded to Dashboard in the Library>Attacks tab.

## Uploading Demodulation Flow Graph
The Python file can be uploaded to Dashboard in the Library>Protocol Data tab.
