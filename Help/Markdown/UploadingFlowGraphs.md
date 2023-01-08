# Attack Flow Graphs

## Flow Graph Configuration
A new Python file is generated each time a .grc file is executed in GNU Radio Companion. The format of this auto-generated Python file is used by FISSURE to perform actions like: displaying variable names, starting attacks, changing values for a running flow graph, etc. Editing the Python file may cause FISSURE to not function properly.

### GUI vs. No GUI

Flow graphs are called differently depending on if there is a GUI or not. Flow graphs configured to "No GUI" mode in the "Options" block will be loaded as Python module prior to runtime and modify the default variables. The standard start(), wait(), and stop() commands are applied in this case.

Flow graphs with GUIs have their Python files called directly and behave similarly to inspection flow graphs (See _Help>>Inspection Flow Graphs_). Variables can be changed from the GNU Radio GUI in the form of GUI widgets or as command line arguments from parameter blocks. 

### Options Block (No GUI)

Within the "Options" block:
*  "ID" must match the file name
*  "Generate Options" must be set to "No GUI"

### Special Variables

The Dashboard populates certain flow graphs variable names like "ip_address" and "serial" to match the values in the Attack hardware button. These variables must be named correctly in the flow graph to be populated automatically and handled as intended. Refer to other attack flow graphs as examples for how these variables should be utilized.

### Numerical Strings

To help specify that a string variable containing only numerical values is indeed a string and should not to be interpreted as a float, a new variable named "string_variables" can be added to the flow graph. Its value must be a list with the names of the variables to be considered as exceptions: ["variable_name"]

For example:
![string_variables](./Images/string_variables.png)

## Uploading Attack Flow Graph
Attack flow graphs can be added to FISSURE within the _Library>Add_ tab by selecting a protocol and choosing "Attack". Attacks will be visible within the Attack tree if the "Attack Template Name" is entered properly.

