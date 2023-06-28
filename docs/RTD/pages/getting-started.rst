Getting Started
===============

Supported
---------
There are three branches within FISSURE to make file navigation easier and reduce code redundancy. The Python2_maint-3.7 branch contains a codebase built around Python2, PyQt4, and GNU Radio 3.7; the Python3_maint-3.8 branch is built around Python3, PyQt5, and GNU Radio 3.8; and the Python3_maint-3.10 branch is built around Python3, PyQt5, and GNU Radio 3.10.

+----------------------+--------------------+
| Operating System     |  FISSURE Branch    |
+======================+====================+
| Ubuntu 18.04 (x64)   | Python2_maint-3.7  | 
+----------------------+--------------------+
| Ubuntu 18.04.5 (x64) | Python2_maint-3.7  |
+----------------------+--------------------+
| Ubuntu 18.04.6 (x64) | Python2_maint-3.7  |
+----------------------+--------------------+
| Ubuntu 20.04.1 (x64) | Python3_maint-3.8  |
+----------------------+--------------------+
| Ubuntu 20.04.4 (x64) | Python3_maint-3.8  |
+----------------------+--------------------+
| Ubuntu 20.04.5 (x64) | Python3_maint-3.8  |
+----------------------+--------------------+
| Ubuntu 20.04.6 (x64) | Python3_maint-3.8  |
+----------------------+--------------------+
| KDE neon 5.25 (x64)  | Python3_maint-3.8  |
+----------------------+--------------------+
| Ubuntu 22.04 (x64)   | Python3_maint-3.10 |
+----------------------+--------------------+

In-Progress (beta)
------------------
These operating systems are still in beta status. They are under development and several features are known to be missing. Items in the installer might conflict with existing programs or fail to install until the status is removed.

+---------------------------+---------------------+
| Operating System          | FISSURE Branch      |
+===========================+=====================+
| DragonOS Focal (x86_64)   | Python3_maint-3.8   |
+---------------------------+---------------------+
| Parrot OS 5.2 (amd64)     | Python3_maint-3.8   |
+---------------------------+---------------------+
| DragonOS FocalX (x86_64)  | Python3_maint-3.10  | 
+---------------------------+---------------------+
| Kali 23.1 (x64)           | Python3_maint-3.10  |
+---------------------------+---------------------+
| BackBox Linux 8 (amd64)   | Python3_maint-3.10  |
+---------------------------+---------------------+

Note: Certain software tools do not work for every OS. Refer to `Software And Conflicts <https://github.com/xxanxnie/FISSURE_RTD/blob/Python3_maint-3.8/docs/Help/Markdown/SoftwareAndConflicts.md>`_

Installation
------------

.. code-block:: text

    git clone https://github.com/ainfosec/FISSURE.git
    cd FISSURE
    git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
    git submodule update --init
    ./install

This will install PyQt software dependencies required to launch the installation GUIs if they are not found. The git submodule command will download all missing GNU Radio out-of-tree modules from their repositories.

Next, select the option that best matches your operating system (should be detected automatically if your OS matches an option).

*insert image*

It is recommended to install FISSURE on a clean operating system to avoid conflicts with existing software. The items listed under the "Minimum Install" category are what is required to launch the FISSURE Dashboard without errors. Select all the recommended checkboxes (Default button) to avoid additonal errors while operating the various tools within FISSURE. There will be multiple prompts throughout the installation, mostly asking for elevated permissions and user names.

If an item contains a "Verify" section at the end, the installer will run the command that follows and highlight the checkbox item green or red depending on if any errors are produced by the command. Checked items without a "Verify" section will remain black following the installation.

*insert image*

The FISSURE installer is helpful for staging computers or installing select software programs of interest. The code can be quickly modified to allow for custom software installs. The size estimates for the programs are before and after readings from a full install. The sizes for each program are not exact as some dependencies are installed in previously checked items. The sizes may also change over time as programs get updated.

*insert image*


Usage
-----
Open a terminal and enter:

.. code-block:: text
    
    fissure

Refer to FISSURE Help menu for more details on usage
