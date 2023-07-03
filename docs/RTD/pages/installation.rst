Installation
============

The FISSURE installer is helpful for staging computers or installing select software programs of interest. The code can be quickly modified to allow for custom software installs. The size estimates for the programs are before and after readings from a full install. The sizes for each program are not exact as some dependencies are installed in previously checked items. The sizes may also change over time as programs get updated.


Requirements
------------

It is recommended to install FISSURE on a clean operating system to avoid conflicts with existing software. The items listed under the "Minimum Install" category are what is required to launch the FISSURE Dashboard without errors. Select all the recommended checkboxes (Default button) to avoid additonal errors while operating the various tools within FISSURE. There will be multiple prompts throughout the installation, mostly asking for elevated permissions and user names. 


Cloning
-------

.. code-block:: console

   $ git clone https://github.com/ainfosec/FISSURE.git
   $ cd FISSURE
   $ git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
   $ git submodule update --init
   $ ./install

This will install PyQt software dependencies required to launch the installation GUIs if they are not found. The git submodule command will download all missing GNU Radio out-of-tree modules from their repositories.


Installer
---------

Next, select the option that best matches your operating system (should be detected automatically if your OS matches an option). The "Minimum Install" option is a list of programs needed to launch the FISSURE Dashboard without any errors. The remaining programs are needed to utilize the various hardware and software tools integrated into FISSURE menu items and tabs.


Uninstalling
------------

There is no uninstaller for FISSURE. Exercise caution when installing several GB of new software for all the installer checkboxes. There are only a few places where FISSURE writes to the system outside of apt-get, make, or pip commands. A future uninstaller could get rid of those changes. 

The following are locations that are impacted by the FISSURE installer:

- a couple PPAs for getting the latest/specific versions of software
- writes to ``~/.local/bin`` and ``~/.bashrc`` (or equivalent) for issuing the fissure command and displaying the icon
- GNU Radio paths added to ``~/.bashrc`` (or equivalent)
- GNU Radio ``~/.gnuradio/config.conf`` file for detecting FISSURE OOT modules
- ``/etc/udev`` rules for detecting hardware
- UHD images from ``uhd_images_downloader`` command, ``sysctl`` changes to ``net.core.wmem_max``
- Optional Wireshark user groups to use it without sudo
- ESP32 Bluetooth Classic Sniffer and FISSURE Sniffer wireshark plugins

Many programs are stored in the ~/Installed_by_FISSURE folder but the dependencies are heavily intertwined amongst the programs.


Usage
-----

Open a terminal and enter: ``fissure``

