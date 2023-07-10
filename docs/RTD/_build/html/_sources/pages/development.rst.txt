===========
Development 
===========

Adding Custom Options
---------------------

**Options Dialog**

Bring up the options dialog in Qt Designer using the `designer` command and then open the *FISSURE/UI/options.ui* file. Click the arrows for the stacked widget (top right) to locate the table where the custom option will be inserted. Double-click on the table and add a new row with the name of the variable. Set the font size to match the other rows with the "Properties<<" button.

.. image:: /pages/Images/options.png

**default.yaml**

Open *FISSURE/YAML/User Configs/default.yaml* and insert the variable name and value (fft_size: 4096) for the new option.

**dashboard.py**

Access the variable in _dashboard.py_ with: `int(self.dashboard_settings_dictionary['fft_size'])`.

Built With
----------

The following software tools are used to edit FISSURE.

**Git**

To add a new git submodule for repositories like GNU Radio out-of-tree modules:

.. code-block:: console

   $ git submodule add -b maint-3.8 https://github.com/someone/gr-something.git ./Custom_Blocks/maint-3.8/gr-something

To submit changes for FISSURE, clone the git repository with the SSH address to avoid errors when doing a push later on. Generate an SSH key and add it to your GitHub access settings.

**Qt Designer**

Python2 branch:

.. code-block:: console

   $ sudo apt-get install python-qt4 qt4-designer

Python3 branches:

.. code-block:: console

   $ sudo apt-get install -y build-essential qtcreator qt5-default

To launch: 

.. code-block:: console

   $ designer

**Grip**

Python2 branch:

.. code-block:: console

   $ sudo python2 -m pip install grip

Python3 branches:

.. code-block:: console

   $ sudo python3 -m pip install grip

To convert markdown to html (requires Internet connection): 

.. code-block:: console

   $ grip README.md --export README.html

