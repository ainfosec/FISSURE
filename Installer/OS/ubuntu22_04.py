#!/usr/bin/env python3

import os
this_file_directory = os.path.dirname(os.path.realpath(__file__))
fissure_directory = os.path.abspath(os.path.join(this_file_directory, os.pardir, os.pardir))

########################################################################
########################## Ubuntu 22.04 ################################
########################################################################

programs_ubuntu22_04 = []

# Misc. Dependencies
programs_ubuntu22_04.append(('Misc. Dependencies (1.4 GB)',
"""sudo apt-get -y update
sudo apt-get install -y ubuntu-standard
sudo apt-get install -y eog
sudo apt-get -y install cmake
sudo apt-get install -y python-setuptools python-dev-is-python3 build-essential
sudo apt-get install -y curl
curl https://bootstrap.pypa.io./pip/2.7/get-pip.py | sudo python2  # Installs pip 20.3.4
sudo apt-get install -y python3-pip
python3 -m pip install cmake --upgrade
sudo apt install -y python3-testresources
python3 -m pip install --upgrade setuptools
python3 -m pip install --upgrade virtualenv
#python3 -m pip install matplotlib  # This version conflicts with yellowbrick
python3 -m pip install PyYAML==5.1
python3 -m pip install pyyaml
wget http://archive.ubuntu.com/ubuntu/pool/universe/p/python-scipy/python-scipy_0.19.1-2ubuntu1_amd64.deb
sudo apt-get install -y ./python-scipy_0.19.1-2ubuntu1_amd64.deb  # FIX?
rm python-scipy_0.19.1-2ubuntu1_amd64.deb
sudo apt-get install -y gedit
sudo apt-get install -y software-properties-common #python-software-properties # does Python3
sudo add-apt-repository -y ppa:git-core/ppa
sudo apt-get -y update
sudo apt-get install -y git 
sudo apt-get install -y libcanberra-gtk-module
python3 -m pip install bitarray
sudo apt install net-tools
python3 -m pip install crcmod
python3 -m pip install pycrypto
sudo apt-get install -y python-tk
python3 -m pip install pyzmq
sudo apt-get install -y libosmocore-dev
sudo apt-get install -y liborc-0.4-dev
sudo apt-get install -y expect
sudo add-apt-repository --y ppa:wireshark-dev/stable  # Latest Wireshark
sudo apt-get update
python3 -m pip install pyshark
sudo apt install -y debconf
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt install -y tshark
python3 -m pip install pypcapfile
python2 -m pip install pypcapfile
python2 -m pip install netaddr
python3 -m pip install psutil
python3 -m pip install pyserial
sudo apt-get install -y gpsd-clients python3-gi-cairo
python3 -m pip install pandas
sudo apt-get install -y dsniff
sudo apt-get install -y ncurses-term
python3 -m pip install yellowbrick
python3 -m pip install seaborn
sudo apt-get install -y rtl-sdr
python3 -m pip install gpsd-py3
python3 -m pip install geopy
python3 -m pip install sounddevice
python3 -m pip install qasync
python3 -m pip install pydotplus
python3 -m pip install pytak
python3 -m pip install tensorflow-cpu
sudo apt-get install -y snapd
sudo snap install netron
python3 -m pip install ipython
python3 -m pip install scikit-learn==1.3.2
python3 -m pip uninstall opencv-python
python3 -m pip install "opencv-python-headless<4.12"
python3 -m pip install pyzipper
sudo apt-get install -y unzip
sudo apt-get install -y usbutils
python3 -m pip install mgrs
sudo apt-get install -y debconf-utils
sudo apt-get install -y xdg-utils
sudo apt-get install -y p7zip-full
python3 -m pip install watchdog
python3 -m pip install aiohttp
python3 -m pip install paho-mqtt
sudo apt install -y python3-eventlet
python3 -m pip install msgpack
python3 -m pip install eventlet
python3 -m pip install psycopg2-binary
python3 -m pip install python-dotenv
sudo apt-get install -y iw
sudo apt-get install -y python3-pyproj
sudo apt-get install -y python3-uhd
. ~/.bashrc
""",True,"Minimum Install"))

# fissure Commands
programs_ubuntu22_04.append(('fissure Commands',
f"""# Detect environment and choose bin path
if [ -n "$APPTAINER_CONTAINER" ] || [ -n "$APPTAINER_NAME" ]; then
  echo "[Apptainer detected] Using /usr/local/bin for command installs."
  bin_path="/usr/local/bin"
else
  bin_path="$HOME/.local/bin"
fi

echo "Using bin path: $bin_path"
mkdir -p "$bin_path"

# Add ~/.local/bin to PATH if missing (for normal installs)
if [ "$bin_path" = "$HOME/.local/bin" ]; then
  if grep -Fq "~/.local/bin" ~/.bashrc
  then
    echo "~/.local/bin is already in ~/.bashrc"
  else
    printf "\\n%s\\n" "export PATH=~/.local/bin:$PATH" >> ~/.bashrc
  fi
fi

# Create fissure command
cat << EOF > "$bin_path/fissure"
#!/bin/bash
export PYTHONPATH="$PYTHONPATH:{fissure_directory}"
cd {fissure_directory} || exit 1
exec python3 fissure/Dashboard/__main__.py
EOF
chmod +x "$bin_path/fissure"

# Create fissure-sensor-node command
cat << EOF > "$bin_path/fissure-sensor-node"
#!/bin/bash
export PYTHONPATH="$PYTHONPATH:{fissure_directory}"
cd {fissure_directory} || exit 1
exec python3 fissure/Sensor_Node/SensorNode.py
EOF
chmod +x "$bin_path/fissure-sensor-node"

# Create fissure-hiprfisr command
cat << EOF > "$bin_path/fissure-hiprfisr"
#!/bin/bash
export PYTHONPATH="$PYTHONPATH:{fissure_directory}"
cd {fissure_directory} || exit 1
exec python3 fissure/Server/__main__.py --remote
EOF
chmod +x "$bin_path/fissure-hiprfisr"

# Create desktop entry for FISSURE (skip in Apptainer)
if [ -z "$APPTAINER_CONTAINER" ] && [ -z "$APPTAINER_NAME" ]; then
  echo "[Desktop Entry]\\nStartupWMClass=__main__.py\\nName=FISSURE\\nTerminal=false\\nType=Application\\nCategories=Qt;Science;DataVisualization;Electricity;HamRadio;" > {fissure_directory}/Installer/fissure.desktop
  echo "Exec=/home/$USER/.local/bin/fissure" >> {fissure_directory}/Installer/fissure.desktop
  echo "Icon={fissure_directory}/docs/Icons/logo_f.png" >> {fissure_directory}/Installer/fissure.desktop
  sudo cp {fissure_directory}/Installer/fissure.desktop /usr/share/applications/ 2>/dev/null || true
else
  echo "[Apptainer detected] Skipping desktop entry creation."
fi

########## Verify ##########
ls -l /usr/local/bin/fissure /usr/local/bin/fissure-sensor-node 2>/dev/null \
  || ls -l ~/.local/bin/fissure ~/.local/bin/fissure-sensor-node
""", True, 'Minimum Install'))

# Password Prompt Exceptions
programs_ubuntu22_04.append(('Password Prompt Exceptions',
f"""# Replace placeholder in the template file directly into a temporary file
sed "s/__USERNAME__/$(whoami)/g" "{fissure_directory}/Installer/password_prompt_exceptions.txt" > /tmp/password_prompt_exceptions

# Validate the temporary sudoers file
echo "Validating sudoers file..."
if visudo -c -f /tmp/password_prompt_exceptions; then
    echo "Validation successful. Installing sudoers file..."
    sudo mv /tmp/password_prompt_exceptions /etc/sudoers.d/fissure
    sudo chown root:root /etc/sudoers.d/fissure
    sudo chmod 440 /etc/sudoers.d/fissure
    echo "No Password Prompts Setup completed successfully!"
else
    echo "Validation failed! Not installing the sudoers file to avoid system issues."
    rm /tmp/password_prompt_exceptions
fi
########## Verify ##########
ls -l /etc/sudoers.d/fissure
""", True, 'Minimum Install'))

# GNU Radio
programs_ubuntu22_04.append(('GNU Radio (1.3 GB)',
"""sudo add-apt-repository -y ppa:gnuradio/gnuradio-releases
sudo apt-get update
sudo apt-get install -y gnuradio  # =3.10.5.1-0~gnuradio~jammy-2  # Check for changes here: https://launchpad.net/~gnuradio/+archive/ubuntu/gnuradio-releases
sudo apt-get install -y uhd-host

# Configure GNU Radio
(gnuradio-companion &) && sleep 5 && killall gnuradio-companion
/bin/echo -e "[grc]\nlocal_blocks_path=""" + fissure_directory + """/Custom_Blocks\nxterm_executable=/usr/bin/gnome-terminal" > ~/.gnuradio/config.conf
sudo cp /usr/lib/uhd/utils/uhd-usrp.rules /etc/udev/rules.d/  # For B205 mini
sudo udevadm control --reload-rules
sudo udevadm trigger
sudo mkdir /usr/share/uhd
sudo chmod -R 777 /usr/share/uhd
uhd_images_downloader

# Find OOT Modules
printf "\\n%s\\n" "export PYTHONPATH=/usr/local/lib/python3.8/site-packages:/usr/local/lib/python3/dist-packages:/usr/lib/python3/site-packages:$PYTHONPATH" >> ~/.bashrc
printf "\\n%s\\n" "export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH" >> ~/.bashrc
printf "\\n%s\\n" "export PYTHONPATH=/usr/local/lib/python3/dist-packages:/usr/lib/python3/site-packages:$PYTHONPATH" >> ~/.profile  # For GRC without terminal
printf "\\n%s\\n" "export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH" >> ~/.profile  # For GRC without terminal
. ~/.bashrc
sudo apt-get install -y libzmq3-dev swig cmake
sudo sh -c "/bin/echo -e '/usr/local/lib' >> /etc/ld.so.conf"
sudo ldconfig
########## Verify ##########
gnuradio-companion --help
""",True,"Minimum Install"))

# Scapy
programs_ubuntu22_04.append(('Scapy (80.1 MB)',
"""sudo apt-get install -y python3-scapy
#python3 -m pip install scapy  # Causes errors
python2 -m pip install scapy==2.4.5
sudo sed -i 's/tostring/tobytes/g' /usr/local/lib/python3.10/dist-packages/scapy/arch/linux.py
########## Verify ##########
python2 -c "import scapy" && python3 -c "import scapy"
""",True,"Minimum Install"))

# Wireshark
programs_ubuntu22_04.append(('Wireshark (49.9 MB)',
"""sudo add-apt-repository --y ppa:wireshark-dev/stable  # Gets installed with Misc. Dependencies (tshark), ESP32 Bluetooth Classic Sniffer
sudo apt-get update
sudo apt install -y wireshark wireshark-dev  # Yes
sudo groupadd wireshark
sudo usermod -a -G wireshark $USER
sudo chgrp wireshark /usr/bin/dumpcap
sudo chmod o-rx /usr/bin/dumpcap
sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap
sudo getcap /usr/bin/dumpcap
mkdir -p ~/.config/wireshark/plugins
cp -a """ + fissure_directory + """/Dissectors/. ~/.config/wireshark/plugins
########## Verify ##########
wireshark --help
""",True,"Minimum Install"))

# PostgreSQL Database 
programs_ubuntu22_04.append(('PostgreSQL Database',
"""python3 -m pip install python-dotenv
sudo apt-get install -y libpq-dev
python3 -m pip install psycopg2
sudo apt-get install -y docker.io docker-compose-v2
sudo usermod -aG docker ${USER}  # Reboot computer to use docker commands without sudo
sudo apt install -y postgresql-client
cd '""" + fissure_directory + """'
cp example.env .env
bash -c '
    set -o allexport
    source .env
    set +o allexport
    export PGPASSWORD=$POSTGRES_PASSWORD
    sudo docker compose up -d
    until pg_isready -U $POSTGRES_USER -h $POSTGRES_HOST -p $POSTGRES_EXTERNAL_PORT; do
        echo "Waiting for PostgreSQL to be ready..."
        sleep 2
    done
    pg_restore -U $POSTGRES_USER -d $POSTGRES_DB -h $POSTGRES_HOST -p $POSTGRES_EXTERNAL_PORT -v db/fissure_db_dump.sql
'
########## Verify ##########
bash -c '
    set -o allexport
    source .env
    set +o allexport
    export PGPASSWORD=$POSTGRES_PASSWORD
    sudo docker compose up -d
    psql -U $POSTGRES_USER -d $POSTGRES_DB -h $POSTGRES_HOST -p $POSTGRES_EXTERNAL_PORT -c "SELECT COUNT(*) FROM pg_tables;"
'
""",True,'Minimum Install'))

# Meshtastic
programs_ubuntu22_04.append(('Meshtastic',
"""sudo apt-get install -y python3-serial
sudo apt-get install -y python3-protobuf
sudo apt-get install -y python3-pyserial
python3 -m pip install meshtastic
sudo usermod -aG dialout $USER  # log out & in/reboot
sudo usermod -aG tty $USER
echo 'SUBSYSTEM=="tty", ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="ea60", MODE="0666"' | sudo tee /etc/udev/rules.d/99-meshtastic.rules
sudo udevadm control --reload-rules
sudo udevadm trigger
########## Verify ##########
python3 -c "import meshtastic"
""",True,'Minimum Install'))

# Network Certificates 
programs_ubuntu22_04.append(('Network Certificates',
"""cd '""" + fissure_directory + """'
export PYTHONPATH='""" + fissure_directory + """':$PYTHONPATH
python3 ./fissure/generate_certificates.py
########## Verify ##########
test -f '""" + fissure_directory + """/certificates/server/server.key' &&
test -f '""" + fissure_directory + """/certificates/server/server.key_secret' &&
test -f '""" + fissure_directory + """/certificates/clients/client_0.key' &&
test -f '""" + fissure_directory + """/certificates/clients/client_0.key_secret'
""",True,'Minimum Install'))

# Auto-Launch Sensor Node
programs_ubuntu22_04.append(('Auto-Launch Sensor Node',
f"""mkdir -p "$HOME/.config/autostart"

cat <<EOF > "$HOME/.config/autostart/fissure-sensor-node.desktop"
[Desktop Entry]
Type=Application
Terminal=true
Name=FISSURE Sensor Node
Exec=gnome-terminal -- bash -c 'sleep 1; $HOME/.local/bin/fissure-sensor-node; exec bash'
EOF

chmod +x "$HOME/.config/autostart/fissure-sensor-node.desktop"

########## Verify ##########
ls "$HOME/.config/autostart/fissure-sensor-node.desktop"
""",False,'Remote Sensor Node'))

# LimeSDR
programs_ubuntu22_04.append(('LimeSDR (288.7 MB)',
"""#sudo add-apt-repository -y ppa:myriadrf/drivers  # doesn't work
#sudo apt-get update
sudo apt-get install -y limesuite liblimesuite-dev limesuite-udev  # No limesuite-images on 22.04
sudo apt-get install -y soapysdr-tools soapysdr-module-lms7
sudo apt-get install -y libboost-all-dev swig
########## Verify ##########
ls /usr/bin/LimeSuiteGUI
""",True,'Hardware'))

# BladeRF
programs_ubuntu22_04.append(('BladeRF (23.1 MB)',
"""sudo apt-get install -y libusb-1.0-0-dev libusb-1.0-0 build-essential cmake libncurses5-dev libtecla1 pkg-config git wget  # no package: libtecla1-dev       
sudo apt-get install -y bladerf
sudo apt-get install -y bladerf-fpga-hostedx115
sudo apt-get install -y bladerf-fpga-hostedx40
sudo apt-get install -y bladerf-fpga-hostedxa4
sudo apt-get install -y bladerf-fpga-hostedxa9
########## Verify ##########
bladeRF-cli --help
""",True,'Hardware'))

# USRP X300 Series - FIX
programs_ubuntu22_04.append(('USRP X300 Series (499.7 kB)',
"""mkdir -p ~/Installed_by_FISSURE  # Set MTU to 9000 and run uhd_image_loader command
cd ~/Installed_by_FISSURE
#wget https://codeload.github.com/EttusResearch/uhd/zip/release_003_010_003_000 -O uhd.zip
#unzip uhd.zip
#cd uhd-release_003_010_003_000/host/include
#sudo cp -Rv uhd/rfnoc /usr/share/uhd/
#rm -Rf ~/Installed_by_FISSURE/uhd-release_003_010_003_000
/usr/lib/uhd/utils/uhd_images_downloader.py
#"/usr/bin/uhd_image_loader" --args="type=x300,addr=192.168.40.2"  # Use your X310 IP
sudo sysctl -w net.core.wmem_max=24862979
""",True,'Hardware'))

# HackRF, gr-osmosdr
programs_ubuntu22_04.append(('HackRF, gr-osmosdr',
"""sudo apt-get install -y libusb-1.0-0-dev

# HackRF
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE/
wget https://github.com/greatscottgadgets/hackrf/releases/download/v2024.02.1/hackrf-2024.02.1.zip
unzip hackrf-2024.02.1.zip
rm hackrf-2024.02.1.zip
mkdir ~/Installed_by_FISSURE/hackrf-2024.02.1/host/build
cd ~/Installed_by_FISSURE/hackrf-2024.02.1/host/build
sed -i 's/cmake_minimum_required(VERSION 2.8.12)/cmake_minimum_required(VERSION 3.5)/' \
    ~/Installed_by_FISSURE/hackrf-2024.02.1/host/CMakeLists.txt \
    ~/Installed_by_FISSURE/hackrf-2024.02.1/host/libhackrf/CMakeLists.txt \
    ~/Installed_by_FISSURE/hackrf-2024.02.1/host/hackrf-tools/CMakeLists.txt
cmake ..
make
sudo make install
sudo ldconfig
sudo cp """ + fissure_directory + """/Tools/53-hackrf.rules /etc/udev/rules.d/53-hackrf.rules
sudo udevadm trigger --action=change
#sudo apt-get install -y hackrf

# gr-osmosdr
#sudo apt-get install gr-osmosdr
cd ~/Installed_by_FISSURE
git clone https://gitea.osmocom.org/sdr/gr-osmosdr.git
cd gr-osmosdr
mkdir build
cd build
cmake ..
make
sudo make install
sudo ldconfig
########## Verify ##########
hackrf_sweep -h #&& ls /usr/local/bin/osmocom_fft
""",True,'Hardware'))

# 8812au Driver
programs_ubuntu22_04.append(('8812au Driver (810.8 MB)',
"""# Still Broken, Needs Replacement Driver
sudo apt-get -y install dkms
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/aircrack-ng/rtl8812au/
cd ~/Installed_by_FISSURE/rtl8812au
sudo make dkms_install
""",True,'Hardware'))

# Zigbee Sniffer
programs_ubuntu22_04.append(('Zigbee Sniffer (10.1 MB)',
"""mkdir -p ~/Installed_by_FISSURE
cp -R """ + fissure_directory + """/Tools/OpenSniffer-0.1/ ~/Installed_by_FISSURE/
cd ~/Installed_by_FISSURE/OpenSniffer-0.1/
sudo python3 setup.py install
#sudo add-apt-repository -y ppa:rock-core/qt4  # PyQt4, doesn't work
#sudo apt-get update
wget http://archive.ubuntu.com/ubuntu/pool/universe/q/qt-assistant-compat/libqtassistantclient4_4.6.3-7build1_amd64.deb -O ~/Downloads/libqtassistantclient4_4.6.3-7build1_amd64.deb 
sudo apt-get install -y ~/Downloads/libqtassistantclient4_4.6.3-7build1_amd64.deb
wget http://archive.ubuntu.com/ubuntu/pool/universe/p/python-qt4/python-qt4_4.12.1+dfsg-2_amd64.deb -O ~/Downloads/python-qt4_4.12.1+dfsg-2_amd64.deb
sudo apt-get install -y ~/Downloads/python-qt4_4.12.1+dfsg-2_amd64.deb
wget http://archive.ubuntu.com/ubuntu/pool/universe/p/python-pyaudio/python-pyaudio_0.2.11-1build2_amd64.deb -O ~/Downloads/python-pyaudio_0.2.11-1build2_amd64.deb
sudo apt-get install -y ~/Downloads/python-pyaudio_0.2.11-1build2_amd64.deb
rm ~/Downloads/libqtassistantclient4_4.6.3-7build1_amd64.deb
rm ~/Downloads/python-qt4_4.12.1+dfsg-2_amd64.deb
rm ~/Downloads/python-pyaudio_0.2.11-1build2_amd64.deb
sudo apt-get install -y mlocate
""",True,'Hardware'))

# fl2k
programs_ubuntu22_04.append(('fl2k',
"""mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://gitea.osmocom.org/sdr/osmo-fl2k.git  # gets redirected: https://git.osmocom.org/osmo-fl2k.git
cd osmo-fl2k
mkdir build
cd build
sed -i 's/cmake_minimum_required(VERSION 2.6)/cmake_minimum_required(VERSION 3.5)/' ~/Installed_by_FISSURE/osmo-fl2k/CMakeLists.txt
cmake ../ -DINSTALL_UDEV_RULES=ON
make -j 3
sudo make install
sudo ldconfig
sudo udevadm control -R
sudo udevadm trigger
########## Verify ##########
ls /usr/local/bin/fl2k_test
""",True,'Hardware'))

# Proxmark3
programs_ubuntu22_04.append(('Proxmark3 (3.1 GB)',
"""sudo apt-get install -y p7zip git build-essential libreadline8 libreadline-dev libusb-0.1-4 libusb-dev perl pkg-config wget libncurses5-dev gcc-arm-none-eabi libreadline-dev libpcsclite-dev gcc-arm-none-eabi
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/Proxmark/proxmark3.git
cd proxmark3
make clean && make all
########## Verify ##########
ls ~/Installed_by_FISSURE/proxmark3/client/proxmark3
""",True,'Hardware'))

# PlutoSDR
programs_ubuntu22_04.append(('PlutoSDR (194.4 MB)',
"""sudo apt-get install -y libglib2.0-dev libgtk2.0-dev libgtkdatabox-dev libmatio-dev libfftw3-dev libxml2 libxml2-dev bison flex libavahi-common-dev libavahi-client-dev libcurl4-openssl-dev libjansson-dev cmake libaio-dev libserialport-dev libcdk5-dev libusb-1.0-0-dev doxygen graphviz git libgmp-dev swig liborc-dev
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/pcercuei/libini.git
cd libini
mkdir build && cd build && cmake ../ && make && sudo make install
cd ~/Installed_by_FISSURE
git clone https://github.com/analogdevicesinc/libiio.git
cd libiio
mkdir build && cd build && cmake ../ && make && sudo make install
cd ~/Installed_by_FISSURE
git clone https://github.com/analogdevicesinc/libad9361-iio.git
cd libad9361-iio
cmake ./
make
sudo make install
#cd ~/Installed_by_FISSURE
#git clone https://github.com/analogdevicesinc/iio-oscilloscope.git  # IIO oscilloscope is broken. /usr/include/gtkdatabox_graph.h:100:38: error: unknown type name ‘GdkRGBA’; did you mean ‘GdkGC’?
#cd iio-oscilloscope
#git checkout origin/master
#mkdir build && cd build
#cmake ../ && make
#sudo make install
#cd ~/Installed_by_FISSURE
#git clone -b upgrade-3.8 https://github.com/analogdevicesinc/gr-iio.git  # No Github version for 3.10. Comes with GNU Radio 3.10.
#cd gr-iio
#cmake .
#make
#sudo make install
#cd ..
#sudo ldconfig
########## Verify ##########
ls /usr/lib/python*/*/gnuradio/iio
""",True,'Hardware'))

# qFlipper
programs_ubuntu22_04.append(('qFlipper',
"""mkdir -p ~/Installed_by_FISSURE/qFlipper
cd ~/Installed_by_FISSURE/qFlipper
wget -r -np -nd -A "qFlipper-x86_64-dev*.AppImage" https://update.flipperzero.one/builds/qFlipper/dev/
chmod +x qFlipper*
########## Verify ##########
ls ~/Installed_by_FISSURE/qFlipper/qFlipper*
""",True,'Hardware'))

# gr-acars-3.10ng
programs_ubuntu22_04.append(('gr-acars-3.10ng (7.1 MB)',
"""cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-acars-3.10ng/
sudo rm -Rf build
mkdir build
cd build
cmake ..
make
sudo make install
sudo ldconfig
########## Verify ##########
ls /usr/local/lib/python*/*/acars
""",True,'Out-of-Tree Modules'))

# gr-adsb
programs_ubuntu22_04.append(('gr-adsb (2.7 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-adsb/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-adsb"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-adsb/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-adsb/)" ]; 
then
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-adsb/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/gnuradio/adsb
""",True,'Out-of-Tree Modules'))

# gr-ainfosec
programs_ubuntu22_04.append(('gr-ainfosec (7.6 MB)',
"""cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-ainfosec/
sudo rm -Rf build
mkdir build
cd build
cmake ..
make
sudo make install
sudo ldconfig
########## Verify ##########
ls /usr/local/lib/python*/*/gnuradio/ainfosec
""",True,'Minimum Install'))

# gr-ais
programs_ubuntu22_04.append(('gr-ais (9.2 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-ais/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-ais"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-ais/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-ais/)" ]; 
then
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-ais/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/gnuradio/ais
""",True,'Out-of-Tree Modules'))

# gr-aistx
programs_ubuntu22_04.append(('gr-aistx',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/ais/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/ais"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/ais/gr-aistx/
    git checkout gnuradio-3.10-port-udp
    git pull origin gnuradio-3.10-port-udp
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/ais/gr-aistx/)" ]; 
then
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/ais/gr-aistx/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/gnuradio/aistx
""",True,'Out-of-Tree Modules'))

# gr-bluetooth
programs_ubuntu22_04.append(('gr-bluetooth (34.7 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-bluetooth/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-bluetooth"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-bluetooth/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-bluetooth/)" ]; 
then
  mkdir -p ~/Installed_by_FISSURE
  cd ~/Installed_by_FISSURE
  rm -Rf libbtbb
  git clone https://github.com/greatscottgadgets/libbtbb -b master
  cd libbtbb
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-bluetooth/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/bin/btrx
""",False,'Out-of-Tree Modules'))

# gr-clapper_plus
programs_ubuntu22_04.append(('gr-clapper_plus (2.4 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-clapper_plus/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-clapper_plus"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-clapper_plus/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-clapper_plus/)" ]; 
then
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-clapper_plus/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/gnuradio/clapper_plus
""",True,'Out-of-Tree Modules'))

# gr-dect2
programs_ubuntu22_04.append(('gr-dect2 (11.9 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-dect2/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-dect2"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-dect2/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-dect2/)" ]; 
then
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-dect2/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/gnuradio/dect2
""",True,'Out-of-Tree Modules'))

# gr-foo
programs_ubuntu22_04.append(('gr-foo (37.6 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-foo/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-foo"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-foo/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-foo/)" ]; 
then
  sudo apt-get install -y libsndfile1-dev
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-foo/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/foo
""",True,'Out-of-Tree Modules'))

# gr-fuzzer
programs_ubuntu22_04.append(('gr-fuzzer (7.4 MB)',
"""cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-fuzzer/
sudo rm -Rf build
mkdir build
cd build
cmake ..
make
sudo make install
sudo ldconfig
########## Verify ##########
ls /usr/local/lib/python*/*/gnuradio/fuzzer
""",True,'Out-of-Tree Modules'))

# gr-garage_door
programs_ubuntu22_04.append(('gr-garage_door (2.4 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-garage_door/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-garage_door"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-garage_door/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-garage_door/)" ]; 
then
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-garage_door/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/gnuradio/garage_door
""",True,'Out-of-Tree Modules'))

# gr-gsm
programs_ubuntu22_04.append(('gr-gsm (156.8 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-gsm/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-gsm"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-gsm/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-gsm/)" ]; 
then
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-gsm/
  sudo rm -Rf build
  sudo apt-get install -y gr-osmosdr
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
  # gr-gsm needs to be made twice for "import arfcn" block to work
  make 
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/gnuradio/gsm
""",True,'Out-of-Tree Modules'))

# gr-ieee802-11
programs_ubuntu22_04.append(('gr-ieee802-11 (37.9 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-ieee802-11/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-ieee802-11"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-ieee802-11/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-ieee802-11/)" ]; 
then
  sudo apt-get install -y libsndfile1-dev
  sudo apt-get install -y clang
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-ieee802-11/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/ieee802_11
""",True,'Out-of-Tree Modules'))

# gr-ieee802-15-4
programs_ubuntu22_04.append(('gr-ieee802-15-4 (63.3 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-ieee802-15-4/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-ieee802-15-4"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-ieee802-15-4/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-ieee802-15-4/)" ]; 
then
  sudo apt-get install -y libsndfile1-dev
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-ieee802-15-4/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
  grcc """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-ieee802-15-4/examples/ieee802_15_4_CSS_PHY.grc
  grcc """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-ieee802-15-4/examples/ieee802_15_4_OQPSK_PHY.grc
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/ieee802_15_4
""",True,'Out-of-Tree Modules'))

# gr-iridium
programs_ubuntu22_04.append(('gr-iridium (29.5 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-iridium/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-iridium"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-iridium/
    git checkout master
    git pull origin master
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-iridium/)" ]; 
then
  sudo apt-get install -y libsndfile1-dev
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-iridium/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/iridium
""",True,'Out-of-Tree Modules'))

# gr-j2497
programs_ubuntu22_04.append(('gr-j2497 (2.6 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-j2497/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-j2497"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-j2497/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-j2497/)" ]; 
then
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-j2497/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/gnuradio/j2497
""",True,'Out-of-Tree Modules'))

# gr-limesdr
programs_ubuntu22_04.append(('gr-limesdr (12.0 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-limesdr/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-limesdr"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-limesdr/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-limesdr/)" ]; 
then
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-limesdr/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/gnuradio/limesdr
""",True,'Out-of-Tree Modules'))

# gr-mixalot
programs_ubuntu22_04.append(('gr-mixalot (19.1 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-mixalot/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-mixalot"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-mixalot/
    git checkout main
    git pull origin main
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-mixalot/)" ]; 
then
  sudo apt-get install -y libitpp-dev
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-mixalot/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/gnuradio/mixalot
""",True,'Out-of-Tree Modules'))

# gr-nrsc5
programs_ubuntu22_04.append(('gr-nrsc5 (53.8 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-nrsc5/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-nrsc5"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-nrsc5/
    git checkout master
    git pull origin master
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-nrsc5/)" ]; 
then
  sudo apt-get install -y libsndfile1-dev
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-nrsc5/
  sudo rm -Rf build
  sudo apt install -y git build-essential cmake autoconf libtool libao-dev libfftw3-dev librtlsdr-dev libgsl-dev
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/nrsc5
""",True,'Out-of-Tree Modules'))

# gr-paint
programs_ubuntu22_04.append(('gr-paint (9.0 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-paint/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-paint"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-paint/
    git checkout master
    git pull origin master
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-paint/)" ]; 
then
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-paint/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-paint/
  gcc tgatoluma.c -o tgatoluma
  chmod +x tgatoluma
  cp tgatoluma ~/.local/bin/
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/paint
""",True,'Out-of-Tree Modules'))

# gr-rds
programs_ubuntu22_04.append(('gr-rds (20.5 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-rds/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-rds"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-rds/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-rds/)" ]; 
then
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-rds/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/rds
""",True,'Out-of-Tree Modules'))

# gr-sidekiq
programs_ubuntu22_04.append(('gr-sidekiq',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-sidekiq/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-sidekiq"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-sidekiq/
    git checkout master
    git pull origin master
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-sidekiq/)" ];  # Requires Sidekiq SDK files before building.
then
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-sidekiq/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/*/sidekiq
""",False,'Out-of-Tree Modules'))

# gr-sdrplay3
programs_ubuntu22_04.append(('gr-sdrplay3',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-sdrplay3/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-sdrplay3"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-sdrplay3/
    git checkout main
    git pull origin main
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-sdrplay3/)" ];  # Requires SDRplay API before building: https://www.sdrplay.com/api
then
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-sdrplay3/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/*/sdrplay3
""",True,'Out-of-Tree Modules'))

# gr-tpms
programs_ubuntu22_04.append(('gr-tpms (11.8 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-tpms/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-tpms"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-tpms/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-tpms/)" ]; 
then
  sudo apt-get install -y libsndfile1-dev
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-tpms/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/gnuradio/tpms
""",True,'Out-of-Tree Modules'))

# gr-tpms_poore
programs_ubuntu22_04.append(('gr-tpms_poore (2.5 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-tpms_poore/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-tpms_poore"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-tpms_poore/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-tpms_poore/)" ]; 
then
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-tpms_poore/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/gnuradio/tpms_poore
""",True,'Out-of-Tree Modules'))

# gr-X10
programs_ubuntu22_04.append(('gr-X10 (2.4 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-X10/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-X10"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-X10/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-X10/)" ]; 
then
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-X10/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/gnuradio/X10
""",True,'Out-of-Tree Modules'))

# gr-zwave_poore
programs_ubuntu22_04.append(('gr-zwave_poore (2.5 MB)',
"""cd """ + fissure_directory + """
if [ ! -f "Custom_Blocks/maint-3.10/gr-zwave_poore/.git" ]; then
    git submodule update --init -- "Custom_Blocks/maint-3.10/gr-zwave_poore"
    cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-zwave_poore/
    git checkout maint-3.10
    git pull origin maint-3.10
fi
if [ "$(ls -A """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-zwave_poore/)" ]; 
then
  cd """ + fissure_directory + """/Custom_Blocks/maint-3.10/gr-zwave_poore/
  sudo rm -Rf build
  mkdir build
  cd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
else
  echo "Folder is empty. Execute 'git submodule update --init' from FISSURE directory."
fi
########## Verify ##########
ls /usr/local/lib/python*/*/gnuradio/zwave_poore
""",True,'Out-of-Tree Modules'))

# QSpectrumAnalyzer
programs_ubuntu22_04.append(('QSpectrumAnalyzer (9.6 MB)',
"""#sudo add-apt-repository -y ppa:myriadrf/drivers
#sudo apt-get -y update
sudo apt-get install -y python3-pip python3-pyqt5 python3-numpy python3-scipy python3-soapysdr  # No package: soapysdr
sudo apt-get install -y soapysdr-module-rtlsdr soapysdr-module-airspy soapysdr-module-hackrf soapysdr-module-lms7
python3 -m pip install --user qspectrumanalyzer  # log in again, run without sudo
########## Verify ##########
ls ~/.local/bin/qspectrumanalyzer
""",True,'SDR'))

# GQRX
programs_ubuntu22_04.append(('GQRX (7.0 MB)',
"""sudo apt-get install -y libqt5svg5-dev  #sudo apt-get install -y gqrx-sdr
sudo apt-get install -y libpulse-dev
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE/
git clone https://github.com/gqrx-sdr/gqrx.git
cd  ~/Installed_by_FISSURE/gqrx
mkdir build
cd build
cmake ..
make
sudo make install
########## Verify ##########
ls /usr/local/bin/gqrx
""",True,'SDR'))

# Dump1090
programs_ubuntu22_04.append(('Dump1090 (3.4 MB)',
"""sudo apt-get install -y libusb-1.0-0-dev
sudo apt-get install -y librtlsdr-dev
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE/
git clone https://github.com/antirez/dump1090.git
cd ~/Installed_by_FISSURE/dump1090/
make
########## Verify ##########
~/Installed_by_FISSURE/dump1090/dump1090 --help
""",True,'Aircraft'))

# QtDesigner
programs_ubuntu22_04.append(('QtDesigner',
"""sudo apt-get install -y build-essential qtcreator qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools
########## Verify ##########
ls /usr/bin/designer
""",True,'Development'))

# Grip
programs_ubuntu22_04.append(('Grip (6.4 MB)',
"""python3 -m pip install grip
########## Verify ##########
ls /usr/local/bin/grip
""",True,'Development'))

# Kismet
programs_ubuntu22_04.append(('Kismet (106.4 MB)',
"""wget -O - https://www.kismetwireless.net/repos/kismet-release.gpg.key | sudo apt-key add -
echo 'deb https://www.kismetwireless.net/repos/apt/release/jammy jammy main' | sudo tee /etc/apt/sources.list.d/kismet.list
sudo cp /etc/apt/trusted.gpg /etc/apt/trusted.gpg.d  # Removes "sudo apt update" warnings
sudo apt update
echo "kismet kismet/install-setuid boolean false" | sudo debconf-set-selections
echo "kismet kismet/install-user string kismet" | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y kismet
""",True,'802.11'))

# UDP Replay
programs_ubuntu22_04.append(('UDP Replay (1.1 MB)',
"""sudo apt-get install -y libpcap-dev
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/rigtorp/udpreplay.git
cd ~/Installed_by_FISSURE/udpreplay
mkdir build
cd build
cmake ..
make
sudo make install
########## Verify ##########
ls /usr/local/bin/udpreplay
""",True,'802.11'))

# V2Verifier
programs_ubuntu22_04.append(('V2Verifier (3.8 MB)',
"""sudo apt-get install -y libgmp3-dev python3-tk python3-pil.imagetk
python3 -m pip install fastecdsa
python3 -m pip install -U pyyaml
#sudo apt install -y git cmake libuhd-dev uhd-host swig libgmp3-dev python3-pip python3-tk python3-pil 
#python3-pil.imagetk gnuradio
#Needs gr-foo and gr-ieee802-11
""",True,'V2V'))

# srsRAN_4G/srsRAN/srsLTE
programs_ubuntu22_04.append(('srsRAN_4G',
"""sudo apt-get install -y build-essential cmake net-tools libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev gcc-11 g++-11
sudo apt-get install -y libboost-system-dev libboost-test-dev libboost-thread-dev libqwt-qt5-dev qtbase5-dev  # srsGUI
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/srsLTE/srsGUI.git
cd srsGUI
mkdir build
cd build
export CC=$(which gcc-11)
export CXX=$(which g++-11)
cmake ..
make
sudo make install
cd ~/Installed_by_FISSURE
git clone https://github.com/srsRAN/srsRAN_4G.git
cp """ + fissure_directory + """/Tools/IMSI-Catcher_4G/cell_search.c ~/Installed_by_FISSURE/srsRAN_4G/lib/examples/  # IMSI-Catcher 4G
cd srsRAN_4G/
mkdir build
cd build
cmake ..
make
sudo make install
sudo ldconfig
sudo srsran_install_configs.sh user  # user or service, not username
cd ../..
mkdir -p ~/.config/srsran
sudo cp -f """ + fissure_directory + """/Tools/srsRAN_configs/* ~/.config/srsran/
sudo chown -R $USER:$USER ~/.config/srsran     # IMSI-Catcher 4G
sudo apt-get install -y fortune cowsay lolcat  # IMSI-Catcher 4G
# cd srsRAN/srsepc
# interface=$(route | awk '/default/ {print $0}' | awk 'END {print $(NF)}')
# sudo ./srsepc_if_masq.sh "$interface"
# gnome-terminal --tab --title="srsEPC" -- /bin/sh -c 'sudo srsepc; $SHELL' 
# gnome-terminal --tab --title="srsENB" -- /bin/sh -c 'sudo srsenb; $SHELL'
########## Verify ##########
srsenb --help
""",True,'LTE'))

# FALCON - FIX (needs older soapysdr version?)
programs_ubuntu22_04.append(('FALCON',
"""sudo apt-get install -y build-essential git cmake libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev  # For srsLTE
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
sudo apt-get install -y libglib2.0-dev libudev-dev libcurl4-gnutls-dev libboost-all-dev qtdeclarative5-dev libqt5charts5-dev  # FALCON
git clone https://github.com/falkenber9/falcon.git
cd falcon
mkdir build
cd build
cmake -DFORCE_SUBPROJECT_SRSLTE=ON -DCMAKE_INSTALL_PREFIX=/usr ../
make
sudo make install
#sudo xargs rm < install_manifest.txt  # uninstall
#make clean
########## Verify ##########
ls /usr/bin/FalconGUI
""",False,'LTE'))

# LTE-ciphercheck - Fix
programs_ubuntu22_04.append(('LTE-ciphercheck',
"""sudo apt install -y git cmake libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev libuhd-dev libpcsclite-dev pcsc-tools pcscd
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/mrlnc/LTE-ciphercheck  # No 22.04 version yet.
cd LTE-ciphercheck
mkdir build 
cd build
cmake ..
make srsue
sudo ldconfig
cp """ + fissure_directory + """/Tools/LTE-ciphercheck/ciphercheck.conf ../srsue/ciphercheck.conf 
""",False,'LTE'))

# Aircrack-ng
programs_ubuntu22_04.append(('Aircrack-ng (20.4 MB)',
"""sudo apt-get install -y aircrack-ng
########## Verify ##########
aircrack-ng --help
""",True,'802.11'))

# Geany
programs_ubuntu22_04.append(('Geany (16.4 MB)',
"""sudo apt-get install -y geany
########## Verify ##########
geany --help
""",False,'Development'))

# Arduino IDE
programs_ubuntu22_04.append(('Arduino IDE (630.3 MB)',
"""wget -P ~/Installed_by_FISSURE/ https://downloads.arduino.cc/arduino-1.8.15-linux64.tar.xz
cd ~/Installed_by_FISSURE
tar -xf arduino-1.8.15-linux64.tar.xz
rm arduino-1.8.15-linux64.tar.xz
cd arduino-1.8.15/
sudo ./install.sh
cp -R """ + fissure_directory + """/Tools/Esp8266_listen_trigger/ ~/Installed_by_FISSURE/
########## Verify ##########
arduino --version
""",True,'Development'))

# Minicom
programs_ubuntu22_04.append(('Minicom (2.1 MB)',
"""sudo apt-get install -y minicom
########## Verify ##########
ls /usr/bin/minicom
""",True,'Hardware'))

# PuTTY
programs_ubuntu22_04.append(('PuTTY (6.4 MB)',
"""sudo apt-get install -y putty
########## Verify ##########
putty --help
""",True,'Hardware'))

# openHAB - FIX
programs_ubuntu22_04.append(('openHAB (616.9 MB)',
"""sudo apt-get -yq install gnupg curl
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 0xB1998361219BD9C9
cd ~/Downloads
curl -O https://cdn.azul.com/zulu/bin/zulu-repo_1.0.0-2_all.deb
sudo apt-get install ./zulu-repo_1.0.0-2_all.deb
sudo apt-get update
sudo apt-get install -y zulu11-jdk
rm zulu-repo_1.0.0-2_all.deb
wget -qO - 'https://openhab.jfrog.io/artifactory/api/gpg/key/public' | sudo apt-key add -
sudo apt-get install -y apt-transport-https
echo 'deb https://openhab.jfrog.io/artifactory/openhab-linuxpkg stable main' | sudo tee /etc/apt/sources.list.d/openhab.list
sudo apt-get update 
sudo apt-get install -y openhab
########## Verify ##########
ls /usr/bin/openhab-cli
""",True,'Z-Wave'))

# rtl-zwave
programs_ubuntu22_04.append(('rtl-zwave (106.5 kB)',
"""mkdir -p ~/Installed_by_FISSURE
sudo apt-get install -y libpcap-dev
cp -R """ + fissure_directory + """/Tools/rtl-zwave-master ~/Installed_by_FISSURE/
cd ~/Installed_by_FISSURE/rtl-zwave-master
make
########## Verify ##########
ls ~/Installed_by_FISSURE/rtl-zwave-master/rtl_zwave
""",True,'Z-Wave'))

# waving-z
programs_ubuntu22_04.append(('waving-z (2.3 MB)',
"""mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE/
git clone https://github.com/baol/waving-z.git
cd ~/Installed_by_FISSURE/waving-z
mkdir build
cd build
sed -i -E 's/^cmake_minimum_required\s*\(\s*VERSION\s+3\.[0-4](\.[0-9]+)?\s*\)/cmake_minimum_required(VERSION 3.5)/' ~/Installed_by_FISSURE/waving-z/CMakeLists.txt
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
########## Verify ##########
ls ~/Installed_by_FISSURE/waving-z/build/wave-in
""",True,'Z-Wave'))

# baudline
programs_ubuntu22_04.append(('baudline (4.9 MB)',
"""mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
wget -P ~/Installed_by_FISSURE/ https://www.baudline.com/baudline_1.08_linux_x86_64.tar.gz  # They removed this file. We are not allowed to distribute source.
tar -xf baudline_1.08_linux_x86_64.tar.gz
rm baudline_1.08_linux_x86_64.tar.gz
########## Verify ##########
~/Installed_by_FISSURE/baudline_1.08_linux_x86_64/baudline --help
""",False,'SDR'))

# Universal Radio Hacker
programs_ubuntu22_04.append(('Universal Radio Hacker (129.2 MB)',
"""python3 -m pip install cython
python3 -m pip install urh
########## Verify ##########
urh --version
""",True,'SDR'))

# Inspectrum
programs_ubuntu22_04.append(('Inspectrum (1.8 MB)',
"""sudo apt-get install -y inspectrum
########## Verify ##########
inspectrum --help
""",True,'SDR'))

# OpenCPN
programs_ubuntu22_04.append(('OpenCPN (209.3 MB)',
"""sudo add-apt-repository -y ppa:opencpn/opencpn
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C865EB40  # FIX
sudo apt-get update
sudo apt-get install -y opencpn
########## Verify ##########
ls /usr/bin/opencpn
""",True,'AIS'))

# Kalibrate
programs_ubuntu22_04.append(('Kalibrate (2.1 MB)',
"""mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/steve-m/kalibrate-rtl.git
cd kalibrate-rtl
./bootstrap && CXXFLAGS='-W -Wall -O3' ./configure && make
########## Verify ##########
ls ~/Installed_by_FISSURE/kalibrate-rtl/src/kal
""",True,'GSM'))

# retrogram-rtlsdr
programs_ubuntu22_04.append(('retrogram-rtlsdr (1.7 MB)',
"""mkdir -p ~/Installed_by_FISSURE
sudo apt-get install -y librtlsdr-dev libncurses5-dev libboost-program-options-dev
cp -R """ + fissure_directory + """/Tools/retrogram-rtlsdr-master ~/Installed_by_FISSURE/
cd ~/Installed_by_FISSURE/retrogram-rtlsdr-master
make
########## Verify ##########
ls ~/Installed_by_FISSURE/retrogram-rtlsdr-master/retrogram-rtlsdr
""",True,'SDR'))

# RTLSDR-Airband
programs_ubuntu22_04.append(('RTLSDR-Airband (7.0 MB)',
"""sudo apt-get install -y build-essential cmake pkg-config libmp3lame-dev libshout3-dev libconfig++-dev libfftw3-dev libpulse-dev
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/szpajder/RTLSDR-Airband.git
cd RTLSDR-Airband
mkdir build
cd build
sed -i -E 's/^[[:space:]]*(cmake_minimum_required|CMAKE_MINIMUM_REQUIRED)[[:space:]]*\([[:space:]]*VERSION[[:space:]]+3\.[0-4]([[:space:]]*)?\)/cmake_minimum_required(VERSION 3.5)/I' ~/Installed_by_FISSURE/RTLSDR-Airband/CMakeLists.txt
cmake ../
make
sudo make install
########## Verify ##########
rtl_airband -h
""",True,'SDR'))

# Spektrum
programs_ubuntu22_04.append(('Spektrum (241.9 MB)',
"""echo 'blacklist dvb_usb_rtl28xxu' | sudo tee /etc/modprobe.d/rtl-sdr.conf  # Restart computer to use RTL device
echo 'SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="2838", GROUP="adm", MODE="0666"' | sudo tee /etc/udev/rules.d/20.rtlsdr.rules
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
wget -P ~/Installed_by_FISSURE/ https://github.com/pavels/spektrum/releases/download/2.1.0/spektrum-linux64.tar.gz
tar -xf spektrum-linux64.tar.gz
rm spektrum-linux64.tar.gz
########## Verify ##########
ls ~/Installed_by_FISSURE/spektrum/spektrum
""",True,'SDR'))

# SDRTrunk
programs_ubuntu22_04.append(('SDRTrunk (106.9 MB)',
"""#sudo apt-get -yq install gnupg curl  # Java (if needed)
#sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 0xB1998361219BD9C9
#cd ~/Downloads
#curl -O https://cdn.azul.com/zulu/bin/zulu-repo_1.0.0-2_all.deb
#sudo apt-get install ./zulu-repo_1.0.0-2_all.deb
#sudo apt-get update
#sudo apt-get install -y zulu11-jdk
#rm zulu-repo_1.0.0-2_all.deb
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
wget -P ~/Installed_by_FISSURE/ https://github.com/DSheirer/sdrtrunk/releases/download/v0.5.0-alpha.6/sdr-trunk-linux-x86_64-v0.5.0-alpha6.zip
unzip -q sdr-trunk-linux-x86_64-v0.5.0-alpha6.zip
rm sdr-trunk-linux-x86_64-v0.5.0-alpha6.zip
########## Verify ##########
ls ~/Installed_by_FISSURE/sdr-trunk-linux-x86_64-v0.5.0-alpha6/bin/sdr-trunk
""",True,'Trunked Radio'))

# Audacity
programs_ubuntu22_04.append(('Audacity (38.8 MB)',
"""sudo apt-get install -y audacity
########## Verify ##########
audacity --version
""",True,'Audio'))

# Sound eXchange
programs_ubuntu22_04.append(('Sound eXchange (2.3 MB)',
"""sudo apt-get install -y sox
########## Verify ##########
sox --version
""",True,'Audio'))

# LAME
programs_ubuntu22_04.append(('LAME (286.8 kB)',
"""sudo apt-get install -y lame
########## Verify ##########
lame --version
""",True,'Audio'))

# mpv
programs_ubuntu22_04.append(('mpv (174.7 MB)',
"""sudo apt-get install -y mpv
########## Verify ##########
mpv --version
""",True,'Audio'))

# FFmpeg
programs_ubuntu22_04.append(('FFmpeg (114.7 kB)',
"""sudo apt-get install -y ffmpeg 
########## Verify ##########
ffmpeg --help
""",True,'Audio'))

# MPlayer
programs_ubuntu22_04.append(('MPlayer (10.4 MB)',
"""sudo apt-get install -y mplayer
########## Verify ##########
ls /usr/bin/mplayer
""",True,'Audio'))

# VLC
programs_ubuntu22_04.append(('VLC (402.1 MB)',
"""sudo apt-get install -y vlc
########## Verify ##########
vlc --help
""",True,'Video'))

# Simple Screen Recorder
programs_ubuntu22_04.append(('Simple Screen Recorder (5.6 MB)',
"""sudo apt-get install -y simplescreenrecorder
########## Verify ##########
simplescreenrecorder --help
""",False,'Video'))

# radiosonde_auto_rx
programs_ubuntu22_04.append(('radiosonde_auto_rx (82.4 MB)',
"""sudo apt-get install -y python3 python3-numpy python3-setuptools python3-crcmod python3-requests python3-dateutil python3-pip python3-flask sox git build-essential libtool cmake usbutils libusb-1.0-0-dev rng-tools libsamplerate-dev libatlas3-base libgfortran5
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/projecthorus/radiosonde_auto_rx.git
cd radiosonde_auto_rx/auto_rx
./build.sh
cp station.cfg.example station.cfg
python3 -m pip install -r requirements.txt
########## Verify ##########
ls ~/Installed_by_FISSURE/radiosonde_auto_rx/auto_rx/auto_rx.py
""",True,'Radiosonde'))

# SdrGlut
programs_ubuntu22_04.append(('SdrGlut',
"""sudo apt-get install -y build-essential libwxgtk3.2-dev libglew-dev libusb-dev libsoapysdr-dev libopenal-dev libliquid-dev freeglut3-dev libalut-dev libsndfile1-dev librtaudio-dev libhdf4-dev libfftw3-dev
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone --depth=1 https://github.com/righthalfplane/SdrGlut.git
cd SdrGlut
make -f makefileUbuntu -j 8
cd iqSDR
make -f makefileUbuntuOLD -j 8
########## Verify ##########
ls ~/Installed_by_FISSURE/SdrGlut/sdrglut.x
""",True,'SDR'))

# rehex
programs_ubuntu22_04.append(('rehex (197.1 MB)',
"""sudo apt-get install -y build-essential git libwxgtk3.0-gtk3-dev libjansson-dev libcapstone-dev liblua5.3-dev lua5.3 lua5.2 libunistring-dev libgtk-3-dev lua-busted libbotan-2-dev
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/solemnwarning/rehex.git
cd rehex
sudo git config --global --add safe.directory """ + os.path.expanduser('~') + """/Installed_by_FISSURE/rehex
yes | sudo cpan Template
sudo make install
########## Verify ##########
ls /usr/local/bin/rehex 
""",True,'Data'))

# ZEPASSD
programs_ubuntu22_04.append(('ZEPASSD (11.6 MB)',
"""#sudo apt-get install -y # boost.program-options, boost.crc, boost.circular-buffer, libfftw3, libuhd 3.9.5 or later
sudo apt-get install -y libuhd-dev
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/pvachon/zepassd.git
cd zepassd
make
########## Verify ##########
ls ~/Installed_by_FISSURE/zepassd/zepassd
""",True,'RFID'))

# iridium-toolkit
programs_ubuntu22_04.append(('iridium-toolkit (3.3 MB)',
"""#Python (2.7), NumPy (scipy), crcmod
sudo apt-get install -y mplayer
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/muccc/iridium-toolkit.git
git clone git://git.osmocom.org/osmo-ir77
cd osmo-ir77/codec/
sudo make
cp ir77_ambe_decode ~/Installed_by_FISSURE/iridium-toolkit/
########## Verify ##########
ls ~/Installed_by_FISSURE/osmo-ir77/codec/ir77_ambe_decode
""",True,'Satellite'))

# IridiumLive
programs_ubuntu22_04.append(('IridiumLive (97.2 MB)',
"""mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/microp11/iridiumlive.git
wget -P ~/Installed_by_FISSURE/ https://github.com/microp11/iridiumlive/releases/download/v1.2/linux-x64.zip
unzip -q linux-x64.zip
rm linux-x64.zip
cd linux-x64
sudo chmod +x IridiumLive
########## Verify ##########
ls ~/Installed_by_FISSURE/linux-x64/IridiumLive
""",True,'Satellite'))

# NETATTACK2 - Fix
programs_ubuntu22_04.append(('NETATTACK2',
"""#sudo pip install netifaces  # fix for python2
#sudo apt-get install -y python-scapy python-nmap python-nfqueue nmap  # this needs to be fixed, can it still run with python2?
python2 -m pip install netifaces
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/chrizator/netattack2.git
python2 -m pip install nmap
cd netattack2
wget http://archive.ubuntu.com/ubuntu/pool/universe/libn/libnetfilter-queue/libnetfilter-queue1_1.0.2-2_amd64.deb
sudo dpkg -i libnetfilter-queue1_1.0.2-2_amd64.deb
wget http://archive.ubuntu.com/ubuntu/pool/universe/n/nfqueue-bindings/python-nfqueue_0.6-1build2_amd64.deb
sudo dpkg -i python-nfqueue_0.6-1build2_amd64.deb 
""",False,'802.11'))

# Wifite
programs_ubuntu22_04.append(('Wifite (797.5 MB)',
"""echo "macchanger macchanger/automatically_run boolean false" | sudo debconf-set-selections
# python, iwconfig, ifconfig, Aircrack-ng, tshark, reaver, bully, coWPAtty, pyrit, hashcat, hcxdumptool, hcxpcaptool
sudo apt-get install -y build-essential libpcap-dev aircrack-ng pixiewps libssl-dev hashcat libcurl4-openssl-dev pkg-config macchanger python-is-python3
python3 -m pip install psycopg2-binary #scapy (python3 scapy with pip causes errors)
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/derv82/wifite2.git
git clone https://github.com/t6x/reaver-wps-fork-t6x
cd reaver-wps-fork-t6x/src
./configure
make
sudo make install
cd ~/Installed_by_FISSURE
git clone https://github.com/aanarchyy/bully
cd bully/src
make
sudo make install
cd ~/Installed_by_FISSURE
wget http://www.willhackforsushi.com/code/cowpatty/4.6/cowpatty-4.6.tgz
tar zxfv cowpatty-4.6.tgz
rm cowpatty-4.6.tgz
cd cowpatty-4.6
make
sudo cp cowpatty /usr/bin
cd ~/Installed_by_FISSURE
mkdir Pyrit-v0.5.0
cd Pyrit-v0.5.0
wget https://github.com/JPaulMora/Pyrit/releases/download/v0.5.0/Pyrit-v0.5.0.zip
unzip -q Pyrit-v0.5.0.zip
rm Pyrit-v0.5.0.zip
sudo apt-get install -y python2-dev
python2 setup.py clean
python2 setup.py build
sudo python2 setup.py install
cd ~/Installed_by_FISSURE
git clone https://github.com/ZerBea/hcxdumptool.git
cd hcxdumptool
make
sudo make install
cd ~/Installed_by_FISSURE
git clone https://github.com/ZerBea/hcxtools.git
cd hcxtools
make
sudo make install
sudo ln -s /usr/bin/hcxpcapngtool /usr/bin/hcxpcaptool
#sudo apt-get install -y tshark
""",False,'802.11'))

# rtl_433
programs_ubuntu22_04.append(('rtl_433 (27.8 MB)',
"""#sudo apt-get install -y rtl-433
sudo apt-get install -y libtool libusb-1.0-0-dev librtlsdr-dev rtl-sdr build-essential cmake pkg-config
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/merbanan/rtl_433.git
cd rtl_433/
mkdir build
cd build
cmake ..
make
sudo make install
########## Verify ##########
rtl_433 -help
""",True,'433 MHz'))

# RouterSploit
programs_ubuntu22_04.append(('RouterSploit (369.3 MB)',
"""sudo apt-get install -y python3-pip libglib2.0-dev rustc
python3 -m pip install setuptools-rust
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://www.github.com/threat9/routersploit
cd routersploit
python3 -m pip install setuptools
python3 -m pip install -r requirements.txt
python3 -m pip install bluepy
########## Verify ##########
~/Installed_by_FISSURE/routersploit/rsf.py --help
""",True,'802.11'))

# Metasploit
programs_ubuntu22_04.append(('Metasploit (1.1 GB)',
"""mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
mkdir metasploit
cd metasploit
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
########## Verify ##########
ls /usr/bin/msfconsole
""",True,'802.11'))

# monitor_rtl433
programs_ubuntu22_04.append(('monitor_rtl433 (54.6 MB)',
"""mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/mcbridejc/monitor_rtl433.git
cd monitor_rtl433
python3 -m pip install . --force-reinstall --ignore-installed
python3 -m pip install python-dateutil
python3 -m pip install flask_table
########## Verify ##########
ls /usr/local/bin/monitor_rtl433
""",True,'433 MHz'))

# scan-ssid
programs_ubuntu22_04.append(('scan-ssid (585.8 kB)',
"""mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
sudo apt-get install -y iw
git clone https://github.com/Resethel/scan-ssid.git
cd scan-ssid
sudo cp scan-ssid /usr/local/bin
sudo chmod 755 /usr/local/bin/scan-ssid  # can't be in monitor mode, managed only
########## Verify ##########
scan-ssid --help
""",True,'802.11'))

# minimodem
programs_ubuntu22_04.append(('minimodem (217.1 kB)',
"""sudo apt-get install -y minimodem
########## Verify ##########
minimodem --version
""",True,'Audio'))

# WSJT-X
programs_ubuntu22_04.append(('WSJT-X (35.2 MB)',
"""sudo apt-get install -y wsjtx
########## Verify ##########
ls /usr/bin/wsjtx
""",True,'Ham Radio'))

# Google Earth Pro
programs_ubuntu22_04.append(('Google Earth Pro (314.6 MB)',
"""mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
wget https://dl.google.com/dl/earth/client/current/google-earth-pro-stable_current_amd64.deb
sudo dpkg -i google-earth-pro-stable_current_amd64.deb
########## Verify ##########
ls /usr/bin/google-earth-pro
""",True,'Mapping'))

# gr-air-modes
programs_ubuntu22_04.append(('gr-air-modes (1.3 MB)',
"""sudo apt-get install -y gr-air-modes
sudo sed -i 's/numpy.float)/numpy.float32)/g' /usr/lib/python3/dist-packages/air_modes/mlat.py  # Deprecated numpy type: np.float->np.float32 or np.float64
########## Verify ##########
modes_rx --help
""",True,'Aircraft'))

# ESP8266 Deauther v2
programs_ubuntu22_04.append(('ESP8266 Deauther v2 (6.6 MB)',
"""mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
wget https://github.com/SpacehuhnTech/esp8266_deauther/archive/v2.zip
unzip -q v2.zip
rm v2.zip
""",True,'802.11'))

# Viking
programs_ubuntu22_04.append(('Viking (531.5 MB)',
"""mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone git://git.code.sf.net/p/viking/code viking
sudo apt install -y gtk-doc-tools docbook-xsl yelp-tools libpng-dev libgtk-3-dev libicu-dev libjson-glib-dev intltool
sudo apt-get install -y libcurl4-gnutls-dev libglib2.0-dev-bin
sudo apt-get install -y libsqlite3-dev nettle-dev libmapnik-dev libgeoclue-2-dev libgexiv2-dev libgps-dev libmagic-dev libbz2-dev libzip-dev liboauth-dev
sudo apt-get install -y autopoint libnova-dev
cd viking
./autogen.sh
./configure
make
sudo make install
########## Verify ##########
viking --help
""",True,'Mapping'))

# PyGPSClient
programs_ubuntu22_04.append(('PyGPSClient (27.3 MB)',
"""sudo apt install -y python3-pip python3-tk python3-pil python3-pil.imagetk
sudo apt remove -y python3-cryptography
python3 -m pip install --upgrade PyGPSClient
########## Verify ##########
ls /usr/local/bin/pygpsclient
""",True,'GPS'))

# Gpredict
programs_ubuntu22_04.append(('Gpredict (17.6 MB)',
"""sudo apt-get install -y gpredict
########## Verify ##########
gpredict --help
""",True,'GPS'))

# FoxtrotGPS
programs_ubuntu22_04.append(('FoxtrotGPS (2.8 MB)',
"""sudo apt-get install -y foxtrotgps
########## Verify ##########
foxtrotgps --help
""",True,'GPS'))

# multimon-ng
programs_ubuntu22_04.append(('multimon-ng (13.6 MB)',
"""sudo apt-get install -y libpulse-dev
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/EliasOenal/multimonNG.git
cd multimonNG
mkdir build
cd build
qmake ../multimon-ng.pro
make
sudo make install
########## Verify ##########
ls /usr/local/bin/multimon-ng
""",True,'POCSAG'))

# Xastir
programs_ubuntu22_04.append(('Xastir (53.3 MB)',
"""echo 'xastir xastir/setuid boolean true' | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y xastir
########## Verify ##########
sudo xastir -V
""",True,'Ham Radio'))

# LTE-Cell-Scanner
programs_ubuntu22_04.append(('LTE-Cell-Scanner (168.1 MB)',
"""sudo apt-get install -y cmake libncurses5-dev liblapack-dev libblas-dev libboost-thread-dev libboost-system-dev libitpp-dev librtlsdr-dev libfftw3-dev
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/JiaoXianjun/LTE-Cell-Scanner.git
cd LTE-Cell-Scanner
mkdir build
cd build
sed -i -E 's/[Cc][Mm][Aa][Kk][Ee]_MINIMUM_REQUIRED\s*\(\s*VERSION\s+2\.[0-9]+(\.[0-9]+)?\s*\)/cmake_minimum_required(VERSION 3.5)/' ~/Installed_by_FISSURE/LTE-Cell-Scanner/CMakeLists.txt
cmake ..
make 
sudo make install
########## Verify ##########
ls /usr/local/bin/CellSearch
""",True,'LTE'))

# btscanner
programs_ubuntu22_04.append(('btscanner (1.3 MB)',
"""sudo apt-get install -y btscanner
########## Verify ##########
btscanner --help
""",True,'Bluetooth'))

# hcidump
programs_ubuntu22_04.append(('hcidump (1.1 MB)',
"""sudo apt-get install -y bluez-hcidump
########## Verify ##########
hcidump --help
""",True,'Bluetooth'))

# GraphicsMagick
programs_ubuntu22_04.append(('GraphicsMagick (6.0 MB)',
"""sudo apt-get install -y graphicsmagick-imagemagick-compat
########## Verify ##########
gm -help
""",True,'SDR'))

# Spectrum Painter
programs_ubuntu22_04.append(('Spectrum Painter (13.8 MB)',
"""python3 -m pip install numpy imageio 
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/polygon/spectrum_painter.git
#cd spectrum_painter/
#pip3 install --user -e .  # call with "python3 -m spectrum_painter.img2iqstream"
""",True,'SDR'))

# nrsc5 and nrsc5-gui
programs_ubuntu22_04.append(('nrsc5 (116.2 MB)',
"""sudo apt install -y git build-essential cmake autoconf libtool libao-dev libfftw3-dev librtlsdr-dev libgsl-dev python3-pyaudio
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/theori-io/nrsc5.git
cd nrsc5
mkdir build
cd build
cmake ..
make
sudo make install
sudo ldconfig
# nrsc5-gui
python3 -m pip install --upgrade Pillow
python3 -m pip install pyaudio
sudo apt-get install -y python-gobject
cd ~/Installed_by_FISSURE
git clone https://github.com/cmnybo/nrsc5-gui.git
########## Verify ##########
nrsc5 -v
""",True,'HD Radio'))

# HAM2MON
programs_ubuntu22_04.append(('HAM2MON (901.1 kB)',
"""mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/bkerler/ham2mon.git
cp -f """ + fissure_directory + """/Tools/ham2mon/cursesgui.py ~/Installed_by_FISSURE/ham2mon/apps/
""",True,'Ham Radio'))

# Anki
programs_ubuntu22_04.append(('Anki (223.5 MB)',
"""sudo apt-get install -y anki
########## Verify ##########
anki -h
""",True,'Ham Radio'))

# Bless
programs_ubuntu22_04.append(('Bless (4.00 kB)',
"""sudo apt-get install -y snapd
sudo snap install bless-unofficial
########## Verify ##########
snap list bless-unofficial
""",True,'Data'))

# trackerjacker - Fix (needs newer scapy version, something else (netattack2?) resets it, some pieces don't work while running it)
programs_ubuntu22_04.append(('trackerjacker',
"""sudo ln -s -f /usr/lib/x86_64-linux-gnu/libc.a /usr/lib/x86_64-linux-gnu/liblibc.a  # Python3.9 missing file
sudo sed -i 's/tostring/tobytes/g' /usr/local/lib/python3.10/dist-packages/scapy/arch/linux.py
python3 -m pip install trackerjacker
########## Verify ##########
sudo trackerjacker --help
""",True,'802.11'))

# airgeddon
programs_ubuntu22_04.append(('airgeddon (222.1 MB)',
"""sudo apt-get install -y crunch mdk3 hostapd lighttpd ruby-dev xterm isc-dhcp-server ettercap-text-only john
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone --depth 1 https://github.com/v1s1t0r1sh3r3/airgeddon.git
#asleap
mkdir asleap
cd asleap
wget http://http.kali.org/pool/main/a/asleap/asleap_2.3~git20201128.254acab-0kali1_amd64.deb
sudo dpkg -i asleap_2.3~git20201128.254acab-0kali1_amd64.deb
#bettercap
sudo apt-get install -y build-essential libpcap-dev net-tools 
cd ~/Installed_by_FISSURE
mkdir bettercap
cd bettercap
wget https://github.com/bettercap/bettercap/releases/download/v2.31.1/bettercap_linux_amd64_v2.31.1.zip
unzip -q bettercap_linux_amd64_v2.31.1.zip
rm bettercap_linux_amd64_v2.31.1.zip
sudo cp bettercap /usr/bin/
#mdk4
sudo apt-get install -y libnl-genl-3-dev
cd ~/Installed_by_FISSURE
git clone https://github.com/aircrack-ng/mdk4
cd mdk4
make
sudo make install
""",True,'802.11'))

# Hydra
programs_ubuntu22_04.append(('Hydra (13.3 MB)',
"""sudo apt-get install -y hydra
########## Verify ##########
ls /usr/bin/hydra
""",True,'SSH'))

# Enscribe
programs_ubuntu22_04.append(('Enscribe (90.1 MB)',
"""sudo apt-get install -y enscribe
########## Verify ##########
ls /usr/bin/enscribe
""",True,'Audio'))

# ESP32 Bluetooth Classic Sniffer
programs_ubuntu22_04.append(('ESP32 BT Classic Sniffer (400.0 MB)',
"""# Now contains errors caused by newer wireshark versions. Not supporting this until it is fixed.
mkdir -p ~/Installed_by_FISSURE  # Requires Wireshark 3.4 by default, modifying it for 3.6.5, 4.0.3, 4.2.5
cd ~/Installed_by_FISSURE
git clone https://github.com/Matheus-Garbelini/esp32_bluetooth_classic_sniffer
cd esp32_bluetooth_classic_sniffer
#rm ./dissectors/config.h  # Produces errors if missing
sed -i 's/VERSION "3.4.0"/VERSION "4.2.5"/g' ./dissectors/config.h
sed -i 's/VERSION_MAJOR 3/VERSION_MAJOR 4/g' ./dissectors/config.h
sed -i 's/VERSION_MINOR 4/VERSION_MINOR 2/g' ./dissectors/config.h
sed -i 's/VERSION_MICRO 0/VERSION_MICRO 5/g' ./dissectors/config.h
sed -i 's/PLUGIN_PATH_ID "3.4"/PLUGIN_PATH_ID "4.2"/g' ./dissectors/config.h
sed -i 's/Bluetooth Link Manager Protocol/ESP32 Bluetooth Link Manager Protocol/g' ./dissectors/packet-btbrlmp.c
sed -i 's/btlmp/esp32_btlmp/g' ./dissectors/packet-btbrlmp.c
sed -i 's/3.4/4.2/g' ./dissectors/build.sh
sudo ./requirements.sh
./build.sh
sudo cp dissectors/h4bcm.so /usr/lib/x86_64-linux-gnu/wireshark/plugins/4.2/epan/  # Placing it where "sudo Wireshark" dissectors are located
rm ~/.local/lib/wireshark/plugins/4.2/epan/h4bcm.so  # To avoid "plugin 'h4bcm.so' was found in multiple directories" warning
########## Verify ##########
ls /usr/lib/x86_64-linux-gnu/wireshark/plugins/4.2/epan/h4bcm.so
""",False,'Bluetooth'))

# SigDigger
programs_ubuntu22_04.append(('SigDigger (48.00 kB)',
"""sudo apt-get install -y libsndfile1-dev libfftw3-dev qmake6 soapysdr-tools libsoapysdr-dev fuse
mkdir -p ~/Installed_by_FISSURE/SigDigger
cd ~/Installed_by_FISSURE/SigDigger
wget https://github.com/BatchDrake/SigDigger/releases/download/v0.3.0/SigDigger-0.3.0-x86_64-full.AppImage  # Needs newer version of QMake. Above 5.12.8, 5.14?
chmod a+x SigDigger-0.3.0-x86_64-full.AppImage
########## Verify ##########
ls ~/Installed_by_FISSURE/SigDigger/SigDigger-0.3.0-x86_64-full.AppImage
""",True,'SDR'))

# QSSTV
programs_ubuntu22_04.append(('QSSTV (2.8 MB)',
"""sudo apt-get install -y qsstv
########## Verify ##########
ls /usr/bin/qsstv
""",True,'Ham Radio'))

# m17-cxx-demod
programs_ubuntu22_04.append(('m17-cxx-demod (21.8 MB)',
"""sudo apt-get install -y libcodec2-dev libboost-dev libgtest-dev
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://bitbucket.org/blaze-lib/blaze.git
sudo mkdir -p /usr/local/include/blaze
sudo cp -r blaze/blaze /usr/local/include/
cd ~/Installed_by_FISSURE
git clone https://github.com/mobilinkd/m17-cxx-demod.git
cd m17-cxx-demod/
mkdir build
cd build
cmake ..
make
sudo make install
########## Verify ##########
ls /usr/local/bin/m17-demod
""",True,'M17'))

# Fldigi
programs_ubuntu22_04.append(('Fldigi (15.1 MB)',
"""sudo apt-get install -y fldigi
########## Verify ##########
ls /usr/bin/fldigi
""",True,'Ham Radio'))

# pyFDA
programs_ubuntu22_04.append(('pyFDA (11.7 MB)',
"""python3 -m pip install pyfda --use-pep517  # Has PEP issues with Python 3.10
########## Verify ##########
pyfdax -h
""",True,'Filters'))

# Bootable USB
programs_ubuntu22_04.append(('Bootable USB (107.4 MB)',
"""sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 382003C2C8B7B4AB813E915B14E4942973C62A1B
sudo add-apt-repository -y "deb http://ppa.launchpad.net/nemh/systemback/ubuntu xenial main"
sudo apt update
sudo apt install -y systemback
sudo add-apt-repository -y ppa:mkusb/ppa
sudo apt-get update
sudo apt-get install -y mkusb usb-pack-efi mkusb-plug guidus
########## Verify ##########
ls /usr/bin/systemback && ls /usr/bin/guidus
""",True,'Development'))

# Dire Wolf
programs_ubuntu22_04.append(('Dire Wolf (207.8 MB)',
"""sudo apt-get -y install git gcc g++ make cmake libasound2-dev libudev-dev
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://www.github.com/wb2osz/direwolf
cd direwolf
git checkout dev
mkdir build && cd build
cmake ..
make -j4
sudo make install
make install-conf
########## Verify ##########
ls /usr/local/bin/direwolf
""",True,'Ham Radio'))

# Meld
programs_ubuntu22_04.append(('Meld (9.4 MB)',
"""sudo apt-get -y install meld
########## Verify ##########
ls /usr/bin/meld
""",True,'Data'))

# nwdiag
programs_ubuntu22_04.append(('nwdiag (30.3 MB)',
"""python3 -m pip install nwdiag
########## Verify ##########
packetdiag -h
""",True,'Data'))

# HamClock
programs_ubuntu22_04.append(('HamClock (41.2 MB)',
"""mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
wget https://www.clearskyinstitute.com/ham/HamClock/ESPHamClock.zip
unzip -q ESPHamClock.zip
rm ESPHamClock.zip
cd ESPHamClock
make install hamclock-1600x960
sudo make install hamclock-1600x960
########## Verify ##########
ls /usr/local/bin/hamclock
""",True,'Ham Radio'))

# ICE9 Bluetooth Sniffer
programs_ubuntu22_04.append(('ICE9 Bluetooth Sniffer (10.4 MB)',
"""sudo apt install -y libliquid-dev libbtbb-dev libuhd-dev
sudo apt-get install -y libhackrf-dev libbladerf-dev  # Separating in case there are conflicts with Hardware install
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/mikeryan/ice9-bluetooth-sniffer.git
cd ice9-bluetooth-sniffer
mkdir build
cd build
cmake ..
make
sudo make install
########## Verify ##########
ls ~/Installed_by_FISSURE/ice9-bluetooth-sniffer/build/ice9-bluetooth
""",True,'Bluetooth'))

# dump978
programs_ubuntu22_04.append(('dump978 (2.0 MB)',
"""mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/mutability/dump978.git
cd dump978
make
########## Verify ##########
ls ~/Installed_by_FISSURE/dump978/dump978
""",True,'Aircraft'))

# htop
programs_ubuntu22_04.append(('htop (782.4 kB)',
"""sudo apt-get install -y htop
########## Verify ##########
ls /usr/bin/htop
""",True,'Development'))

# OpenWebRX
programs_ubuntu22_04.append(('OpenWebRX (50.4 MB)',
"""echo -e "\nEnter sudo password for adding key (hidden prompt)\n"
wget -O - https://repo.openwebrx.de/debian/key.gpg.txt | sudo apt-key add
echo 'deb https://repo.openwebrx.de/ubuntu/ jammy main' | sudo tee /etc/apt/sources.list.d/openwebrx.list
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y openwebrx
sudo openwebrx admin adduser admin
sudo systemctl stop openwebrx
sudo systemctl disable openwebrx  # Prevents starting on boot
########## Verify ##########
ls /usr/bin/openwebrx
""",True,'SDR'))

# CRC RevEng
programs_ubuntu22_04.append(('CRC RevEng (905.3 kB)',
"""mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
wget -T 10 https://sourceforge.net/projects/reveng/files/3.0.5/reveng-3.0.5.zip/download
unzip download
rm download
cd reveng-3.0.5
make
########## Verify ##########
ls ~/Installed_by_FISSURE/reveng-3.0.5/bin/i386-linux/reveng
""",True,'Data'))

# wl-color-picker
programs_ubuntu22_04.append(('wl-color-picker (643.1 kB)',
"""sudo apt-get install -y slurp grim wl-clipboard
cd ~/Installed_by_FISSURE
git clone https://github.com/jgmdev/wl-color-picker.git
########## Verify ##########
ls ~/Installed_by_FISSURE/wl-color-picker/wl-color-picker.sh
""",True,'Development'))

# GHex
programs_ubuntu22_04.append(('GHex',
"""sudo apt-get install -y ghex
########## Verify ##########
ls /usr/bin/ghex
""",True,'Data'))

# Archive Flow Graphs
programs_ubuntu22_04.append(('Archive Flow Graphs',
"""cd """ + fissure_directory + """/Flow\ Graph\ Library/maint-3.10/Archive\ Flow\ Graphs/
find . -name '*.grc' -exec grcc {} \;
""",True,'Compile Flow Graphs'))

# Fuzzing Flow Graphs
programs_ubuntu22_04.append(('Fuzzing Flow Graphs',
"""cd """ + fissure_directory + """/Flow\ Graph\ Library/maint-3.10/Fuzzing\ Flow\ Graphs/
find . -name '*.grc' -exec grcc {} \;
""",True,'Compile Flow Graphs'))

# Inspection Flow Graphs
programs_ubuntu22_04.append(('Inspection Flow Graphs',
"""cd """ + fissure_directory + """/Flow\ Graph\ Library/maint-3.10/Inspection\ Flow\ Graphs/
find . -name '*.grc' -exec grcc {} \;
""",True,'Compile Flow Graphs'))

# IQ Flow Graphs
programs_ubuntu22_04.append(('IQ Flow Graphs',
"""cd """ + fissure_directory + """/Flow\ Graph\ Library/maint-3.10/IQ\ Flow\ Graphs/
find . -name '*.grc' -exec grcc {} \;
""",True,'Compile Flow Graphs'))

# Plugin Flow Graphs
programs_ubuntu22_04.append(('Plugin Flow Graphs',
"""cd """ + fissure_directory + """/Plugins/

# Compile all plugin flow graphs except GNU Radio 3.8-specific flow graphs.
find . -name '*.grc' \\
    -not -path '*/maint-3.8/*' \\
    -exec grcc {} \\;
""", True, 'Compile Flow Graphs'))

# PD Flow Graphs
programs_ubuntu22_04.append(('PD Flow Graphs',
"""cd """ + fissure_directory + """/Flow\ Graph\ Library/maint-3.10/PD\ Flow\ Graphs/
find . -name '*.grc' -exec grcc {} \;
""",True,'Compile Flow Graphs'))

# Single-Stage Flow Graphs
programs_ubuntu22_04.append(('Single-Stage Flow Graphs',
"""cd """ + fissure_directory + """/Flow\ Graph\ Library/maint-3.10/Single-Stage\ Flow\ Graphs/
find . -name '*.grc' -exec grcc {} \;
""",True,'Compile Flow Graphs'))

# Sniffer Flow Graphs
programs_ubuntu22_04.append(('Sniffer Flow Graphs',
"""cd """ + fissure_directory + """/Flow\ Graph\ Library/maint-3.10/Sniffer\ Flow\ Graphs/
find . -name '*.grc' -exec grcc {} \;
""",True,'Compile Flow Graphs'))

# Standalone Flow Graphs
programs_ubuntu22_04.append(('Standalone Flow Graphs',
"""cd """ + fissure_directory + """/Flow\ Graph\ Library/maint-3.10/Standalone\ Flow\ Graphs/
find . -name '*.grc' -exec grcc {} \;
""",True,'Compile Flow Graphs'))

# TSI Flow Graphs
programs_ubuntu22_04.append(('TSI Flow Graphs',
"""cd """ + fissure_directory + """/Flow\ Graph\ Library/maint-3.10/TSI\ Flow\ Graphs/
find . -name '*.grc' -exec grcc {} \;
""",True,'Compile Flow Graphs'))

# Trigger Flow Graphs
programs_ubuntu22_04.append(('Trigger Flow Graphs',
"""cd """ + fissure_directory + """/Flow\ Graph\ Library/maint-3.10/Triggers/
find . -name '*.grc' -exec grcc {} \;
""",True,'Compile Flow Graphs'))

# pyais
programs_ubuntu22_04.append(('pyais',
"""python3 -m pip install pyais
########## Verify ##########
ls /usr/local/lib/python3*/dist-packages/pyais
""",True,'AIS'))

# HAMRS
programs_ubuntu22_04.append(('HAMRS (105.8 MB)',
"""mkdir -p ~/Installed_by_FISSURE/HAMRS
cd ~/Installed_by_FISSURE/HAMRS
wget https://hamrs-releases.s3.us-east-2.amazonaws.com/1.0.6/hamrs-1.0.6-linux-x86_64.AppImage
sudo chmod +x hamrs*
########## Verify ##########
ls ~/Installed_by_FISSURE/HAMRS/hamrs*
""",True,'Ham Radio'))

# Binwalk
programs_ubuntu22_04.append(('Binwalk',
"""sudo apt-get install -y python3-binwalk binwalk
########## Verify ##########
ls /usr/bin/binwalk
""",False,'Data'))

# Read the Docs
programs_ubuntu22_04.append(('Read the Docs',
"""python3 -m pip install sphinx
python3 -m pip install sphinx_rtd_theme
########## Verify ##########
python3 -m pip show sphinx_rtd_theme
""",True,'Development'))

# IQEngine
programs_ubuntu22_04.append(('IQEngine',
"""if command -v docker > /dev/null 2>&1; then
  echo "Docker is installed."
else
  echo "Docker is not installed."
  sudo apt-get install -y docker.io
  #sudo systemctl start docker
  #sudo systemctl enable docker
  sudo usermod -aG docker ${USER}  # Reboot computer to use docker commands without sudo
  #newgrp docker
fi
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
git clone https://github.com/IQEngine/IQEngine.git
cd ~/Installed_by_FISSURE/IQEngine
cp example.env .env
docker run --env-file .env -v '""" + fissure_directory + """/IQ Recordings':/tmp/myrecordings -p 3001:3000 --pull=always -d ghcr.io/iqengine/iqengine:pre
docker stop $(docker ps -q --filter ancestor=ghcr.io/iqengine/iqengine:pre)
########## Verify ##########
sudo docker run hello-world
""",True,'Data'))

# TAK Server
programs_ubuntu22_04.append(('TAK Server',
"""# Create TAK.gov account and download TAKSERVER-DOCKER-#.#-RELEASE-##.ZIP from https://tak.gov/products/tak-server
# Place ZIP file in ~/Installed_by_FISSURE folder and then run this installer item!

if command -v docker > /dev/null 2>&1; then
  echo "Docker is installed."
else
  echo "Docker is not installed."
  sudo apt-get install -y docker.io
  #sudo systemctl start docker
  #sudo systemctl enable docker
  sudo usermod -aG docker ${USER}  # Reboot computer to use docker commands without sudo
  #newgrp docker
fi

mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE

# Unzip and move into the extracted directory
unzip takserver-docker-*.zip
if [ -n "$(find . -maxdepth 1 -type d -name 'takserver-docker-*' -print -quit)" ]; then
    cd takserver-docker-*/

    # Ensure CoreConfig.xml exists
    [ ! -f tak/CoreConfig.xml ] && cp tak/CoreConfig.example.xml tak/CoreConfig.xml

    # Set database password
    sed -i 's/password=""/password="atakatak"/' tak/CoreConfig.xml

    # Build and start the database
    sudo docker build -t takserver-db:"$(cat tak/version.txt)" -f docker/Dockerfile.takserver-db .
    sudo docker network create takserver-"$(cat tak/version.txt)"

    # Set executable permissions for necessary scripts
    chmod +x tak/db-utils/configureInDocker.sh
    chmod +x tak/certs/makeRootCa.sh
    chmod +x tak/certs/makeCert.sh

    sudo docker run -d \
      -v $(pwd)/tak:/opt/tak:z \
      -p 5432:5432 \
      --network takserver-"$(cat tak/version.txt)" \
      --network-alias tak-database \
      --name takserver-db-"$(cat tak/version.txt)" \
      takserver-db:"$(cat tak/version.txt)"

    # Wait for the database to be fully ready
    echo "Waiting for PostgreSQL to be ready..."
    until sudo docker exec takserver-db-"$(cat tak/version.txt)" psql -U martiuser -d cot -c "SELECT 1;" &>/dev/null; do
        sleep 3
        echo "Waiting for database..."
    done
    echo "Database is ready!"

    # Build and start TAK Server
    sudo docker build -t takserver:"$(cat tak/version.txt)" -f docker/Dockerfile.takserver .
    sudo docker run -d \
      -v $(pwd)/tak:/opt/tak:z \
      -p 8089:8089 -p 8443:8443 -p 8444:8444 -p 8446:8446 -p 9000:9000 -p 9001:9001 \
      --network takserver-"$(cat tak/version.txt)" \
      --name takserver-"$(cat tak/version.txt)" \
      takserver:"$(cat tak/version.txt)"

    # Modify certificate metadata
    sed -i 's/^STATE=.*/STATE="test_state"/' tak/certs/cert-metadata.sh
    sed -i 's/^CITY=.*/CITY="test_city"/' tak/certs/cert-metadata.sh
    sed -i 's/^ORGANIZATIONAL_UNIT=.*/ORGANIZATIONAL_UNIT="test_organization"/' tak/certs/cert-metadata.sh
    sed -i 's/^ORGANIZATION=.*/ORGANIZATION="test_org"/' tak/certs/cert-metadata.sh

    # Generate Root CA
    sudo docker exec takserver-"$(cat tak/version.txt)" bash -c "cd /opt/tak/certs && ./makeRootCa.sh"

    # Ensure CA certificate exists before continuing
    sudo docker exec takserver-"$(cat tak/version.txt)" bash -c "test -f /opt/tak/certs/files/ca.pem || (echo 'CA generation failed!' && exit 1)"

    # Generate Certificates
    sudo docker exec takserver-"$(cat tak/version.txt)" bash -c "cd /opt/tak/certs && ./makeCert.sh server takserver"
    sudo docker exec takserver-"$(cat tak/version.txt)" bash -c "cd /opt/tak/certs && ./makeCert.sh client admin"
    sudo docker exec takserver-"$(cat tak/version.txt)" bash -c "cd /opt/tak/certs && ./makeCert.sh client webadmin"

    # Ensure directories have correct permissions
    sudo find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -type d -exec chmod 755 {} +
      
    sudo openssl rsa -in "$(find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -name 'takserver.key' | head -n 1)" \
        -out "$(find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -type d | head -n 1)/takserver.key.unencrypted" \
        -passin pass:"atakatak"

    sudo mv "$(ls -d ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files | head -n 1)/takserver.key.unencrypted" \
      "$(ls -d ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files | head -n 1)/takserver.key"

    # Set ownership for all certificate-related files to the current user
    sudo find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -type f -exec chown $USER:$USER {} +
    sudo find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -type d -exec chown $USER:$USER {} +

    # Set proper permissions for private keys
    sudo find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -type f -name "*.key" -exec chmod 644 {} +

    # Set correct permissions for other certificate files
    sudo find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -type f -not -name "*.key" -exec chmod 644 {} +

    # Restart TAK Server to apply changes
    sudo docker restart takserver-"$(cat tak/version.txt)"

    # Copy takserver.key and takserver.pem to FISSURE Config Files
    cd """ + fissure_directory + """
    PYTHONPATH=""" + fissure_directory + """ python3 fissure/utils/tak_yaml_key_insert.py \
    "$(find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -name 'takserver.key' | head -n 1)" \
    "$(find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -name 'takserver.pem' | head -n 1)" \
    "$(find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -name 'webadmin.p12' | head -n 1)" \
    "$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' takserver-5.3-RELEASE-24)"

    # Import webadmin.p12:

    # Google Chrome/Edge
    # Open chrome://settings/certificates in your browser.
    # Go to the "Your certificates" tab.
    # Click "Import".
    # Select /home/cups-pk-helper/webadmin.p12.
    # Enter the password (default: atakatak, unless changed).
    # Complete the import and restart your browser.

    # Mozilla Firefox
    # Open about:preferences#privacy in the Firefox address bar.
    # Scroll down to Certificates and click "View Certificates".
    # Go to the "Your Certificates" tab.
    # Click "Import".
    # Select /home/cups-pk-helper/webadmin.p12 and enter the password (atakatak).
    # Restart Firefox.

    # To Remove TAK:
    # docker ps -a | grep takserver
    # docker rm -f $(docker ps -aq --filter "name=takserver")
    # docker rm -f $(docker ps -aq --filter "name=takserver-db")
    # docker ps -a
    # docker images | grep takserver
    # docker rmi -f $(docker images -q takserver)
    # docker rmi -f $(docker images -q takserver-db)
    # docker images
    # docker network ls | grep takserver
    # docker network rm $(docker network ls --filter "name=takserver" -q)
    # sudo rm -rf ~/Installed_by_FISSURE/takserver-docker-*/

    echo ""
    echo "TAK Server setup complete! Import webadmin.p12 certificate via browser. Access WebTAK at https://localhost:8443"
    echo ""
else
    echo "TAK Server zip extraction failed or extracted folder not found. Exiting."
fi

########## Verify ##########
ls "$(find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -name 'webadmin.p12' | head -n 1)"
""",False,'Mapping'))

# Mobile Atlas Creator
programs_ubuntu22_04.append(('Mobile Atlas Creator',
"""sudo apt install -y default-jre
mkdir -p ~/Installed_by_FISSURE
cd ~/Installed_by_FISSURE
wget -O mobac.zip "https://sourceforge.net/projects/mobac/files/Mobile%20Atlas%20Creator/MOBAC%202.0/Mobile%20Atlas%20Creator%202.3.3.zip/download"
unzip mobac.zip -d "Mobile Atlas Creator"
rm mobac.zip
# Run with: java -jar ~/Installed_by_FISSURE/"Mobile Atlas Creator"/Mobile_Atlas_Creator.jar
########## Verify ##########
ls ~/Installed_by_FISSURE/"Mobile Atlas Creator"/Mobile_Atlas_Creator.jar
""",True,'Development'))