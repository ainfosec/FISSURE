---
Espressif Systems is a Shanghai-based Chinese company that created the popular ESP8266, ESP32, ESP32-S, ESP32-C, and ESP32-H series of chips, modules, and development boards. These boards are a cheap solution for Wi-Fi and Bluetooth capabilities. They can be programmed with Arduino IDE, Visual Studio Code, MicroPython, Espressif Mesh Development Framework, Espruino, Lua Network/IoT toolkit, Mongoose OS, mruby, NodeMCU, Zerynth, and .Net nanoFramework.

This lesson will walk through the programming of ESP8266 and ESP32 boards with the Arduino IDE and cover the following topics:
 - Generating Wi-Fi beacons
 - Wi-Fi deauthentication
 - Generating Wi-Fi probe requests
 - Bluetooth writing
 - Bluetooth scanning
 - Bluetooth beacon spamming

## Table of Contents
1. [References](#references)
2. [ESP8266 Beacon Spammer](#esp8266_beacon_spammer)
3. [ESP8266 Deauther v2](#esp8266_deauther)
4. [ESP32 BLE Write](#esp32_ble_write)
5. [ESP32 BLE Beacon Scanner](#esp32_ble_beacon_scanner)
6. [ESP32-BLEBeaconSpam](#esp32_blebeaconspam)
7. [ESP32 Bluetooth Classic Sniffer](#esp32_bluetooth_classic_sniffer)

<div id="references"/> 

## References

- https://en.wikipedia.org/wiki/ESP32
- https://github.com/spacehuhn/esp8266_beaconSpam
- https://github.com/SpacehuhnTech/esp8266_deauther
- https://github.com/tobozo/ESP32-BLEBeaconSpam
- https://randomnerdtutorials.com/how-to-install-esp8266-board-arduino-ide/
- https://learn.sparkfun.com/tutorials/esp32-thing-plus-hookup-guide/arduino-example-esp32-ble
- https://github.com/Matheus-Garbelini/esp32_bluetooth_classic_sniffer

<div id="esp8266_beacon_spammer"/> 

## ESP8266 Beacon Spammer

**Install**

The following commands are one way to install the Arduino IDE:
```
wget -P ~/ https://downloads.arduino.cc/arduino-1.8.15-linux64.tar.xz
cd ~/
tar -xf arduino-1.8.15-linux64.tar.xz
cd arduino-1.8.15/
sudo ./install.sh
```

**Programming**

FISSURE contains an example program that is a modified ESP8266 Beacon Spammer. This program transmits a series of beacon frames over multiple frequency channels with a long list of SSID names. Once activated by a serial command, the program will transmit indefinitely until deactivated by another serial command. The following steps will upload the program to the ESP8266 board.
1. Open the Arduino IDE by navigating the FISSURE menu to _Tools>>802.11>>ESP8266 Beacon Spammer_.
2. Go to _File>>Preferences_ and add `http://arduino.esp8266.com/stable/package_esp8266com_index.json` to the “Additional Boards Manager URLs” field.
3. Go to _Tools>>Boards>>Board Manager_ and type in "esp8266" to see the _esp8266_ package. Click the "Install" button.
4. Go to _Tools>>Boards_ and select your board. For the "ESP8266 ESP-12E Development Board WiFi WLAN Wireless Module CP2102 for NodeMCU for ESP-12E for Arduino" product, choose _NodeMCU 0.9_ or _NodeMCU 1.0_.
5. Go to _Tools>>Port_ and choose the proper port (it might be `/dev/ttyUSB0`).
6. Plug in the board.
7. Click the _Upload_ button in the Arduino IDE (the right arrow).
8. Verify no errors were present while uploading.

**Interacting**

The _Esp8266\_listen\_trigger.ino_ file is a modified _ESP8266 Beacon Spammer_ that can be manually started and stopped over serial. By default nothing is transmitting until an "attack" command is issued. The following steps will control the program:
1. Open PuTTy with _Tools>>Hardware>>PuTTY_ or with the `putty` command.
2. Under _Session_, select _Serial_.
3. Change the _Serial line_ to the proper port (`/dev/ttyUSB0`).
4. Change the speed to 115200.
5. Select "Open".
6. Type "attack" and press the _Control_ key on the keyboard. Note: the text will not be visible while typing. If successful, `Packets/s: ###` will stream and fake Wi-Fi networks will appear on listening devices.
7. Type "stop" to end the program. Type "attack" and _Control_ to resume.

<div id="esp8266_deauther"/> 

## ESP8266 Deauther v2


**Programming**

FISSURE downloads the ESP2866 Deauther v2 program as part of its installer (_Installed_by_FISSURE_ folder). This program will create a wireless network and provide a web interface to the user for scanning, deauthenticating, and generating beacons and probe requests. FISSURE has menu items for opening the .ino file, accessing the web interface, and displaying the credentials for the wireless network. The following steps will upload the program to the ESP8266 board.
1. Open the Arduino IDE by navigating the FISSURE menu to _Tools>>802.11>>ESP8266 Deauther v2_.
2. Go to _File>>Preferences_ and add `https://raw.githubusercontent.com/SpacehuhnTech/arduino/main/package_spacehuhn_index.json` to the “Additional Boards Manager URLs” field.
3. Go to _Tools>>Boards>>Board Manager_ and type in "deauther" to see the _Deauther ESP2866 Boards_ package. Click the "Install" button.
4. Go to _Tools>>Boards>>Deauther ESP8266 Boards_ and select your board. For the "ESP8266 ESP-12E Development Board WiFi WLAN Wireless Module CP2102 for NodeMCU for ESP-12E for Arduino" product, choose _Generic ESP8266_.
5. Go to _Tools>>Port_ and choose the proper port (it might be `/dev/ttyUSB0`).
6. Plug in the board.
7. Click the _Upload_ button in the Arduino IDE (the right arrow).
8. Verify no errors were present while uploading.

**Interacting**

The wireless network and web interface will start automatically after the ESP8266 is programmed. The network may go down temporarily after commands are issued in the web interface. To avoid having to manually reconnect after each command, make sure to connect automatically to this network and no other networks. The following are steps for accessing and interacting with the web interface.
1. On a Wi-Fi device, connect to the network named "pwned" using the password "deauther".
2. Open a browser or use FISSURE to navigate to _192.168.4.1_.
3. Click "I HAVE READ AND UNDERSTOOD THE NOTICE ABOVE"
4. Click "SCAN APS" to discover access points. Refresh the browser.
5. Click "SCAN STATIONS" to discover stations. Refresh the browser.
6. Click the "ADD" button to select APs and stations as targets for attacks.
7. At the top of the page, click "SSIDs" to choose which names will be used in the beacon and probe attacks.
8. Click "Attack" at the top of the page to start/stop deauth, beacon, and probe attacks for previously specified targets and SSID names.


<div id="esp32_ble_write"/> 

## ESP32 BLE Write

This example will demonstrate how to write messages to an ESP32 board over Bluetooth. This was tested on a ESP32-WROOM-32D. See the SparkFun reference.

**Programming**
1. Open the Arduino IDE with the `arduino` command.
2. Open the _BLE\_Write_ program by going to _File>>Examples>>ESP32 BLE Arduino>>BLE\_Write_.
2. Go to _File>>Preferences_ and add `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json` to the “Additional Boards Manager URLs” field.
3. Go to _Tools>>Boards>>Board Manager_ and type in "esp32" to see the _esp32_ package. Click the "Install" button.
4. Go to _Tools>>Boards_ and select your board. For the "ESP32-WROOM-32D" product, choose _ESP32 Dev Module_.
5. Go to _Tools>>Port_ and choose the proper port (it might be `/dev/ttyUSB0`).
6. Plug in the board.
7. Click the _Upload_ button in the Arduino IDE (the right arrow).
8. Verify no errors were present while uploading (requires `pip install pyserial`)

**Interacting**
1. Open PuTTy with _Tools>>Hardware>>PuTTY_ or with the `putty` command.
2. Under _Session_, select _Serial_.
3. Change the _Serial line_ to the proper port (`/dev/ttyUSB0`).
4. Change the speed to 115200.
5. Select "Open".
6. Download a BLE Scanner App (_BLE Scanner 4.0_ on iPhone worked).
7. Scan and connect to "MyESP32".
8. Select "CUSTOM SERVICE".
9. Select "Write,Read".
10. Select "Write Value".
11. Select "Text", enter text, and select "Write" to send.
12. View `New value: <text>` in PuTTY.

<div id="esp32_ble_beacon_scanner"/> 

## ESP32 BLE Beacon Scanner
**Programming**
1. Repeat programming steps 1-8 in [ESP32 BLE Write](#esp32_ble_write) but load _File>>Examples>>ESP32 BLE\_Beacon\_Scanner_.

**Interacting**
1. Repeat interacting steps 1-5 in [ESP32 BLE Write](#esp32_ble_write) and view scan results in PuTTY.

<div id="esp32_blebeaconspam"/> 

## ESP32-BLEBeaconSpam

- Still troubleshooting...


<div id="esp32_bluetooth_classic_sniffer"/> 

## ESP32 Bluetooth Classic Sniffer

The BrakTooth ESP32 BR/EDR Active Sniffer/Injector acts as a simple "Monitor mode" for Bluetooth Classic. It can sniff or inject BR/EDR Baseband packets in ESP32 BT connections. It comes with the firmware for flashing the ESP32 board and can be run from the FISSURE menu item: _Tools>>Bluetooth>>ESP32 Bluetooth Classic Sniffer>>Flash ESP32 Board_. The installer includes a Wireshark dissector for decoding the baseband packets.

This is an active sniffer and requires a connection/the start of a connection to capture traffic. It will interact with the BT network (piconet). It is not a passive sniffer and will not detect Bluetooth traffic unless it is targeted.

The command for launching the sniffer can be accessed from the FISSURE menu item: _Tools>>Bluetooth>>ESP32 Bluetooth Classic Sniffer>>BTSnifferBDEDR_

```
sudo ./BTSnifferBREDR.py --port=/dev/ttyUSB0 --live-terminal --live-wireshark
```
