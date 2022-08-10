Wireshark Plugins
-----------------

This directory contains two sets of Wireshark plugins:
plugins:	for Wireshark 2.0+
plugins-legacy	for Wireshark 1.x

You can determine which version of wireshar you have by running:
wireshark -v

Within the plugins-legacy directory there are BLE plugins which have been
included in Wireshark since v1.12.  If you are running Wireshark 1.12+ you only
need to build the btbb and btbredr plugins.
