#!/bin/sh

sudo ifconfig wlx00c0caafc90c down
sudo iwconfig wlx00c0caafc90c mode managed
sudo ifconfig wlx00c0caafc90c up
sudo service network-manager start
sudo service NetworkManager start  # 22.04
