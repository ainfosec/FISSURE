#!/bin/sh

sudo service network-manager stop
sudo service NetworkManager stop  # 22.04
sudo ifconfig wlx00c0caafc90c down
sudo ifconfig wlx00c0caafc90c up
sudo ifconfig wlx00c0caafc90c down
sudo iwconfig wlx00c0caafc90c mode monitor
sudo ifconfig wlx00c0caafc90c up
sudo iwconfig wlx00c0caafc90c channel 1

