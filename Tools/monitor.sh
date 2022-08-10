#!/bin/sh

sudo service network-manager stop
sudo ifconfig wlan0 down
sudo ifconfig wlan0 up
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
sudo iwconfig wlan0 channel 1

