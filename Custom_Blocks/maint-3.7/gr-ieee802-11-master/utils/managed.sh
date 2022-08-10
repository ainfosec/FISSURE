#!/bin/bash

IFACE=wlan0

### check for command line arguments
if [[ $# -eq 1 ]]
then
	IFACE=$1

elif [[ $# != "0" ]]
then
	echo "too much command line arguments!"
	exit
fi

echo "setting interface >>${IFACE}<< to managed mode"

sudo ifconfig ${IFACE} down
sudo iwconfig ${IFACE} mode managed
sudo ifconfig ${IFACE} up
sudo service network-manager start
