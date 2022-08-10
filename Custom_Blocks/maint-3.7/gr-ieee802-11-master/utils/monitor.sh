#!/bin/bash

IFACE=wlan0
CHANNEL=3

### check for command line arguments
if [[ $# -eq 2 ]]
then
	CHANNEL=$1
	IFACE=$2

elif [[ $# -eq 1 ]]
then
	CHANNEL=$1

elif [[ $# != "0" ]]
then
	echo "too much command line arguments!"
	exit
fi


echo "setting interface >>${IFACE}<< to monitor channel >>${CHANNEL}<<"

sudo service network-manager stop
sudo ifconfig ${IFACE} down
sudo iwconfig ${IFACE} mode monitor
sudo ifconfig ${IFACE} up
sudo iwconfig ${IFACE} channel ${CHANNEL}
