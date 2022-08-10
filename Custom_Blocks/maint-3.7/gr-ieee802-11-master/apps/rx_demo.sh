#!/bin/bash

### Enable Wireshark Connector in wifi_rx flow graph

FILE="/tmp/wifi.pcap"
FLOWGRAPH="wifi_rx.py"
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

### create fifo
if [ -e ${FILE} ]
then
	echo "${FILE}: file already exists"
	if ! [ -p ${FILE} ]
	then
		echo "ERROR: ${FILE} exists and is not a FIFO"
		exit 1
	fi
else
	echo "creating fifo: ${FILE}"
	mkfifo ${FILE}
fi


### create tap interface
if [[ `ifconfig -a | grep tap0 | wc -l` -eq 0 ]]
then
	sudo ip tuntap add dev tap0 user ${USER} mode tap
fi

### reconfigure it in any case, just to be sure it's up
sudo ifconfig tap0 down
sudo ifconfig tap0 hw ether 12:34:56:78:90:ab
sudo ifconfig tap0 up
sudo ifconfig tap0 192.168.123.1


### start transceiver
cd ${DIR}
cd ../examples/
./${FLOWGRAPH} &
sleep 1


### start wireshark
wireshark -k -i ${FILE} &
sleep 1


### start netcat
echo "##########################################################################"
echo "### starting netcat. Just type and the lines will be send to the flowgraph"
echo "##########################################################################"
sleep 2

#echo | nc -u localhost 52001
cat


