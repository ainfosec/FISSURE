#!/bin/bash

FILE="/tmp/ofdm.pcap"
FLOWGRAPH="wifi_transceiver.py"
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
sudo ifconfig tap0 mtu 440
sudo ifconfig tap0 up
sudo ifconfig tap0 192.168.123.1

sudo route del -net 192.168.123.0/24
sudo route add -net 192.168.123.0/24 mss 400 dev tap0

sudo tc qdisc del dev tap0 root
sudo tc qdisc add dev tap0 root netem delay 10ms

sudo arp -s 192.168.123.2 30:14:4a:e6:46:e4


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


