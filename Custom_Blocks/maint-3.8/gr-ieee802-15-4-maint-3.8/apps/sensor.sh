#!/bin/bash

FILE="/tmp/sensor.pcap"
FLOWGRAPH="transceiver_OQPSK.py"
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

### start transceiver
cd ${DIR}
cd ../examples/
./${FLOWGRAPH} &
sleep 1


wireshark -k -i ${FILE} &
sleep 3


cd ${DIR}/sensor_gui
./sensor_value.py


