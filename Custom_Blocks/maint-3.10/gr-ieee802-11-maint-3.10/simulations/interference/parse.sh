#!/bin/bash

files=`ls results/*.pcap`
outfile=results/all.csv
rm -f ${outfile}

echo "repetition;interference;snr;received"
echo "repetition;interference;snr;received" > ${outfile}

for f in ${files}
do
	repetition=`python -c "print \"${f}\".split(\"_\")[1]"`
	snr=`python -c "print \"${f}\".split(\"_\")[2]"`
	interference=`python -c "print \"${f}\".split(\"_\")[3]"`
	echo "file ${f}  repetition ${repetition}  interference ${interference}  snr ${snr}"
	rcvd=`tshark -r ${f} -Y "wlan.sa == 23:23:23:23:23:23" | wc -l | tr -d " "`
	echo "${repetition};${interference};${snr};${rcvd}"
	echo "${repetition};${interference};${snr};${rcvd}" >> ${outfile}
done
