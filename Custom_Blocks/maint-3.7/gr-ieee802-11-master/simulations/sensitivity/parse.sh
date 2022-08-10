#!/bin/bash

files=`ls results/*.pcap`
outfile=results/all.csv
rm -f ${outfile}

echo "repetition;sensitivity;snr;received"
echo "repetition;sensitivity;snr;received" > ${outfile}

for f in ${files}
do
	repetition=`python -c "print \"${f}\".split(\"_\")[1]"`
	sensitivity=`python -c "print \"${f}\".split(\"_\")[2]"`
	snr=`python -c "print \"${f}\".split(\"_\")[3]"`
	echo "file ${f}  repetition ${repetition}  sensitivity ${sensitivity}  snr ${snr}"
	rcvd=`tshark -r ${f} | wc -l | tr -d " "`
	echo "${repetition};${sensitivity};${snr};${rcvd}"
	echo "${repetition};${sensitivity};${snr};${rcvd}" >> ${outfile}
done
