#!/bin/bash

files=`ls results/*.pcap`
outfile=results/all.csv
rm -f ${outfile}

echo "repetition;encoding;snr;received"
echo "repetition;encoding;snr;received" > ${outfile}

for f in ${files}
do
	repetition=`python -c "print \"${f}\".split(\"_\")[1]"`
	encoding=`python -c "print \"${f}\".split(\"_\")[2]"`
	snr=`python -c "print \"${f}\".split(\"_\")[3]"`
	echo "file ${f}  repetition ${repetition}  encoding ${encoding}  snr ${snr}"
	rcvd=`tshark -r ${f} | wc -l | tr -d " "`
	echo "${repetition};${encoding};${snr};${rcvd}"
	echo "${repetition};${encoding};${snr};${rcvd}" >> ${outfile}
done
