SHELL=/bin/bash
MESSAGES=100

PCAPFILES=$(shell python -c 'import itertools; import numpy as np; print(" ".join(["results/sim_%d_%.1f_%s_.pcap" % x for x in itertools.product(range(20), np.arange(0,12,0.5), ["ofdm", "noise"])]))')

all: pdr.pdf

pdr.pdf: plot.py results/all.csv
	python ./plot.py

results/all.csv: $(PCAPFILES)
	./parse.sh

%.pcap: sim.py
	mkdir -p results
	export GR_CONF_DEFAULT_MAX_MESSAGES=2000
	@echo $@
	$(eval REPETITION=$(shell python -c "print \"$@\".split(\"_\")[1]"))
	$(eval SNR=$(shell python -c "print \"$@\".split(\"_\")[2]"))
	$(eval INTERFERENCE=$(shell python -c "print \"$@\".split(\"_\")[3]"))
	@echo REPETITION=$(REPETITION)
	@echo SNR=$(SNR)
	@echo INTERFERENCE=$(INTERFERENCE)
	./sim.py --repetition=$(REPETITION) --snr=$(SNR) --messages=$(MESSAGES) --interference=$(INTERFERENCE)

