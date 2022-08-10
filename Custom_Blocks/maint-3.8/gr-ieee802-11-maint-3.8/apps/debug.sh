#!/bin/bash

valgrind --leak-check=yes --trace-children=yes --log-file=./valgrind.out ../examples/ofdm_sim.py
#valgrind --tool=callgrind --dump-instr=yes  --trace-children=yes --log-file=./valgrind.out ../examples/ofdm_sim.py
