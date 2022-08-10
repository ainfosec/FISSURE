#!/usr/bin/sh
export GR_DONT_LOAD_PREFS=1
export srcdir=/home/chris/sfu/ensc897/btle/port/gr-bluetooth/python
export PATH=/home/chris/sfu/ensc897/btle/port/gr-bluetooth/python:$PATH
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$DYLD_LIBRARY_PATH
export DYLD_LIBRARY_PATH=$LD_LIBRARY_PATH:$DYLD_LIBRARY_PATH
export PYTHONPATH=/home/chris/sfu/ensc897/btle/port/gr-bluetooth/swig:$PYTHONPATH
/usr/bin/python /home/chris/sfu/ensc897/btle/port/gr-bluetooth/python/qa_gr_bluetooth_multi_sniffer.py 
