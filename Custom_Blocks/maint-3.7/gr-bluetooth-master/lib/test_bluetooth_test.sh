#!/usr/bin/sh
export GR_DONT_LOAD_PREFS=1
export srcdir=/home/chris/sfu/ensc897/btle/port/gr-bluetooth/lib
export PATH=/home/chris/sfu/ensc897/btle/port/gr-bluetooth/lib:$PATH
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$DYLD_LIBRARY_PATH
export DYLD_LIBRARY_PATH=$LD_LIBRARY_PATH:$DYLD_LIBRARY_PATH
export PYTHONPATH=$PYTHONPATH
test-bluetooth 
