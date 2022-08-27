#!/bin/bash

TEST_DIR=$(dirname "$0")

# PYTHONPATH and LD_LIBRARY_PATH are needed on Fedora 26
#
# /usr/local/lib/python3/dist-packages/ is currently needed on Debian Testing and Kali Rolling
# https://salsa.debian.org/bottoms/pkg-gnuradio/blob/unstable/debian/patches/debian-python-install#L8
#
export PYTHONPATH=/usr/local/lib/python3/dist-packages/:/usr/local/lib64/python2.7/site-packages/:/usr/local/lib64/python2.7/site-packages/gnuradio/gsm/:$PYTHONPATH
export LD_LIBRARY_PATH=/usr/local/lib64/:$LD_LIBRARY_PATH

export AP_DECODE="grgsm_decode"
export CAPFILE="../../test_data/vf_call6_a725_d174_g5_Kc1EF00BAB3BAC7002.cfile"
export SHORTENED_CAPFILE="tmp.cfile"
export RESULT_EXPECTED="../fixtures/gsm_decode_decrypt1_expected"
export RESULT_OBTAINED="gsm_decode_test1_result"
export RUNLINE="$AP_DECODE -c $SHORTENED_CAPFILE -s $((100000000/174)) -m SDCCH8 -t 1 -k 0x1E,0xF0,0x0B,0xAB,0x3B,0xAC,0x70,0x02 -v --ppm -10"
echo "Testing with:"
echo "  $RUNLINE"
gnuradio-config-info --version
cat /proc/cpuinfo
ulimit -a

cd "$TEST_DIR" || exit 1
head -c -37000000 $CAPFILE | head -c 35800000  > $SHORTENED_CAPFILE

# VOLK_GENERIC=1 is a temporary workaround for the following VOLK's bug
# https://github.com/gnuradio/volk/pull/278
# https://github.com/gnuradio/gnuradio/issues/2748
export VOLK_GENERIC=1

$RUNLINE | grep -A 999999 "862210 1331352:  03 03 01 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b" | tee $RESULT_OBTAINED
diff -u $RESULT_EXPECTED $RESULT_OBTAINED
TEST_RESULT=$?

rm $RESULT_OBTAINED
rm $SHORTENED_CAPFILE

if [ $TEST_RESULT == 0 ]
then
  echo "   Result: PASSED"
  exit 0
else
  echo "   Result: FAILED"
  exit 1
fi

