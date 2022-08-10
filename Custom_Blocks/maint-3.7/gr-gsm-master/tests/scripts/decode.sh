#!/bin/bash

TEST_DIR=`dirname "$0"`

# PYTHONPATH and LD_LIBRARY_PATH are needed on Fedora 26
export PYTHONPATH=/usr/local/lib64/python2.7/site-packages/:/usr/local/lib64/python2.7/site-packages/grgsm/:$PYTHONPATH
export LD_LIBRARY_PATH=/usr/local/lib64/:$LD_LIBRARY_PATH

export AP_DECODE="grgsm_decode"
export CAPFILE="../../test_data/vf_call6_a725_d174_g5_Kc1EF00BAB3BAC7002.cfile"
export SHORTENED_CAPFILE="tmp.cfile"
export RESULT_EXPECTED="../fixtures/grgsm_decode_test1_expected"
export RESULT_OBTAINED="grgsm_decode_test1_result"
export RUNLINE="$AP_DECODE -c $SHORTENED_CAPFILE -s $((100000000/174)) -m BCCH -t 0 -v --ppm -10"
echo "Testing with:"
echo "  $RUNLINE"
gnuradio-companion --version

cd $TEST_DIR
cat $CAPFILE | head -c 6000000 > $SHORTENED_CAPFILE

$RUNLINE | grep -A 999999 "860933 1329237:  59 06 1a 8f 6d 18 10 80 00 00 00 00 00 00 00 00 00 00 00 78 b9 00 00" | tee $RESULT_OBTAINED
diff $RESULT_EXPECTED $RESULT_OBTAINED
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

