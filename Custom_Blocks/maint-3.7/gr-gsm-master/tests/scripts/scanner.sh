#!/bin/bash
# This script runs integration tests for grgsm_scanner.
# Run it fron the enclosing directory.
export TEST_IMAGE_NAMES=()
export TEST_SCAN_BANDS=(P-GSM DCS1800 PCS1900 E-GSM R-GSM GSM450 GSM480 GSM850)
export TEMP_DIR=`mktemp -d`
cd ../../
export GR_SRC_DIR=`echo $PWD`

echo "Using source dir: $GR_SRC_DIR"
echo "Using destination dir: $TEMP_DIR"
cp -R $GR_SRC_DIR $TEMP_DIR

cd $TEMP_DIR/gr-gsm

export DOCKERFILE_LIST=($TEMP_DIR/gr-gsm/tests/dockerfiles/*.docker)

for DOCKERFILE in ${DOCKERFILE_LIST[*]}
do
  cat $DOCKERFILE > Dockerfile
  export IMAGE_BASE=`echo $DOCKERFILE | \
  sed -e "s|$TEMP_DIR/gr-gsm/dockerfiles/||g" | \
  sed -e 's/\.docker//g'`
  export IMAGE_NAME=`echo $IMAGE_BASE | tr '[:upper:]' '[:lower:]'`
  echo "Attempt to build $IMAGE_NAME"
  docker build -t $IMAGE_NAME ./ && TEST_IMAGE_NAMES+=($IMAGE_NAME)
done


for BAND in ${TEST_SCAN_BANDS[*]}
do
  export SCAN_COMMAND="/usr/bin/python /usr/local/bin/grgsm_scanner -b `echo $BAND` -v"
  for IMG in ${TEST_IMAGE_NAMES[*]}
  do
    echo "Now we test: $SCAN_COMMAND on $IMG"
    docker run -it --rm --privileged $IMG `echo $SCAN_COMMAND`
  done
done

cd $GR_SRC_DIR/build_test/scripts && rm -rf $TEMP_DIR
