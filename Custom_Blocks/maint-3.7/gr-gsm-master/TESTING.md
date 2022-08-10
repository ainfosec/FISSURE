# Testing gr-gsm

## CI Testing

CI testing currently consists of attempting to build gr-gsm as described in the .docker files located under gr-gsm/tests/dockerfiles using travis-ci.org.  If the build is successful, travis-ci will attempt to decode the test file located under gr-gsm/test_data and compare the results to this file: gr-gsm/tests/fixtures/grgsm_decode_test1_expected.  See the gr-gsm/tests/scripts/decode.sh file for details.

## Integration testing

Integration testing with use of the grgsm_scanner application:
* Make sure that your RTL SDR dongle is plugged into the system and if you're running on Mac, you need to have the dongle accessible to the VirtualBox VM that's running Docker.
* cd gr-gsm/tests/scripts
* scanner.sh

This will copy the entire contents of the currently checked out branch of gr-gsm to a temp folder, and attempt to build the docker images according to the definitions in the .docker files located under gr-gsm/dockerfiles.  
Once the images are created, the script instantiates a container for testing the rtlsdr scanner on each band, against each Docker image built.  This can take quite a while.  If you're running on Mac, consider using the ```caffeinate``` command to keep your machine from sleeping.
