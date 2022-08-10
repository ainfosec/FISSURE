This docker allows for running gr-acars acquiring from a DVB-T dongle
acting as SDR source (aka RTL-SDR).

Make sure docker.io is installed and running (ps aux | grep docker).
If not,
sudo service docker start

Build docker with
./build_docker.sh

Run docker with
./launch_docker.sh
