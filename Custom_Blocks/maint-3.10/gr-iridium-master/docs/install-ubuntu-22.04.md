# gr-iridium installation on Ubuntu 22.04

## Install dependencies

Install GNU Radio and all needed dependencies:
```
sudo apt update
sudo apt install gnuradio-dev gr-osmosdr cmake libsndfile1-dev
```
You might have to disconnect and re-connect your SDR if it was already connected to your computer.

If you want to use USRP devices, you also need to run:
```
sudo apt install uhd-host
sudo uhd_images_downloader
```

## Optimize VOLK
gr-iridium and GNU Radio use VOLK to do most of the computations. To allow VOLK to chose the best
implementations of its DSP algorithms you should run

```
volk_profile
```

This instructs VOLK to benchmark all the implementations it knows and write a file which it then
uses when running gr-iridium. This will take a few minutes. Make sure to not do other computationally
intensive tasks at the same time.

## Clone, compile and install gr-iridium
```
git clone https://github.com/muccc/gr-iridium
cd gr-iridium
cmake -B build
cmake --build build -j 2
sudo cmake --install build
sudo ldconfig
```

You are now ready to execute `iridium-extractor` as a normal user. Follow the instructions in
[README.md](../README.md#usage-examples) for details.

