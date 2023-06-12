# LimeSDR Notes

## Links

- https://wiki.myriadrf.org/Lime_Suite
- https://wiki.myriadrf.org/Gr-limesdr_Plugin_for_GNURadio
- https://myriadrf.org/news/limesdr-made-simple-part-1/

## Installing

### From Repo

```
sudo add-apt-repository -y ppa:myriadrf/drivers
sudo apt-get update
sudo apt-get install limesuite liblimesuite-dev limesuite-udev limesuite-images
sudo apt-get install soapysdr-tools soapysdr-module-lms7
```

```
# soapysdr-tools was called soapysdr on older packages
sudo apt-get install soapysdr soapysdr-module-lms7
```

### From Source

```
sudo apt-get install libboost-all-dev swig

git clone https://github.com/myriadrf/gr-limesdr

cd gr-limesdr
mkdir build
cd build
cmake ..
make
sudo make install
sudo ldconfig
```

## Other Notes 

- `LimeUtil --find`
- LimeSDR-USB and LimeSDR-PCIe sample rate must be no more than 61.44 MS/s.
- Gain range must be 0dB–70dB (60 on transmit, 70 on receive).
- Up to 10 dBm
- Analog filter bandw. (callback function value): Enter RX analog filter bandwidth for each channel. 0 means that analog filter is turned OFF.
- RX analog filter bandwidth range must be 1.5MHz–130MHz.
- Digital filter bandw. (callback function value):Enter RX digital filter bandwidth for each channel. 0 means that digital filter is turned OFF.
- RX digital filter bandwidth should not be higher than sampling rate.
- LimeSDR v1.4s
- `LimeSuiteGUI`
