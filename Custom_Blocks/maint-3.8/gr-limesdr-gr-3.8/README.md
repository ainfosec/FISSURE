# gr-limesdr

Package includes GNU Radio blocks for various LimeSDR boards.

## Documentation

* [MyriadRF Wiki page](https://wiki.myriadrf.org/Gr-limesdr_Plugin_for_GNURadio)

## Dependencies
 
* GNU Radio (>=3.8)
* BOOST
* SWIG
* LimeSuite

## Installation process

* Installing GNURadio
To install GNURadio3.8 please follow this guide [Installing GNURadio](https://wiki.gnuradio.org/index.php/InstallingGR)

* Installing via PPA
Only available for Ubuntu 20.04
<pre>
sudo add-apt-repository -y ppa:myriadrf/drivers
sudo add-apt-repository -y ppa:myriadrf/gnuradio
sudo apt update
sudo apt install gr-limesdr
</pre>

* Building from source
<pre>
git clone https://github.com/myriadrf/gr-limesdr.git
cd gr-limesdr
git checkout gr-3.8
mkdir build
cd build
cmake ..
make
sudo make install
sudo ldconfig
</pre>

To compile with LimeRFE board support change `cmake ..` line to `cmake -DENABLE_RFE=ON ..`

## GNU Radio-Companion examples

GNU Radio-Companion examples are located in:
gr-limesdr/examples
