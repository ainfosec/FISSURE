# gr-limesdr

Package includes GNU Radio blocks for various LimeSDR boards.

## Documentation

* [MyriadRF Wiki page](https://wiki.myriadrf.org/Gr-limesdr_Plugin_for_GNURadio)

## Dependencies
 
* GNU Radio(3.7)
* BOOST
* SWIG
* LimeSuite

## Installation process

#### Linux

* Installing via PPA
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
mkdir build
cd build
cmake ..
make
sudo make install
sudo ldconfig
</pre>

#### Windows

Install GNU Radio then download zip file from [MyriadRF Wiki](http://downloads.myriadrf.org/project/limesuite/19.01/GNU_Radio_windows_19.01.zip) and extract it to:
<pre>
C:\Program Files\GNURadio-3.7
</pre>

## Known issues

Known issues are located in:
gr-limesdr/docs/known_issues.txt

## GNU Radio-Companion examples

GNU Radio-Companion examples are located in:
gr-limesdr/examples
