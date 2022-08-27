# gr-dect2

This project was developed to demonstrate the possibility of real-time DECT 
voice channel decoding by Gnuradio. It allows to listen to a voice when encryption
isn't applied. As an example DECT digital baby monitors don't perform 
encryption. 

Usage of this project for phone connection eavesdropping may be illegal in 
some countries.


## Hardware requirements

DECT operates in the 1880–1900MHz band and occupies ten channels from 
1881.792MHz to 1897.344MHz. So in order to receive DECT digital stream an 
appropriate hardware is necessary. This project was developed and tested with 
USRP2 + WBX daughterboard and USRP B200. 

It also should work with other SDR radios that can cover 1880–1900 MHz band and
can provide sample rate at least two times more than DECT data rate (1152000bps). 
But some adaptation may be necessary. 

As a DECT link source the Motorola MBP12 baby monitor was used.

Because of the high DECT data rate a computer on with to run the project should 
be powerful enough. 

 
## To build

```
git clone git://github.com/pavelyazev/gr-dect2.git
```

( git checkout pyqt4  - optional in case of old Gnuradio and PyQt4)

```
cd gr-dect2/
mkdir build
cd build
cmake ../
make
sudo make install
sudo ldconfig
```

Then Gnuradio companion should be used to open and run the flow graph 
dect2.grc from gr-dect/grc

### HackRF

If you are using a HackRF, in that case you should use the dect2_Hackrf.grc
flow graph, which can also be found in the gr-dect/grc directory.


## Usage

Each device that can emit DECT signal will be called a part. According to the 
DECT specification there are parts of two types – RFP (Radio Fixed Part) or 
base station and PP (Portable Part) or handset. RFP emits a signal that 
setups frame structure on the air. A RFP can be listened to independently.  
But in order to get a voice from a PP it is necessary to receive its pair RFP.

The project uses QT-based controls. There are RX gain slider, channels and 
receiver ID drop-down lists, status console.

The status console shows parts on the air. Information about a part consists
of a receiver ID, part’s ID in DECT system, part’s type and voice presence sign. 
The status is updated every time when a part is gained/lost or voice data is 
gained/lost. A pair of RFP and PP will have the same DECT ID.

The receiver ID is an internally assigned number inside receiver. The current 
implementation allows to listen to only one part. A necessary part is selected 
by ID from the drop-down list. The selected part will be marked by asterisk in 
console. If voice data is available a status line will have the “v” letter at 
the end and decoded voice will be routed to a sound card.

From time to time parts may change frequency channel. So to catch something 
a periodic manual scan over channels is necessary.

## GNU Radio Installation

### Ubuntu 20.04.2 LTS

#### Dependencies

Make sure you have the following packages in your runtime environment:

```
sudo apt-get update
sudo apt-get install cmake gnuradio gr-osmosdr swig git doxygen -y
```

To ensure that the optimizations which are best suited for your hardware architecture
are used, run volk_profile, which comes as part of GNU Radio:

```
volk_profile
```

#### Troubleshooting

##### Compilation error

If you get a compilation error like this while running make:

```
$ make
[  9%] Building CXX object lib/CMakeFiles/gnuradio-dect2.dir/phase_diff_impl.cc.o
[ 18%] Building CXX object lib/CMakeFiles/gnuradio-dect2.dir/packet_decoder_impl.cc.o
[ 27%] Building CXX object lib/CMakeFiles/gnuradio-dect2.dir/packet_receiver_impl.cc.o
make[2]: *** No rule to make target '/usr/lib/x86_64-linux-gnu/liborc-0.4.so', needed by 'lib/libgnuradio-dect2.so'.  Stop.
make[1]: *** [CMakeFiles/Makefile2:252: lib/CMakeFiles/gnuradio-dect2.dir/all] Error 2
make: *** [Makefile:141: all] Error 2
```

Then it is possible that your liborc library is not properly symlinked. 
In that case you will need to create the symbolic link manually:

```
cd /usr/lib/x86_64-linux-gnu/

sudo ln -s liborc-0.4.so.0.31.0 liborc-0.4.so
```

##### Permission error while opening the HackRF device

By default in most linux distributions, a regular user will not have permissions to
access USB (or other) raw devices. In order to allow your GNU Radio instance 
running in user space to access the HackRF, you will need to add the appropriate
udev rule for that to be possible.

As such, you will need to:

1. Clone the HackRF project:

```
git clone https://github.com/mossmann/hackrf.git
```

2. Copy the appropriate rules file into your configuration:

```
sudo cp hackrf/host/libhackrf/53-hackrf.rules /etc/udev/rules.d/
```

3. Reload the rules and restart udev:

```
sudo udevadm control --reload-rules
sudo service udev restart
```

##### ModuleNotFoundError

If you get this error while trying to run your flow graph in GNU Radio, most likely you are missing
the PYTHONPATH env variable.

Make sure it is set to the appropriate path. You can persist this by adding the following
line to the end of your ~/.profile file:

```
export PYTHONPATH=/usr/local/lib/python3/dist-packages
```

Restart the shell for the change to take effect.
