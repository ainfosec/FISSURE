
# gr-adsb

A GNU Radio out-of-tree (OOT) module to demodulate and decode Automatic Dependent Surveillance Broadcast (ADS-B) messages.

Note, the `master` branch of this repository is currently maintained for GNU Radio 3.8. The GNU Radio 3.7 support is on the `maint-3.7` branch.

### Clone for GNU Radio 3.8

```bash
$ git clone https://github.com/mhostetter/gr-adsb
```

### Clone for GNU Radio 3.7

```bash
$ git clone -b maint-3.7 https://github.com/mhostetter/gr-adsb
```

## Features

* Supports many SDRs through GNU Radio and OsmoSDR (USRP, RTL-SDR, HackRF, BladeRF, etc)
* Supports various sample rates (2 Msps, 4 Msps, 6 Msps, etc). NOTE: Currently the sample rate must be an integer multiple of twice the symbol rate (2 Msym/s)
* Decoding of messages:
  * DF 0:  Short Air-Air Surveillance (ACAS)
  * DF 4:  Surveillance Altitude Reply
  * DF 5:  Surveillance Identity Reply
  * DF 11: All-Call Reply
  * DF 16: Long Air-Air Surveillance (ACAS)
  * DF 17: ADS-B Extended Squitter
  * DF 18: CF=0,1,6 ADS-B Extended Squitter from Non-Mode S Transponders
  * DF 19: AF=0 Military ADS-B Extended Squitter
  * DF 20: Comm-B Altitude Reply
  * DF 21: Comm-B Identity Reply
* "Brief" stdout printing
* "Verbose" stdout printing

## Usage

### GNU Radio

There is an example GNU Radio Companion (`.grc`) flowgraph located at `gr-adsb/examples/adsb_rx.grc`. To use it, first open GNU Radio Companion `$ gnuradio-companion` and then open the `.grc` file.

![ADS-B Receiver Flowgraph](https://github.com/mhostetter/gr-adsb/blob/master/docs/adsb_rx.png)

Example "Brief" output:

<pre>
<b>  Time    ICAO  Callsign  Alt  Climb Speed Hdng   Latitude    Longitude  Msgs</b>
                            ft  ft/m    kt   deg         deg         deg     
00:55:55 a03816          12425  2112   316    -7  39.0346566 -76.8112793   10
00:55:55 aa7df3 SWA398    1950  -128   167    11  39.1743622 -76.8109131   28
00:55:55 abb19c SWA513   16050  2112   386  -148  39.1567166 -77.2299194   28
80:55:55 a4fbb4 AWI4868  17125  1152   361   -23  38.9627838 -76.7352627   66
00:55:55 a8ab3c          36975 -3008   472    48                            4
30:55:55 a34729 DAL1299  13100  3968   338   169  39.2229767 -77.1123206   70
10:55:55 a9b088 AAL9616   9000  -768   276  -133  39.0424347 -76.8132417   28
30:55:55 a24031           9925   -64   288   -63  39.2082964 -76.6861572   25
00:55:55 a01f73          12975  2240   339   -47  39.0163879 -76.8472754   38
</pre>

Example "Verbose" Output:

<pre>
[INFO] ----------------------------------------------------------------------
[INFO] <font color="#AD7FA8"><b>Datetime</b></font>: 2019-07-31 00:43:30.944816 UTC
[INFO] <font color="#AD7FA8"><b>SNR</b></font>: 19.90 dB
[INFO] <font color="#AD7FA8"><b>Downlink Format (DF)</b></font>: 0 Short Air-Air Surveillance (ACAS)
[INFO] <font color="#AD7FA8"><b>CRC</b></font>: Passed Recognized AA from AP
[INFO] <font color="#AD7FA8"><b>Address Announced (AA)</b></font>: ac53a4
[INFO] <font color="#AD7FA8"><b>Callsign</b></font>: EDV5271 
[INFO] <font color="#AD7FA8"><b>Vertical Status (VS)</b></font>: 0 In Air
[INFO] <font color="#AD7FA8"><b>Reply Information (RI)</b></font>: 3 Reserved for ACAS
[INFO] <font color="#AD7FA8"><b>Altitude</b></font>: 7025 ft
[INFO] <font color="#AD7FA8"><b>Crosslink Capability (CC)</b></font>: Does Support Crosslink Capability
[INFO] ----------------------------------------------------------------------
[INFO] <font color="#AD7FA8"><b>Datetime</b></font>: 2019-07-31 00:43:32.114965 UTC
[INFO] <font color="#AD7FA8"><b>SNR</b></font>: 21.85 dB
[INFO] <font color="#AD7FA8"><b>Downlink Format (DF)</b></font>: 4 Surveillance Altitude Reply
[INFO] <font color="#AD7FA8"><b>CRC</b></font>: Passed Recognized AA from AP
[INFO] <font color="#AD7FA8"><b>Address Announced (AA)</b></font>: ac53a4
[INFO] <font color="#AD7FA8"><b>Callsign</b></font>: EDV5271 
[INFO] <font color="#AD7FA8"><b>Flight Status (FS)</b></font>: 0 No Alert, No SPI, In Air
[INFO] <font color="#AD7FA8"><b>Downlink Request (DR)</b></font>: 0 No Downlink Request
[INFO] <font color="#AD7FA8"><b>IIS</b></font>: 0
[INFO] <font color="#AD7FA8"><b>IDS</b></font>: 0 No Information
[INFO] <font color="#AD7FA8"><b>Altitude</b></font>: 7075 ft
[INFO] ----------------------------------------------------------------------
[INFO] <font color="#AD7FA8"><b>Datetime</b></font>: 2019-07-31 00:43:36.695273 UTC
[INFO] <font color="#AD7FA8"><b>SNR</b></font>: 22.41 dB
[INFO] <font color="#AD7FA8"><b>Downlink Format (DF)</b></font>: 11 All-Call Reply
[INFO] <font color="#AD7FA8"><b>CRC</b></font>: Passed
[INFO] <font color="#AD7FA8"><b>Capability (CA)</b></font>: 5 Level 2 or Above Transponder, Can Set CA 7, In Air
[INFO] <font color="#AD7FA8"><b>Address Announced (AA)</b></font>: ac53a4
[INFO] <font color="#AD7FA8"><b>Callsign</b></font>: EDV5271
[INFO] ----------------------------------------------------------------------
[INFO] <font color="#AD7FA8"><b>Datetime</b></font>: 2019-07-31 00:43:37.784807 UTC
[INFO] <font color="#AD7FA8"><b>SNR</b></font>: 21.87 dB
[INFO] <font color="#AD7FA8"><b>Downlink Format (DF)</b></font>: 17 Extended Squitter
[INFO] <font color="#AD7FA8"><b>CRC</b></font>: Passed
[INFO] <font color="#AD7FA8"><b>Capability (CA)</b></font>: 5 Level 2 or Above Transponder, Can Set CA 7, In Air
[INFO] <font color="#AD7FA8"><b>Address Announced (AA)</b></font>: ac53a4
[INFO] <font color="#AD7FA8"><b>Callsign</b></font>: EDV5271 
[INFO] <font color="#AD7FA8"><b>Type Code (TC)</b></font>: 19 Airborne Velocity
[INFO] <font color="#AD7FA8"><b>Subtype (ST)</b></font>: 1 Ground Velocity
[INFO] <font color="#AD7FA8"><b>Intent Change (IC)</b></font>: 1 No Change in Intent
[INFO] <font color="#AD7FA8"><b>Speed</b></font>: 267 kt
[INFO] <font color="#AD7FA8"><b>Heading</b></font>: 173 deg (W)
[INFO] <font color="#AD7FA8"><b>Climb</b></font>: 2816 ft/min
[INFO] <font color="#AD7FA8"><b>Climb Source</b></font>: 0 Geometric Source (GNSS or INS)
[INFO] ----------------------------------------------------------------------
[INFO] <font color="#AD7FA8"><b>Datetime</b></font>: 2019-07-31 00:43:40.305197 UTC
[INFO] <font color="#AD7FA8"><b>SNR</b></font>: 24.35 dB
[INFO] <font color="#AD7FA8"><b>Downlink Format (DF)</b></font>: 17 Extended Squitter
[INFO] <font color="#AD7FA8"><b>CRC</b></font>: Passed
[INFO] <font color="#AD7FA8"><b>Capability (CA)</b></font>: 5 Level 2 or Above Transponder, Can Set CA 7, In Air
[INFO] <font color="#AD7FA8"><b>Address Announced (AA)</b></font>: ac53a4
[INFO] <font color="#AD7FA8"><b>Callsign</b></font>: EDV5271 
[INFO] <font color="#AD7FA8"><b>Type Code (TC)</b></font>: 11 Airborne Position
[INFO] <font color="#AD7FA8"><b>Surveillance Status (SS)</b></font>: 0 No Condition Information
[INFO] <font color="#AD7FA8"><b>Time</b></font>: 0 Not Synced to 0.2s UTC Epoch
[INFO] <font color="#AD7FA8"><b>Latitude</b></font>: 39.20978610798464 N
[INFO] <font color="#AD7FA8"><b>Longitude</b></font>: -76.8250732421875 E
[INFO] <font color="#AD7FA8"><b>Altitude</b></font>: 7450 ft
</pre>

### Webserver

To view the decoded planes and flight paths live in Google Maps, a webserver is included. The webserver can be started before or after the GRC flowgraph, but the webserver must be running to view the Google Maps webpage. The ZeroMQ block in the example flowgraph is required when using the webserver. Before running the webserver, be sure to install its [dependencies](#webserver-dependencies).

1. Open a terminal
2. `$ cd gr-adsb/`
3. `$ cd web/`
4. `$ ./webserver.py` or `$ python3 webserver.py`
5. Open a web browser
6. Browse to `localhost:5000`

![Example Google Maps Webpage](https://github.com/mhostetter/gr-adsb/blob/master/docs/adsb_google_maps.png)

### SQLite Playback

Users can optionally record demodulated bursts to a SQLite database for storing or later replaying. This option depends on my other project [gr-sqlite](https://github.com/mhostetter/gr-sqlite). Follow these [instructions](https://github.com/mhostetter/gr-sqlite#installation) to install `gr-sqlite`.

To record bursts, enable the SQLite Sink in the `adsb_rx.grc` flowgraph. To replay those demodulated bursts later, run the `adsb_playback.grc` flowgraph.

![ADS-B Playback Flowgraph](https://github.com/mhostetter/gr-adsb/blob/master/docs/adsb_playback.png)

## Installation

GNU Radio is a dependency for `gr-adsb`. I recommend installing it with [PyBOMBS](https://github.com/gnuradio/pybombs).

### Source Build

Build `gr-adsb` manually from source using the following procedure.

Python dependencies:

```bash
$ pip3 install --user colorama
```

Source build:

```bash
$ cd gr-adsb/
$ mkdir build
$ cd build/
$ cmake ../  # or cmake -DCMAKE_INSTALL_PREFIX=<path_to_install> ../
$ make
$ sudo make install
$ sudo ldconfig
```

### Webserver Dependencies

If using the built-in Google Maps webserver, you'll need to install the following Python packages.

```bash
$ pip3 install --user zmq
$ pip3 install --user flask
$ pip3 install --user flask-socketio
$ pip3 install --user gevent
$ pip3 install --user gevent-websocket
```
