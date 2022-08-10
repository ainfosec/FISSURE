# Development

Like GNU Radio, this module uses *master* and *maint* branches for development.
These branches are supposed to be used with the corresponding GNU Radio
branches. This means: the *maint-3.7* branch is compatible with GNU Radio 3.7,
*maint-3.8* is compatible with GNU Radio 3.8, and *master* is compatible with
GNU Radio master, which tracks the development towards GNU Radio 3.9.


### Dependencies

- GNU Radio. See the [GNU Radio
  Wiki](https://wiki.gnuradio.org/index.php/InstallingGR) for
  installation instructions.


### Installation
```
mkdir build
cd build
cmake ..
make
sudo make install
sudo ldconfig
```

### Usage

open apps/rds_rx.grc example flow graph in GNU Radio Companion.


### Demos

Quick example:
http://www.youtube.com/watch?v=05i9C5lhorY

HAK5 episode (including installation):
http://www.youtube.com/watch?v=ukhrIl4JHbw

FOSDEM'15 talk (video and slides):
https://archive.fosdem.org/2015/schedule/event/sdr_rds_tmc/


### History

Continuation of gr-rds on BitBucket (originally from Dimitrios Symeonidis
https://bitbucket.org/azimout/gr-rds/ and also on CGRAN
https://www.cgran.org/wiki/RDS).
