# "ADS-B Out" add-on for SoftRF-Emu, Stratux, etc...

This repository contains "ADS-B Out" encoder for Tx-capable SDR hardware.

It is currently written in architecture independent Python language and can be used as an add-on for existing
open source "ADS-B In" solutions. One known good example is [Stratux](https://github.com/cyoung/stratux).

## Disclaimer
The source code is published for academic purpose only.

## Instructions
1. Execute *ADSB_Encoder.py* script with `<ICAO>` `<Latitude>` `<Longtitude>` `<Altitude>` arguments:
```
$ ADSB_Encoder.py  0xABCDEF 12.34 56.78 9999.0
$ ls Samples.iq8s
Samples.iq8s
$
```
2. Make the raw signal file aligned to 256K buffer size:
```
$ dd if=Samples.iq8s of=Samples_256K.iq8s bs=4k seek=63
1+0 records in
1+0 records out
4096 bytes (4.1 kB) copied, 0.00110421 s, 3.7 MB/s
$
```
3. Transmit the signal into air:
```
$ hackrf_transfer -t Samples_256K.iq8s -f 868000000 -s 2000000 -x 10
call hackrf_sample_rate_set(2000000 Hz/2.000 MHz)
call hackrf_baseband_filter_bandwidth_set(1750000 Hz/1.750 MHz)
call hackrf_set_freq(868000000 Hz/868.000 MHz)
Stop with Ctrl-C
 0.5 MiB / 1.000 sec =  0.5 MiB/second

User cancel, exiting...
Total time: 1.00038 s
hackrf_stop_tx() done
hackrf_close() done
hackrf_exit() done
fclose(fd) done
exit
$
```
## Validation
```
$ sudo dump1090 --net --freq 868000000
...
```
![](https://github.com/lyusupov/ADSB-Out/raw/master/documents/images/dump1090.JPG)

## References
1. "*Gr-Air-Modes*", **Nick Foster**, 2012
2. "*EXPLOITING THE AUTOMATIC DEPENDENT SURVEILLANCE BROADCAST SYSTEM VIA FALSE TARGET INJECTION*", **Domenic Magazu III**, 2012
3. "*ADS-B out by HACKRF and received over the air by rtl-sdr dongle and dump1090*", **Jiao Xianjun**, 2014
4. "*Ghost in the Air(Trafﬁc): On insecurity of ADS-B protocol and practical attacks on ADS-B devices*", **Andrei Costin and Aurelien Francillon**, 2015
5. "*ADS-B Decoding Guide*", **Junzi Sun**, 2017


