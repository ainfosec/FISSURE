# ble_dump - SDR Bluetooth LE dumper

News: C++/Gnu Radio BLE/SB/ESB module will be released soon, stay tuned...

## Introduction
This tool was created to dump Bluetooth LE (BLE) packets using SDR hardware. The captured BLE packets can either be saved to a PCAP file or displayed directly in Wireshark via a named pipe (FIFO). Gnu Radio is used to receive and demodulate the incoming BLE packets. The received packet bytes are transferred to ble_dump using a common Gnu Radio Message Sink.

## Gnu Radio flow-graph
The following (simplified) Gnu Radio Companion (GRC) signal flow graph is used to generate the final flow-graph source code:
![GRC](https://raw.githubusercontent.com/drtyhlpr/ble_dump/master/grc/gr_ble.png)


## Command-line parameters
```
Usage: ble_dump.py: [opts]

Options:
  -h, --help            show this help message and exit

  Capture settings:
    -o PCAP_FILE, --pcap_file=PCAP_FILE
                        PCAP output file or named pipe (FIFO)
    -m MIN_BUFFER_SIZE, --min_buffer_size=MIN_BUFFER_SIZE
                        Minimum buffer size [default=65]
    -s SAMPLE_RATE, --sample-rate=SAMPLE_RATE
                        Sample rate [default=4000000.0]
    -t SQUELCH_THRESHOLD, --squelch_threshold=SQUELCH_THRESHOLD
                        Squelch threshold (simple squelch) [default=-70]

  Low-pass filter::
    -C CUTOFF_FREQ, --cutoff_freq=CUTOFF_FREQ
                        Filter cutoff [default=850000.0]
    -T TRANSITION_WIDTH, --transition_width=TRANSITION_WIDTH
                        Filter transition width [default=300000.0]

  GMSK demodulation::
    -S SAMPLES_PER_SYMBOL, --samples_per_symbol=SAMPLES_PER_SYMBOL
                        Samples per symbol [default=4]
    -G GAIN_MU, --gain_mu=GAIN_MU
                        Gain mu [default=0.7]
    -M MU, --mu=MU      Mu [default=0.5]
    -O OMEGA_LIMIT, --omega_limit=OMEGA_LIMIT
                        Omega limit [default=0.035]

  Bluetooth LE::
    -c CURRENT_BLE_CHANNELS, --current_ble_channels=CURRENT_BLE_CHANNELS
                        BLE channels to scan [default=37,38,39]
    -w BLE_SCAN_WINDOW, --ble_scan_window=BLE_SCAN_WINDOW
                        BLE scan window [default=10.24]
    -x, --disable_crc   Disable CRC verification [default=False]
    -y, --disable_dewhitening
                        Disable dewhitening [default=False]
```

## SDR hardware
Your SDR device should offer a minimum sample rate of 4.000.000 samples/sec. The SDR device as well should be usable as Gnu Radio osmocom/osmosdr source device. The HackRF One SDR was used for all Gnu Radio related tasks described within this document. Other SDRs should also work well.

## Usage
Scan BLE advisory channels (37, 38, 39) and save received packets to PCAP file:

```
./ble_dump.py -o /tmp/dump1.pcap
```

Scan BLE advisory channels (37, 38, 39) and send received packets to FIFO:

```
mkfifo /tmp/fifo1
./ble_dump.py -o /tmp/fifo1
```
Display BLE packets from FIFO in Wireshark:

```
wireshark -S -k -i /tmp/fifo1
```

## Notes
* The captured BLE packets are stored as "Bluetooth Low Energy Link Layer" (btle) format
* BLE Data and BLE Control packets are currently not supported
* If the default hopping pattern is used, and you want to receive BLE data it should be possible to hop only a limited number of BLE data channels. Keep in mind that the initial CRC value (not 0x555555) is essential to determine the validity of incoming BLE data packets.
* Feel free to help and improve the code!

The generated Gnu Radio Companion (GRC) signal flow graph (grc/gr_ble.py) was slightly modified to avoid errors. If you re-generate the GRC flow graph please run to following command-line:

```
sed -i -e "s/message_sink_msgq_out,/message_queue,/" -e "s/message_sink_msgq_out = virtual_sink_msgq_in/self.message_queue = message_queue/" ./grc/gr_ble.py
```
