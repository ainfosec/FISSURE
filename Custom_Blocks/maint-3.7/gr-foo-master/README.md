```
                     ____                 \
   ____ ______      / __/___  ____     \   \
  / __ `/ ___/_____/ /_/ __ \/ __ \  \  |   |
 / /_/ / /  /_____/ __/ /_/ / /_/ /  /  |   |
 \__, /_/        /_/  \____/\____/     /   /
/____/                                    /

```

Hi!

This is a collection of custom blocks that are not directly associated with a
project. For sample applications see:

-  https://github.com/bastibl/gr-ieee802-11
-  https://github.com/bastibl/gr-ieee802-15-4



### Development

Like GNU Radio, this module uses *master* and *next* branches for development, which are supposed to be used with the corresponding GNU Radio branches.
I recommend staying up-to-date by using the *next* branch.



### Wireshark Connector

This blocks outputs PDUs in the PCAP format which is supported by all common
network monitoring applications. Some examples are Wireshark, Tshark, and
tcpdump. Currently, it supports WiFi packets with Radiotap header and ZigBee.

For further information about Radiotap, PCAP, and Wireshark see:

- http://www.radiotap.org/
- http://www.wireshark.org/



### Packet Pad

Adds a configurable number of zeros before and after a burst. The burst has to
be started with an tx_sob, and ended with a tx_eob tag. From time to time I had
issues when I did not pad the sample stream. This block helps to investigate
that. It is also handy for loopback testing when there is no continues sample
stream. Furthermore, this block can add a tx_time tag to every burst that lies
a configurable number of seconds in the future. This is handy to buffer the
sample stream for a short time to avoid underruns during the transmission,
which lead to corrupted signals. You have to set the sync option to 'PC source'
for this feature.



### Burst Tagger

Tags a burst / packet / bunch of samples with tx_sob and tx_eob tags. This is
useful if the SDR is operating in half-duplex mode. With adding a tx_eob the
USRP switches back to receive mode immediately. That way, direct responses like
ACKs are not missed.

The block searches for a special tag that indicates the start of a burst. The
name of this tag is configurable. The tag should indicate the length of the
packet in samples. Also a multiplier can be specified, which multiples the
length given in the tag.



### Packet Dropper

Drops a configurable percentage of messages. I used it to test protocol logic
like ACKs, retransmission and stuff.



### Periodic Msg Source

This block sends messages at regular intervals much like the Message Strobe
block in mainline GNU Radio. With this block you can also configure the number
of packets that are sent. When all normal messages are sent, the blocks sends a
final PMT_EOF message to indicate that it is done.
I used this block for automated performance tests with no-GUI flow graphs.


### Dependencies

GNU Radio v3.7


### Installation

```
git clone https://github.com/bastibl/gr-foo.git
cd gr-foo
mkdir build
cd build
cmake ..
make
sudo make install
sudo ldconfig
``` 

