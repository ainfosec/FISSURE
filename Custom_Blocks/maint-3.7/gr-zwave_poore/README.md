# gr-zwave_poore

This GNU Radio out-of-tree module transmits Z-Wave signals and was tested with a USRP B210. Signals from an Aeotec Z-Stick Gen5 communicating with a Monoprice Z-Wave Plus RGB Smart Bulb through openHAB were analyzed with FM demodulation code and with the _rtl-zwave_ application. For longer messages, _rtl-zwave_ would consistently drop a bit and was a cause for some confusion. Inserting the missing bit did produce valid messages. I will attempt to develop more reliable receive code and update it here. I had limited success with the _scapy-radio_ z-wave module.

# Installation

The maint-3.7 branch is for GNU Radio versions prior to 3.8 while the maint-3.8 is for versions 3.8+.

```
cd gr-zwave_poore/
mkdir build
cd build
cmake ..
make
sudo make install
sudo ldconfig
```

# Inspiration

When I was researching how to do this I leaned on the following sites for guidance:

- https://github.com/baol/waving-z
- https://github.com/andersesbensen/rtl-zwave
- https://github.com/BastilleResearch/scapy-radio
- https://www.openhab.org/
- https://www.silabs.com/documents/login/miscellaneous/SDS13781-Z-Wave-Application-Command-Class-Specification.pdf
- https://www.silabs.com/documents/login/miscellaneous/SDS13548-List-of-defined-Z-Wave-Command-Classes.xlsx

# Transmit

The example transmit flow graph contains commands for turning the RGB bulb on and off along with switching the colors. There are blocks for changing it to red, green, and blue. The block that is set to the second configuration will cycle through a color list found in the _message\_generator\_pdu_ block. The block set to the third configuration will generate random RGB values.

The _msg\_length_ variable is the length in bytes from the start of the Home ID until the end of the CRC. The Home ID belongs to the light bulb. The Source Node ID represents the Z-Stick and the Destination Node ID is the bulb. The Command Classes and the formats for each message can be found in the Z-Wave Command Class specification. Lists of what hex values are associated with each Command Class can be found in the link above. The CRC is calculated across the Home ID to the end of the command. The polynomial is 0x1021 with a seed of 0x1D0F with no final XORing or data reversal.

There is a preamble of roughly 25 bytes of 0x55 followed by 0xF0 which are not part of the length count. Zeros are padded at the end of the message and the number of zero-padded bytes does not have an impact. I invert all the bits so the higher frequency is a 0 and the lower is a 1.

I do a weird tagging method for each message because the GFSK Mod hierarchical block adds a delay to things. Fortunately, it looks consistent. Fewer messages will go through if the message length is not accounted for in the delay and stream tagging.

All messages were transmitted after the light bulb was included into the stick's Z-Wave network (there's a pairing procedure that happens first). Signals were transmitted on 916 MHz with 40 kHz of deviation at 100 kbit/s. Although now that I look more at the specification, the 100 kbps rate should have a BT=0.6 with 58 kHz of separation. 

Here's a video of the random color configuration in action:

https://user-images.githubusercontent.com/12356089/131055067-3cf2e84f-a1bf-4b42-9021-76f22a84f62b.mp4

# Receive

The example receive flow graph will tag the start and stop of a message, smooth the output of the quadrature demod block, and take one of every ten samples for decoding. This will not decode every message due to a lack of synchronization with the one out of ten samples. The CRC is calculated for each decoded message and it can be compared with what is read in the message for integrity verification. It does not work well for weak signals. If successful, a message like this will appear:

```
Message #283:
Bitstream: 11111010000111000000101101001000000000010100000100001000000110000000001000110011000001010000010100000000000000000000000100000000000000100101110100000011111111110000010000000000010000111011001010000000000000
Full Hex: FA1C0B48014108180233050500000100025D03FF040043B2
Home ID: 0xFA1C0B48
Source Node ID: 01
Frame Control: 4108
Length: 18
Destination Node ID: 02
Command Class: 33
Command: 050500000100025D03FF0400
CRC: 43B2
Calculated CRC: 43B2
```
