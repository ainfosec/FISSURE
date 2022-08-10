---
A tire-pressure monitoring system (TPMS) monitors the air pressure inside pneumatic tires on vehicles. There are several varieties that fall under the categories of indirect TPMS and direct TPMS. Indirect TPMS does not use physical pressure sensors but derives information from other sensor signals like wheel speed, accelerometers, driveline data, etc. Direct TPMS measures the tire pressure from a battery-drive pressure sensor on the inside of the valve for each tire. Signals are transmitted periodically to a vehicle central control unit which reports it to the vehicle's onboard computer. Other information such as temperature, battery status, or rapid pressure drop alerts can also be included in each message. There are hundreds of combinations of TPMS message formats, modulation types, and encodings. The signals are transmitted at 315 MHz or 433 MHz.

This lesson provides example tools and reference material to help learn about TPMS. 

## Table of Contents
1. [References](#references)
2. [tpms_rx](#tpms_rx)
3. [gr-tpms_poore](#gr_tpms_poore)
4. [rtl_433](#rtl_433)

<div id="references"/> 

## References

- https://github.com/jboone/gr-tpms
- https://github.com/cpoore1/gr-tpms_poore
- https://github.com/jboone/gr-tpms/blob/master/python/packet_check.py
- https://github.com/xnk/pacific-tpms
- https://github.com/merbanan/rtl_433/tree/master/src/devices

<div id="tpms_rx"/>   

## tpms_rx

The gr-tpms out-of-tree module for GNU Radio by jboone includes a `tpms_rx` command for capturing, demodulating, decoding, and assessing data from tire pressure monitors. There is a live capture mode which is included in the FISSURE menu. Example commands to utilize `tpms_rx` are:

```
tpms_rx --source rtlsdr --if-rate 400000 --tuned-frequency 315000000
tpms_rx --source hackrf --if-rate 400000 --tuned-frequency 315000000
tpms_rx --if-rate 400000 --file <filename of complex<float32> file sampled at 400kHz>
--bursts: Output a complex<float32> file of each burst of significant energy.
--raw: Output undecoded bits of detected packets.
tpms_burst_ping .
```

This program accounts for several varieties of TPMS as can be seen in the code. It is good for logging data from other vehicles while driving around. However, the raw data requires some formatting knowledge to make sense out of it.

- https://github.com/jboone/gr-tpms
- https://github.com/jboone/gr-tpms/blob/master/python/packet_check.py

## gr-tpms_poore

I made this TPMS out-of-tree module for the purpose of integrating it into FISSURE. Currently, it only accounts for one type of TPMS sensor but it has proven transmit and receive capabilities for my car. The following sections are pulled directly from the github page:

- https://github.com/cpoore1/gr-tpms_poore

This GNU Radio out-of-tree module transmits and receives Tire Pressure Monitoring System (TPMS) signals for the sensor on my car. More sensors and SDRs might be supported/tested in the future. This all works fine for me when I transmit from the driver's seat and when I receive next to the target tire with either a USRP B210 or B205mini using the standard HackRF antenna.

### Installation

The maint-3.7 branch is for GNU Radio versions prior to 3.8 while the maint-3.8 is for versions 3.8+.

```
sudo python -m pip install crcmod
cd gr-tpms_poore/
mkdir build
cd build
cmake ..
make
sudo make install
sudo ldconfig
```

### Inspiration

When I was researching how to do this I leaned on the following sites for guidance:

- https://github.com/jboone/gr-tpms
- https://github.com/jboone/gr-tpms/blob/master/python/packet_check.py
- https://github.com/xnk/pacific-tpms
- https://github.com/merbanan/rtl_433/tree/master/src/devices

### Transmit

The fields observed in the data mostly line up with what was observed by xnk. I am keeping the same nomenclature because I did not see an impact on the car for some of the bit locations. Therefore, maybe a feature is not supported by my car but the field is still valid, who knows. Let me know if you are aware of what all the bits do.

The _message\_generator\_pdu_ block requires the following information:

- Repetition Interval: How often messages are generated.
- Configuration: This is a placeholder for switching between TPMS formats. There is only one format supported for now. Keep it 1.
- Sensor ID: The 28-bit ID to be entered as a hex string (ABCDEF1). Unique for each tire.
- Battery Status: 1 bit. No observable impact. I think I observed this as a 0 and 1 from the same sensor so it could be part of the counter.
- Counter: 2 bits. No observable impact. Changes frequently, appears to be a counter.
- Unknown1: 1 bit. No observable impact. Always set to 0.
- Unknown2: 1 bit. No observable impact. Always set to 0.
- Self-Test Failed: Makes warning light flash when set to 1. If I sent messages fast, the light would appear steady and then resume flashing when I stopped. If I sent messages slow, the flash would not always occur until I retried it from the start (maybe it is just me). I would believe it if this turned out to be the rapid pressure drop field.
- Tire Pressure: 8 bits. Entered in PSI as a decimal. The warning light comes on for me at 25.41 PSI ('01101110'). The formula to produce the bits is: (pressure/0.363)+40. The next field is the tire pressure complement, which is the opposite of the pressure ('01101110'->'10010001'). The code calculates that for you.
- Temperature: 8 bits. The temperature in Celsius. The formula to convert the temperature to bits is: (temp_Celsius+40). The 8-bit CRC field immediately follows and is calculated for you. The CRC works as xnk described it with the six bits of padding at the front with the 0x13 polynomial.

The block assembles the fields, applies the access code at the front, throws in a little extra at the end, and outputs the bytes as a pdu. The flow graph GFSK modulates the +/-40 kHz signal centered at 314.96 MHz. I sampled everything at 1 MS/s and took 100 samples/symbol for a bit rate of 10000 bps. It was close to what xnk observed, not exact, but this worked for me.

I do a weird tagging method for each message because the GFSK Mod hierarchical block adds a delay to things. Fortunately, it looks consistent. Don't worry if the QT GUI Time Sink doesn't show them in the right place, there's something up with that block. I've always found the tags are in the right spot when they go to the radio. I've seen the B205mini do a power ramp-up when using the TSB tags for other things but it didn't have an impact on the messages getting through to the car so I didn't introduce any extra padding in front of each message.

Here's a video of a program that runs the integrated transmit flow graph for two scenarios: low tire pressure and the self-test failed bit set to '1'.

https://user-images.githubusercontent.com/12356089/126883222-476f65e1-6f48-4cbb-94e7-2658cf96a430.mp4

### Receive

The receive flow graph tags the start and end of each message with the Burst Tagger block. The instantaneous frequency is used to produce the bitstream. The upper frequency is the '1' and the lower is the '0'.

![message](./Images/message.png)

The decoder block isolates the data between the burst tags and works with it to detect the start of each message. My biggest problem in all of this was determining where the message data started. For this xnk was spot on in his README but jboone's "packet_check.py" code threw me off. The data was not aligned right unless the start was the last '01' in the '00111111001' access code. The data from there on out is all Manchester encoded. There will never be three 0's or three 1's in a row for all the chips. I took the bitstream, Manchester decoded it (01=0, 10=1), differentiated the bits, and parsed the fields.

If the signal strength is strong enough, a message like this will be printed: 

```
Message #4:
Bitstream: 01011010010101101001010101101001010110100101010110101010100110101010101001011010011001101001011010101010100110011010010101010101100101111111
Decoded Bits: 010100101000101001010001000011000001010111101010000011110100000110100
Sensor ID: 0x528A510
Battery_Status: 1
Counter: 10
Unknown1: 0
Unknown2: 0
Self Test Failed: 0
Tire Pressure: 01010111 | PSI: 17.061
T.P. Complement: 10101000
Tire Temperature: 00111101 | Celsius: 21 | Fahrenheit: 69
CRC: 00000110
```


## rtl_433

rtl_433 contains code for several types of TPMS sensors. Not yet verified.

- https://github.com/merbanan/rtl_433/tree/master/src/devices
