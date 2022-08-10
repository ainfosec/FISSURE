#!/usr/bin/env python

num_channels = 40
bits = []
channels = {}
reg = 0x57

while not (len(bits) and reg==0x57):
    if reg & 0x3f < num_channels and reg & 0x40:
        channels[reg & 0x3f] = len(bits)
    bit = (reg & 1)
    bits.append(bit)
    reg >>= 1
    reg |= (bit << 6)
    reg ^= (bit << 2)

print bits

print "\nArray index:"
for k in sorted(channels.keys()):
    print channels[k]
