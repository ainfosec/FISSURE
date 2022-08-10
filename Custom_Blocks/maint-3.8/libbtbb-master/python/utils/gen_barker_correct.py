#!/usr/bin/env python

# Reverse the binary of thesebarker codes for the host code
barkers = (0x0d, 0x72)
distances = []
corrections = []

def count_bits(x):
    i = 0
    while x:
        i += 1
        x &= x - 1
    return i

for i in range(128):
    diffs = [(count_bits(barkers[0] ^ i), barkers[0]),
             (count_bits(barkers[1] ^ i), barkers[1])]
    diffs.sort()
    distances.append(diffs[0][0])
    corrections.append(diffs[0][1])

print "Barker distance:", distances
print "Barker correct:", ["0x%x" % c for c in corrections]
