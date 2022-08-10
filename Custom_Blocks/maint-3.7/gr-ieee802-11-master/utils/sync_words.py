#!/usr/bin/env python


short  = tuple([(52**.5/24**.5) * x for x in [0, 0, 0, 0, 0, 0, 0, 0, 1+1j, 0, 0, 0, -1-1j, 0, 0, 0, 1+1j, 0, 0, 0, -1-1j, 0, 0, 0, -1-1j, 0, 0, 0, 1+1j, 0, 0, 0, 0, 0, 0, 0, -1-1j, 0, 0, 0, -1-1j, 0, 0, 0, 1+1j, 0, 0, 0, 1+1j, 0, 0, 0, 1+1j, 0, 0, 0, 1+1j, 0, 0, 0, 0, 0, 0, 0]])

long_norm = tuple([0, 0, 0, 0, 0, 0, 1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, 1, 1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, 1, 0, 1, -1, -1, 1, 1, -1, 1, -1, 1, -1, -1, -1, -1, -1, 1, 1, -1, -1, 1, -1, 1, -1, 1, 1, 1, 1, 0, 0, 0, 0, 0])


mul = tuple([1, -1j, -1, 1j] * 16)
long_rot = tuple([x * y for x, y in zip(long_norm, mul)])


sync = tuple([short, short, long_rot, long_norm])


assert(len(short)     == 64)
assert(len(long_norm) == 64)
assert(len(long_rot)  == 64)
assert(len(sync)      == 4)

print "power short: " + str(sum([abs(x)**2 for x in short]))
print "power long: " + str(sum([abs(x)**2 for x in long_norm]))

print "sync sequence"
print sync
print "len sync: " + str(len(sync))







