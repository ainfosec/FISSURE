#!/usr/bin/python

# produce a sync word for a given LAP

lap = 0xffffff

pn = 0x83848D96BBCC54FC

# generator matrix for (64,30) linear block code
# based on polynomial 0260534236651
# (see gen_check_tables.py for automatic generation)
g = (
	0x8000000000000001,
	0x40000002c2b89ed4,
	0x20000001615c4f6a,
	0x10000000b0ae27b5,
	0x080000029aef8d0e,
	0x040000014d77c687,
	0x0200000264037d97,
	0x01000003f0b9201f,
	0x008000033ae40edb,
	0x004000035fca99b9,
	0x002000036d5dd208,
	0x00100001b6aee904,
	0x00080000db577482,
	0x000400006dabba41,
	0x00020002f46d43f4,
	0x000100017a36a1fa,
	0x00008000bd1b50fd,
	0x000040029c3536aa,
	0x000020014e1a9b55,
	0x0000100265b5d37e,
	0x0000080132dae9bf,
	0x000004025bd5ea0b,
	0x00000203ef526bd1,
	0x000001033511ab3c,
	0x000000819a88d59e,
	0x00000040cd446acf,
	0x00000022a41aabb3,
	0x0000001390b5cb0d,
	0x0000000b0ae27b52,
	0x0000000585713da9)

def encode(data):
	assert data < 2**30
	codeword = 0
	for i in range(30):
		if (data & (0x20000000 >> i)):
			codeword ^= g[i]
	return codeword

# append barker code
if (lap & 0x800000):
	data = 0x13000000 | lap
else:
	data = 0x2c000000 | lap

# scramble
data ^= (pn >> 34)

# encode
codeword = encode(data)

# scramble again
syncword = codeword ^ pn

print "0x%06x 0x%016x 0x%016x" % (lap, codeword, syncword)
