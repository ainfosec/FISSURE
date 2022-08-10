#!/usr/bin/python

# (64,30) linear block code stuff

polynomial = 0260534236651

# produce generator matrix g
g = []
for i in range(30):
	g.append(polynomial << i)
	for j in range(i):
		if g[i] & (1 << (33 + i - j)):
			g[i] ^= g[i-j-1]

#print
#for i in range(29,-1,-1):
	#print "0x%016x," % g[i]
#print

# produce check matrix h
h = []
for i in range(34):
	h.append(0)
	for j in range(30):
		h[i] |= (g[29-j] >> i) & 0x1
		h[i] <<= 1
	h[i] <<= 33
	h[i] |= (0x1 << i)

#print
#for i in range(34):
	#print "0x%016x," % h[i]
#print

# reverse the order
g = g[::-1]
h = h[::-1]

def count_bits(n):
	i = 0
	while n != 0:
		n &= n - 1
		i += 1
	return i

def gen_syndrome(c):
	assert c < 2**64
	s = 0
	# look for a faster GF(2) matrix multiplication algorithm
	for i in range(34):
		s <<= 1
		s |= (count_bits(c & h[i]) % 2)
	return s

# optimized check table generation (sw_check_tables.h)
for shift in range(8):
	for i in range(256):
			print "0x%09x, " % gen_syndrome(i<<(shift*8)),
	print
