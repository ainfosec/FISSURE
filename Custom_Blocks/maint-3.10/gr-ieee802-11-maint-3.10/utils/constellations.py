#!/usr/bin/env python

import sys
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt

import ieee802_11

###############################################
#                 16-QAM
###############################################

c = ieee802_11.constellation_16qam()
a = np.array(c.points())
p = np.average(np.abs(a)**2)
level = .1**.5

print "16-QAM, average power: {0:.4f}".format(p)

plt.scatter(a.real, a.imag)
for i, x in enumerate(a):
    s = "{0:04b}".format(i)[::-1]
    plt.text(x.real, x.imag+0.1, s, ha='center')

plt.show()

#######################
# test decison maker
#######################

N = 1000
data = np.random.randint(0, 16, N)
orig_const = a[data]
noisy_const = orig_const + np.random.sample(N) * 2 * level - level +\
                           np.random.sample(N) * 2j * level - level * 1j

rx = np.array(map(lambda x: c.decision_maker_v([x]), noisy_const))
rx_const = a[rx]

if any(rx != data):
    print "16-QAM: data does not match."
else:
    print "16-QAM: points decoded successfully."

plt.scatter(a.real, a.imag)
plt.scatter(noisy_const.real, noisy_const.imag, marker='x')
for d, a, b in zip(rx, rx_const, noisy_const):
    plt.plot([a.real, b.real], [a.imag, b.imag], color=mpl.cm.hsv(d/16.0))

plt.show()



###############################################
#                 64-QAM
###############################################

c = ieee802_11.constellation_64qam()
a = np.array(c.points())
p = np.average(np.abs(a)**2)
level = (1.0/42)**.5

print "64-QAM, average power: {0:.4f}".format(p)

plt.scatter(a.real, a.imag)
for i, x in enumerate(a):
    s = "{0:06b}".format(i)[::-1]
    plt.text(x.real, x.imag+0.06, s, ha='center')

plt.show()

#######################
# test decison maker
#######################

N = 1000
data = np.random.randint(0, 64, N)
orig_const = a[data]
noisy_const = orig_const + np.random.sample(N) * 2 * level - level +\
                           np.random.sample(N) * 2j * level - level * 1j

rx = np.array(map(lambda x: c.decision_maker_v([x]), noisy_const))
rx_const = a[rx]

if any(rx != data):
    print "16-QAM: data does not match."
else:
    print "16-QAM: points decoded successfully."

plt.scatter(a.real, a.imag)
plt.scatter(noisy_const.real, noisy_const.imag, marker='x')
for d, a, b in zip(rx, rx_const, noisy_const):
    plt.plot([a.real, b.real], [a.imag, b.imag], color=mpl.cm.hsv(d/64.0))

plt.show()
