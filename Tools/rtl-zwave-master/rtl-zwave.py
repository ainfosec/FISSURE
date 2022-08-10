#!/usr/bin/python
from math import *
from scipy import signal 
import matplotlib.pyplot as plt
from scipy import arange
import numpy as np
import sys
from struct import *
from scipy.signal import firwin


def zwave_print(frame):
    print "Frame: " + frame.encode("hex")
    
def bits2bytes(bits):
    r = ""
    by = 0
    c = 0
    for b in bits:
        by = (by << 1) | b
        c = c + 1
        if(c & 7 == 0):
            r = r + chr(by)
            by = 0
    return r
  
def butter_bandpass(lowcut, highcut, fs, order=5):
    nyq = 0.5 * fs
    low = lowcut / nyq
    high = highcut / nyq
    b, a = signal.butter(order, [low, high], btype='band')
    return b, a


def butter_bandpass_filter(data, lowcut, highcut, fs, order=5):
    b, a = butter_bandpass(lowcut, highcut, fs, order=order)
    y = signal.lfilter(b, a, data)
    return y



# fEU1	869.85	bw 300khz
# fEU2	868.40	bw 400khz
 
samp = 2024000

#f =  open('test_sample4', 'r')
f =  open(sys.argv[1], 'r')
#f = open('zwave_100k.bin', 'r')

n = 0


sigre = []
sigim = []

def rotate_90(j,re,im):    
    if(j==1):
      tmp = re
      re = im
      im = tmp
    elif(j==2):
      re = 255 - re
      im = 255 - im
    elif(j==3):
      tmp = 255 - re
      re = im
      im =tmp
    return (re,im)

try:
  while(True):
    (re, im) = unpack("2B", f.read(2))
    
    # "rotate 90" whatever that means?
    j = n & 3

    re,im = rotate_90(j,re,im)
    re = re - 127
    im = im - 127

    sigre.append(re)
    sigim.append(im)

    n = n + 1

    #if(n >= 50000):
    #    break;

except Exception:
  print "read error"

sig = np.array(sigre) + 1j*np.array(sigim)

sig = butter_bandpass_filter(sig,350e3,500e3,samp)

#Wn = 300.0e3 / float(samp)
#b, a = signal.butter(6, Wn, 'low')
#sig = signal.lfilter(b, a, sig)

plt.plot(sig.real,label="real")
plt.plot(sig.imag,label="imag")
plt.xlabel('Sample')
plt.title("RAW sampled data")
plt.legend()
plt.show()
  

sp = np.fft.fft(sig)
freq = np.fft.fftfreq(len(sig)) * samp
plt.plot(freq, sp.real, 'g-', freq, sp.imag, 'b-')

plt.xlabel('Frequency')
plt.title("Spectrum of RAW sampled data")
plt.show()

sold = 0


'''
Algorithm

The imput signal is on the form s(t) = a*exp(-i*w*t+p)
where a is the amplitude
w if the angular frequncy, (in reality w is a function of t but we will ignore that)
p if the phase difference

We wish to find w...

First we take the time derivative(s') of s
s' = -i(w)*a*exp(-i*w*t+p)

then we multiply s' by by conj(s) where conj is complex conjugation

s'*conj(s) = -i(w)*a*exp(-i*w*t+p)*a*exp(i*w*t + p)
           = -i(w)*a*a

finally we devide the result by the norm of s squared

s'*conj(s) / |s|^2 = -i(w+p)

Releated to the FSK demodulation, we know that w will fall out to two distinct values.
w1 and w2, and that w2-w1 = dw.

w will have the form w = wc +/- dw, where wc is the center frequnecy.

wc + p will show up as a DC component in the s'*conj(s) / |s|^2 function.
'''

# FSK decoder
def aes_fsk(sig):
  s1 = 0
  s2 = 0
  y2=[]
  kk=0
  for s in sig:
      p = np.abs(s1) 
      if(p > 0):
          ds = (s - s2) / 2 
          q = (np.conj(s1) * ds)  
          k = -q.imag/(p * p)

          if(k > pi or k < -pi):
            k=kk
          else:
            kk = k
      else:
          k=0

      s2 = s1
      s1 = s

      y2.append(k)
  return y2


# FSK decoder
def atan_fsk(sig):
  s1 = 0
  y2=[]
  for s in sig:
    k = np.angle(s*np.conj(s1))
    s1 = s

    y2.append(k)
  return y2




#y2 = aes_fsk(sig)
y2 = atan_fsk(sig)
#y2 = pll_fsk(sig)

Wn = 101e3 / float(samp)
#Wn = 2*9.6e3 / float(samp)
b, a = signal.butter(12, Wn, 'low')
y1 = signal.lfilter(b, a, y2)

Wn = 10.1e3 / float(samp)
#Wn = 2.0e3 / float(samp)
b, a = signal.butter(3, Wn, 'low')
print b
print a
lock_det = signal.lfilter(b, a, y2)

S_IDLE = 0
S_PREAMP = 1
S_BITLOCK = 3

B_PREAMP = 1
B_SOF0 = 2
B_SOF1 = 3
B_DATA = 4

n = 0

pre_len = 0  # Length of preamble bit
pre_cnt = 0;

bit_len = 0
bit_cnt = 0.0;

wc = 0  # center frequency
bits = []
state = S_IDLE
dif = []
last_logic = False
lead_in = 10

n=0
for s in y1:
    logic = (s - wc) > 0
    
    #If we are in bitlock mode, make sure that the signal does not derivate by more than
    # 1/2 seperation, TODO calculate 1/2 seperation
    if(state == S_BITLOCK):
        if(fabs(wc - lock_det[n]) < 0.1):
            signal=True
        else:
            signal=False
    elif(fabs(lock_det[n]) > 0.01):
        signal=True
    else:
        signal = False

    if(signal):
        if(state == S_IDLE):
            state = S_PREAMP
            pre_cnt = 0
            pre_len = 0
            print "Frame start",n
        elif(state == S_PREAMP):
            wc = lock_det[n]            
            pre_len = pre_len + 1
            if(logic ^ last_logic): #edge trigger (rising and falling)
                pre_cnt = pre_cnt + 1
            
            if(pre_cnt == lead_in):  # skip the first lead_in
                pre_len = 0;
            elif(pre_cnt > 30):
                print "Center freq ",wc/(2.0*pi)*samp
                state = S_BITLOCK
                state_b = B_PREAMP
                
                bit_len = float(pre_len) / (pre_cnt - lead_in)
                #print bit_len
                bit_cnt = bit_len / 2.0
                last_bit = not logic
        elif(state == S_BITLOCK): #Preamble has been detected now we are processing bits not samples            
            if(logic ^ last_logic):
                bit_cnt = bit_len / 2.0 #Re-sync on edges
            else:
                bit_cnt = bit_cnt + 1.0    

            if(bit_cnt >= bit_len): # new bit
                if(state_b == B_PREAMP):
                    if( logic and last_bit):
                        state_b = B_SOF1
                        b_cnt = 1 #This was the first SOF bit
                elif(state_b == B_SOF0):
                    if( not logic ):
                        b_cnt = b_cnt +1
                        if(b_cnt == 4):
                            b_cnt = 0
                            state_b = B_DATA
                    else:
                        print "SOF 0 error",b_cnt,n
                        state = S_IDLE
                elif(state_b == B_SOF1):
                    if( logic ):
                        b_cnt = b_cnt +1
                        if(b_cnt == 4):
                            b_cnt = 0
                            state_b = B_SOF0
                    else:
                        print "SOF 1 error",b_cnt,n
                        state = S_IDLE
                elif(state_b == B_DATA):
                    print "Data",n
                    # print logic
                    bits.append(logic)
                
                last_bit = logic
                bit_cnt = bit_cnt - bit_len
    else: # No LOCK
        if(state == S_BITLOCK):
            frame = bits2bytes(bits)
            zwave_print(frame)
            bits = []
    
        #  break
        state = S_IDLE

    last_logic = logic    
    dif.append(s - wc)  
    n = n + 1

# print len(dif)
plt.plot(y2)
plt.plot(y1)
plt.plot(dif)
plt.plot(lock_det)

plt.show()

sys.exit(0)

