#!/usr/bin/python
from math import *
from scipy import signal 
import matplotlib.pyplot as plt
from scipy import arange
import numpy as np
import sys
from struct import *
from scipy.signal import firwin
import array
import bitarray
def zwave_print(frame):
    print "Frame: " + frame.encode("hex")
    
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



samp = 400e3
f =  open(sys.argv[1], 'r')

n = 0

y2 = np.fromfile(f,dtype='int16') 

#plt.plot(y2)
#plt.show()

Wn = 100e3 / float(samp)
#Wn = 2*9.6e3 / float(samp)
b, a = signal.butter(8, Wn, 'low')
y1 = signal.lfilter(b, a, y2)

Wn = 10.1e3 / float(samp)
#Wn = 2.0e3 / float(samp)
b, a = signal.butter(4, Wn, 'low')

lock_det = signal.lfilter(b, a, y2)

S_IDLE = 0
S_PREAMP = 1
S_BITLOCK = 3

B_PREAMP = 1
B_SOF0 = 2
B_SOF1 = 3
B_DATA = 4

n = 0
state_b = B_PREAMP
pre_len = 0  # Length of preamble bit
pre_cnt = 0;

bit_len = 0
bit_cnt = 0.0;

wc = 0  # center frequency
bits = bitarray.bitarray()
state = S_IDLE
dif = []
last_logic = False
lead_in = 10

n=0
msc =False
frames=0
for s in y1:
    logic = (s - wc) < 0
    
    #If we are in bitlock mode, make sure that the signal does not derivate by more than
    # 1/2 seperation, TODO calculate 1/2 seperation
    if(state == S_BITLOCK):
        if(fabs(wc - lock_det[n])/0x7FFF < 0.1):
            signal=True
        else:
            signal=False
    elif(fabs(lock_det[n]) > 0.01*0x7FFF):
        signal=True
    else:
        signal = False

    if(signal):
        if(state == S_IDLE):
            state = S_PREAMP
            pre_cnt = 0
            pre_len = 0
            #print "Frame start",n
	    wc = lock_det[n]
        elif(state == S_PREAMP):
            wc = wc*0.99 + 0.01*lock_det[n]
            pre_len = pre_len + 1
            if(logic ^ last_logic): #edge trigger (rising and falling)
                pre_cnt = pre_cnt + 1
            
            if(pre_cnt == lead_in):  # skip the first lead_in
                pre_len = 0;
            elif(pre_cnt > lead_in+20):
                state = S_BITLOCK
                state_b = B_PREAMP
                
                bit_len = float(pre_len) / (pre_cnt - lead_in-1)
                #print bit_len

		dr = samp/bit_len
                #print "Center freq ",wc/(0x7FFF*2.0*pi)*samp," Data rate", dr,bit_len,n
		#9.6 kbps is manchester encoded
		msc = dr < 15.0e3 #make room for jitter in the data rate measurement

                bit_cnt = 3*bit_len/4.0 if msc else bit_len / 2.0

                last_bit = not logic
        elif(state == S_BITLOCK): #Preamble has been detected now we are processing bits not samples            
            pre_len = pre_len + 1
            if(logic ^ last_logic):
              pre_cnt = pre_cnt + 1
              if(state_b == B_PREAMP):
                bit_len = float(pre_len) / (pre_cnt - lead_in-1)
              if(msc):
                  if(bit_cnt < bit_len/2.0):
                    bit_cnt = bit_len/4.0
                  else:
                    bit_cnt = 3.0*bit_len/4.0
              else:
                  bit_cnt = bit_len / 2.0 #Re-sync on edges
            else:
                bit_cnt = bit_cnt + 1.0    

            if( bit_cnt >= bit_len): # new bit
		#if bit_len==4:
                #  print logic,state_b 
                if(state_b == B_PREAMP):
                    if( logic and last_bit):
                        pre_cnt = pre_cnt + 1
                        state_b = B_SOF1
                        b_cnt = 1 if bit_len != 4 else 2 #This was the first SOF bit			
                elif(state_b == B_SOF0):
                    if( not logic ):
                        b_cnt = b_cnt +1
                        if(b_cnt == 4):
                            b_cnt = 0
                            state_b = B_DATA
                    else:
                        print "SOF 0 error",b_cnt,n #1016182
                        state = S_IDLE
			#sys.exit(0)
                elif(state_b == B_SOF1):
                    if( logic ):
                        b_cnt = b_cnt +1
                        if(b_cnt == 4):
                            b_cnt = 0
                            state_b = B_SOF0
			   
                    else:
                        print "SOF 1 error",b_cnt,n
                        #sys.exit(0)
                        state = S_IDLE
                elif(state_b == B_DATA):
                    #print "Data",n
                    # print logic
                    bits.append(logic)
                
                last_bit = logic
                bit_cnt = bit_cnt - bit_len
    else: # No LOCK
        if(state == S_BITLOCK and state_b == B_DATA):
            frame = bits.tostring()
            print "FC=%10f DR=%6i"%(wc/(0x7FFF*2.0*pi)*samp, dr),
	    zwave_print(frame)
            bits = bitarray.bitarray()
            frames=frames +1 
        #  break
        state = S_IDLE

    last_logic = logic    
    #dif.append( (s-wc)*state/0x7FFF )
    #dif.append( (logic-0.5)*state*state_b)    
    n = n + 1

print frames,"Frames decoded"
#plt.plot(y2)
plt.plot(y1/ 0x7fff)
plt.plot(dif)
plt.plot(lock_det / 0x7fff)

plt.show()

sys.exit(0)

