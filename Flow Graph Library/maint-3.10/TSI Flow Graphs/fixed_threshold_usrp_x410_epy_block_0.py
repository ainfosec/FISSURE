"""
Embedded Python Blocks:

Each time this file is saved, GRC will instantiate the first class it finds
to get ports and parameters of your block. The arguments to __init__  will
be the parameters. All of them are required to have default values!
"""

import numpy as np
from gnuradio import gr
import time
import pmt
import zmq

class blk(gr.sync_block):  # other base classes are basic_block, decim_block, interp_block
    """Embedded Python Block example - a simple multiply const"""

    def __init__(self, vec_len=8192, sample_rate=1000000, rx_freq_mhz=2412):  # only default arguments here
        """arguments to this function show up as parameters in GRC"""
        gr.sync_block.__init__(
            self,
            name='Embedded Python Block',   # will show up in GRC
            in_sig=[(np.float32,vec_len),(np.float32,vec_len)],
            out_sig=None
        )
        # if an attribute with the same name as a parameter is found,
        # a callback is registered (properties work, too).
        self.message_port_register_out(pmt.intern('detected_signals'))         
        self.sample_rate = sample_rate
        self.fft_size = vec_len
        self.rx_freq_mhz = rx_freq_mhz

    def work(self, input_items,output_items):
        for vecindx in range(len(input_items[0])):
            if len(np.nonzero(input_items[0][vecindx] > input_items[1][vecindx][0])[0])>0:
                max_index = (input_items[0][vecindx]).argmax()
                max_freq = str(round((max_index/int(self.fft_size))*float(self.sample_rate)/1e6 - (float(self.sample_rate)/2e6) + float(self.rx_freq_mhz),4)*1000000)
                max_power = str(int(input_items[0][vecindx][np.nonzero(input_items[0][vecindx] > input_items[1][0])].max()))
                self.message_port_pub(pmt.intern('detected_signals'), pmt.intern('TSI:/Signal Found/' + max_freq + '/' + max_power + '/' + str(time.time())))

        return len(input_items[0])
