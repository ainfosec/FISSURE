"""
Embedded Python Blocks:

Each time this file is saved, GRC will instantiate the first class it finds
to get ports and parameters of your block. The arguments to __init__  will
be the parameters. All of them are required to have default values!
"""

import numpy as np
from gnuradio import gr
import time

class blk(gr.sync_block):  # other base classes are basic_block, decim_block, interp_block
    """Embedded Python Block example - a simple multiply const"""

    def __init__(self, vec_len=8192, peak_detect_file="/tmp/indexes.data", fft_threshold=-80, sample_rate=1000000):  # only default arguments here
        """arguments to this function show up as parameters in GRC"""
        gr.sync_block.__init__(
            self,
            name='Embedded Python Block',   # will show up in GRC
            in_sig=[(np.float32,vec_len)],
            out_sig=None
        )
        # if an attribute with the same name as a parameter is found,
        # a callback is registered (properties work, too).
        self.peak_detect_file=peak_detect_file
        self.fft_threshold=fft_threshold
        self.vec_len=vec_len
        self.sample_rate=sample_rate
        self.max_value=-100
        self.max_index=-1
        print("Starting Frequency Detection")


    def work(self, input_items,output_items):
        over_threshold = input_items[0][0][np.nonzero(input_items[0][0] > self.fft_threshold)]
        if len(over_threshold) > 0:
            if over_threshold.max() > self.max_value:
                self.max_value = over_threshold.max()
                self.max_index = input_items[0][0].argmax()
                print("Strongest Freq.: " + str(self.max_value) + ' (dB), ' + str(self.max_index) + ' (bin), ' + str(float(self.max_index/self.vec_len)*self.sample_rate-float(self.sample_rate/2)) + " (Hz)")
            
                with open(self.peak_detect_file,'w') as fobj:
                    fobj.write(str(float(self.max_index/self.vec_len)*self.sample_rate-float(self.sample_rate/2)))
        return len(input_items[0])
