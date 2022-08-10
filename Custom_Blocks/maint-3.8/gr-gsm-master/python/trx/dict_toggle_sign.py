"""
Embedded Python Blocks:

Each this file is saved, GRC will instantiate the first class it finds to get
ports and parameters of your block. The arguments to __init__  will be the
parameters. All of them are required to have default values!
"""

from gnuradio import gr
from pmt import *

class dict_toggle_sign(gr.basic_block):
    def __init__(self):  # only default arguments here
        gr.basic_block.__init__(
            self,
            name='Change sign of elts in dict',
            in_sig=[],
            out_sig=[]
        )
        self.message_port_register_in(intern("dict_in"))
        self.message_port_register_out(intern("dict_out"))
        self.set_msg_handler(intern("dict_in"), self.change_sign)

    def change_sign(self, msg):
        if is_dict(msg):
            d = to_python(msg)
            #print d
            for key, value in d.items():
                d[key] *= -1
            self.message_port_pub(intern("dict_out"), to_pmt(d))
