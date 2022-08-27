# vim: set ts=4 sw=4 tw=0 et pm=:

import sys
import numpy as np
from gnuradio import gr


class file_object_source(gr.sync_block):
    """Python Block - a minimal file object source"""

    def __init__(self, fileobject=None, itemtype=np.complex64):
        gr.sync_block.__init__(
            self,
            name='Python File Object Source',
            in_sig=None,
            out_sig=[itemtype]
        )
        self.fileobject = fileobject
        self.itemtype = itemtype
        self.itemsize = np.dtype(self.itemtype).itemsize

    def work(self, input_items, output_items):
        items = len(output_items[0])
        count = items * self.itemsize

        buf = self.fileobject.read(count)

        if len(buf) == count:
            output_items[0][:] = np.frombuffer(buf, dtype=self.itemtype)
        elif len(buf) == 0:
            return -1  # WORK_DONE
        else:
            items = len(buf) // self.itemsize
            if (len(buf) % self.itemsize) != 0:
                print("Error[file_object_source]: read returned non-multiple of itemsize(%d)" % self.itemsize, file=sys.stderr)
                buf = buf[:(items * self.itemsize)]
            output_items[0][:items] = np.frombuffer(buf, dtype=self.itemtype)
        return items
