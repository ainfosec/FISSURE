---
The following are examples of different ways to work with custom GNU Radio blocks. The main functionality for blocks are contained in either Python or C++ with the graphical/input parameters configured in a .xml or .yml file depending on the GNU Radio version. 

## Table of Contents
1. [References](#references)
2. [Creating from Scratch](#from_scratch)
3. [Creating Input Parameters](#input_parameters)
4. [Adding Stream Tags](#adding_stream_tags)
5. [Reading Stream Tags](#reading_stream_tags)
6. [Removing Tags](#removing_tags)
7. [Use the Last N Samples](#last_n_samples)
8. [Message Passing](#message_passing)
9. [PDUs](#pdus)
10. [Reusing Existing GNU Radio Types](#existing_gnu_radio_types)

<div id="references"/> 

## References

- https://wiki.gnuradio.org/index.php/Guided_Tutorial_GNU_Radio_in_Python#3.2.1._Using_gr_modtool
- https://wiki.gnuradio.org/index.php/OutOfTreeModules
- https://github.com/dzlabsio/gr-callback_xml
- https://wiki.gnuradio.org/index.php/Message_Passing

<div id="from_scratch"/>   

## Creating from Scratch

**Generic Python Block**

https://wiki.gnuradio.org/index.php/Guided_Tutorial_GNU_Radio_in_Python#3.2.1._Using_gr_modtool

https://wiki.gnuradio.org/index.php/OutOfTreeModules

```
gr_modtool newmod <name>
cd <name>
gr_modtool add -t sync -l python
<block_name: framer>
```

```
gr_modtool: option -t: (choose from 'sink', 'source', 'sync', 'decimator', 
'interpolator', 'general', 'tagged_stream', 'hier', 'noblock')
```

**Edit the Main Python File**
```xml
def __init__(self):
    gr.sync_block.__init__(self,
        name="downlink_tagger",
        in_sig=[<+numpy.float+>],
        out_sig=[<+numpy.float+>])
```
Types: numpy.complex64, numpy.float32, numpy.uint8

**Edit the *./grc/* XML File**
```python
<?xml version="1.0"?>
<block>
  <name>downlink_tagger</name>
  <key>lightbridge_downlink_tagger</key>
  <category>lightbridge</category>
  <import>import lightbridge</import>
  <make>lightbridge.downlink_tagger()</make>
  <!-- Make one 'param' node for every Parameter you want settable from the GUI.
       Sub-nodes:
       * name
       * key (makes the value accessible as $keyname, e.g. in the make node)
       * type -->
  <param>
    <name>...</name>
    <key>...</key>
    <type>...</type>
  </param>

  <!-- Make one 'sink' node per input. Sub-nodes:
       * name (an identifier for the GUI)
       * type
       * vlen
       * optional (set to 1 for optional inputs) -->
  <sink>
    <name>in</name>
    <type><!-- e.g. int, float, complex, byte, short, xxx_vector, ...--></type>
  </sink>

  <!-- Make one 'source' node per output. Sub-nodes:
       * name (an identifier for the GUI)
       * type
       * vlen
       * optional (set to 1 for optional inputs) -->
  <source>
    <name>out</name>
    <type><!-- e.g. int, float, complex, byte, short, xxx_vector, ...--></type>
  </source>
</block>
```

**Make/Add Module to FISSURE**

Copy *gr-name* folder to *~/Fissure/Custom_Blocks/maint-3.x* and build the module. Afterwards, click the "Reload Blocks" arrow in GNU Radio Companion to load the new custom blocks.

```
cd *~/FISSURE/Custom_Blocks/maint-3.7/gr-<name>*
mkdir build
cd build
cmake ..
make
sudo make install
sudo ldconfig
```

**Refresh GNU Radio Companion**

Click the blue arrow to reload the blocks.

![reload](./Images/reload.png)

**Making C++ Blocks**
```
gr_modtool add -t sync -l cpp <block_name>
```
Similar procedure to Python but use this for the complex data type:
```
gr_complex
```

<div id="input_parameters"/>  

## Creating Input Parameters

In the xml:

```xml
  <make>lightbridge.downlink_tagger($high_threshold,$low_threshold)</make>
  
  <callback>set_high_threshold($high_threshold)</callback>
  <callback>set_low_threshold($low_threshold)</callback>
  
  <param>
    <name>high_threshold</name>
    <key>high_threshold</key>
    <value>"0.4"</value>
    <type>float</type>
  </param>
  <param>
    <name>low_threshold</name>
    <key>low_threshold</key>
    <value>"0.01"</value>
    <type>float</type>
```

In the Python file:

```python
class downlink_tagger(gr.sync_block):
    """
    docstring for block downlink_tagger
    """
    def __init__(self, high_threshold, low_threshold):
        gr.sync_block.__init__(self,
            name="downlink_tagger",
            in_sig=[numpy.complex64],
            out_sig=[numpy.complex64])
            
        self.high_threshold = high_threshold
        self.low_threshold = low_threshold        
        
    def set_high_threshold(self,high_threshold):
        self.high_threshold = float(high_threshold)
        
    def set_low_threshold(self,low_threshold):
        self.low_threshold = float(low_threshold)
```

For Callbacks in C++:
https://github.com/dzlabsio/gr-callback_xml

<div id="adding_stream_tags"/>  

## Adding Stream Tags
```python
 import numpy as np
 from gnuradio import gr
 import pmt
 
 class blk(gr.sync_block):
     def __init__(self):
         gr.sync_block.__init__(
             self,
             name='Embedded Python Block',
             in_sig=[np.complex64],
             out_sig=[np.complex64]
         )
 
     def work(self, input_items, output_items):
         for indx, sample in enumerate(input_items[0]):
             if np.random.rand() > 0.95: # 5% chance this sample is chosen
                 key = pmt.intern("example_key")
                 value = pmt.intern("example_value")
                 self.add_item_tag(0, self.nitems_written(0) + indx, key, value)
                 # note: (self.nitems_written(0) + indx) is our current sample, in absolute time
         output_items[0][:] = input_items[0] # copy input to output
         return len(output_items[0])
```

<div id="reading_stream_tags"/>  

## Reading Stream Tags
To get tags from a particular input stream, we have two functions we can use:

    gr::block::get_tags_in_range: Gets all tags from a particular input port between a certain range of items (in absolute item time).

    gr::block::get_tags_in_window: Gets all tags from a particular input port between a certain range of items (in relative item time within the work function).

The difference between these functions is working in absolute item time versus relative item time. Both of these pass back vectors of gr::tag_t, and they both allow specifying a particular key (as a PMT symbol) to filter against (or the fifth argument can be left out to search for all keys). Filtering for a certain key reduces the effort inside the work function for getting the right tag's data.

For example, this call just returns any tags between the given range of items:

```
#include <pmt/pmt.h>
#include <string>

void get_tags_in_range(std::vector<tag_t> &v,
                        unsigned int which_input,
                        uint64_t abs_start,
                        uint64_t abs_end);

std::vector<gr::tag_t> tags;
get_tags_in_range(tags, 0, nitems_read(0), nitems_read(0) + framesize);
for (unsigned t = 0; t < tags.size(); t++) {
            int offset = tags[t].offset - nitems_read(0);
            tags[t].offset = offset + nitems_written(0);
            add_item_tag(0, tags[t]);           
            printf("\n[*] TAG FOUND: %s",  (pmt::symbol_to_string(tags[t].key)).c_str());
```

Adding a fifth argument to this function allows us to filter on the key key.

```
 void get_tags_in_range(std::vector<tag_t> &v,
                        unsigned int which_input,
                        uint64_t abs_start,
                        uint64_t abs_end,
                        const pmt::pmt_t &key);
```

In Python, the main difference from the C++ function is that instead of having the first argument be a vector where the tags are stored, the Python version just returns a list of tags. We would use it like this:

```python
def work(self, input_items, output_items):
    ....
    tags = get_tags_in_window(which_input, rel_start, rel_end)

    tags = self.get_tags_in_window(0, 0, input_len,pmt.string_to_symbol("downlink"))
    for tag in tags:  #.offset, .key, .value
        print str(tag.offset)
    ....
```

<div id="removing_tags"/>  

## Removing Tags

Remove all tags coming in and then you can make your own tags going out. The function for removing a single tag is deprecated.

```python
from gnuradio import gr
import pmt

class cp_remover(gr.sync_block):
    def __init__(self):
        gr.sync_block.__init__(self,
            name="cp_remover",
            in_sig=[numpy.complex64],
            out_sig=[numpy.complex64])
        
        # Don't Propagate Tags
        self.set_tag_propagation_policy(gr.TPP_DONT)

    def work(self, input_items, output_items):
        in0 = input_items[0]
        in0_len = len(in0)

        # Make Tag
        key = pmt.intern("test")
        value = pmt.intern("test1")
        self.add_item_tag(0, self.nitems_written(0)+0, key, value)


        std::vector<gr::tag_t> tags;
        get_tags_in_range(tags, 0, nitems_read(0), nitems_read(0) + noutput_items, d_reset_tag_key);
        for (unsigned t = 0; t < tags.size(); t++) {
            int offset = tags[t].offset - nitems_read(0);
            tags[t].offset = offset + nitems_written(0);
            add_item_tag(0, tags[t]);      
        }     
```

<div id="last_n_samples"/>  

## Use the Last N Samples

How does the history work?

The history is the number of items a block needs to calculate 1 output item. For a filter, this is equal to the number of taps.
For a simple differentiator (y(n) = x(n) - x(n-1)), the history equals 2. Obviously, the smallest value for the history is 1.

When you are in the work function, the number of items in your input buffer equals the number of input items plus the history minus one.
Here is an example for an accumulator that outputs the sum of the last N items:

```python
for (int i = 0; i < noutput_items; i++) {
    out[i] = 0;
    for (int k = 0; k < history(); k++) {
        out[i] += in[i+k];
    }
}
```

As you can see, noutput_items items of out[] are written, whereas noutput_items + history() - 1 items of in[] are read from.

If the history has the value N, the first N-1 items are "old" items, i.e. they were available in the previous call to work() (when work() is called the first time, they are set to zero). 

<div id="message_passing"/>  

## Message Passing
Must register input, output ports when using "message" as a block output type:
```
self.message_port_register_in(pmt.intern("in_port_name"))
self.message_port_register_out(pmt.intern("out_port_name"))
self.set_msg_handler(pmt.intern("port name"), <msg handler function>)
self.set_msg_handler(pmt.intern("port name"), self.handle_msg)  # No () and no input parameters

def handle_msg(self, msg):
    snr = pmt.to_float(msg)
```

```
const pmt::pmt_t d_port;           // in .h private:
d_port(pmt::mp("header_data"))     // in impl before {}
message_port_register_out(d_port); // in impl in the {}

message_port_pub(d_port, pmt::PMT_F);
pmt::pmt_t dict(pmt::make_dict());
for (unsigned i = 0; i < tags.size(); i++) {
    dict = pmt::dict_add(dict, tags[i].key, tags[i].value);
}
message_port_pub(d_port, dict);
message_port_pub(d_snr_port, pmt::from_float(snr_avg));


message_port_register_in(pmt::mp("print"));
set_msg_handler(pmt::mp("print"),
    boost::bind(&message_debug_impl::print, this, _1));

 void message_debug_impl::print(pmt::pmt_t msg)
 {
   std::cout << "***** MESSAGE DEBUG PRINT ********\n";
   pmt::print(msg);
   std::cout << "**********************************\n";
 }
```

https://wiki.gnuradio.org/index.php/Message_Passing

<div id="pdus"/>  

## PDUs

```
import pmt

msg = pmt.to_python(pmt.cdr(msg))  # [ 67 104  97 110 103 101 70 114 101 113 117 101 110  99 121  82 101 113 117 101 115 116]
msg = "".join([chr(item) for item in msg]) # convert to string
```

```
import zmq
import numpy, pmt

class ZMQ_pub(object):
    def __init__(self, portOut):
        self._ipAddress = '127.0.0.1'
        self._portOut = portOut

        self._zmqContext = zmq.Context()
        self._socketOut = self._zmqContext.socket(zmq.PUB)
        self._socketOut.bind('tcp://%s:%s' % (self._ipAddress, self._portOut))


    def send(self, data):
        car = pmt.make_dict()
        data = bytes(data)
        data = numpy.frombuffer(data, dtype=numpy.uint8)
        cdr = pmt.to_pmt(data)
        pdu = pmt.cons(car, cdr)
        self._socketOut.send(pmt.serialize_str(pdu))
```

```
import zmq
from zmq import Again as ZMQ_sub_timeout
import numpy, pmt
import binascii

class ZMQ_sub(object):
    def __init__(self, portIn, timeout = 100):
        self._ipAddress = '127.0.0.1'
        self._portIn = portIn

        self._zmqContext = zmq.Context()
        self._socketIn = self._zmqContext.socket(zmq.SUB)
        self._socketIn.RCVTIMEO = timeout
        self._socketIn.connect('tcp://%s:%s' % (self._ipAddress,self._portIn))
        try:
            self._socketIn.setsockopt(zmq.SUBSCRIBE, '') # python2
        except TypeError:
            self._socketIn.setsockopt_string(zmq.SUBSCRIBE, '') # python3, if this throws an exception... give up...

    def recv(self):
        msg = self._socketIn.recv()
        pdu = pmt.deserialize_str(msg)
        cdr = pmt.to_python(pmt.cdr(pdu))
        cdr = numpy.getbuffer(cdr)
        return cdr
```

<div id="existing_gnu_radio_types"/>  

## Reusing Existing GNU Radio Types

Edit CMakeLists.txt:

```
########################################################################
# Find gnuradio build dependencies
########################################################################
find_package(CppUnit)
find_package(Doxygen)

# Search for GNU Radio and its components and versions. Add any
# components required to the list of GR_REQUIRED_COMPONENTS (in all
# caps such as FILTER or FFT) and change the version to the minimum
# API compatible version required.
#set(GR_REQUIRED_COMPONENTS RUNTIME)
set(GR_REQUIRED_COMPONENTS RUNTIME DIGITAL ANALOG FILTER FFT BLOCKS PMT)
```

Edit swig.i:

```
/* -*- c++ -*- */

#define ADJULINK1_API
#define DIGITAL_API
#define FFT_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "AdjuLink1_swig_doc.i"

%{
#include "AdjuLink1/additive_scrambler1.h"
#include "AdjuLink1/ofdm_carrier_allocator1.h"
#include "AdjuLink1/ofdm_cyclic_prefixer1.h"
#include "AdjuLink1/ofdm_channel_est1.h"
#include "AdjuLink1/ofdm_frame_equalizer1.h"
#include "AdjuLink1/protocol_formatter1.h"
#include "AdjuLink1/ofdm_serializer1.h"
#include "AdjuLink1/constellation_decoder1.h"
%}
//%include "gnuradio/digital/ofdm_equalizer_simpledfe.h"
%include "gnuradio/digital/ofdm_equalizer_base.h"
%include "gnuradio/digital/header_format_base.h"
%include "gnuradio/digital/constellation.h"
```

Use `gr::package::type` when referencing:

```
gr::digital::constellation_sptr constellation
```
