# Copyright 2013 Nick Foster
# 
# This file is part of gr-ais
# 
# gr-ais is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
# 
# gr-ais is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with gr-ais; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
#

# Radio interface for AIS receiver
# Handles all hardware- and source-related functionality
# You pass it options, it gives you data.
# It uses the pubsub interface to allow clients to subscribe to its data feeds.

from gnuradio import gr, gru, eng_notation, filter, blocks, digital
from gnuradio.filter import optfir
from gnuradio.eng_option import eng_option
from gnuradio.gr.pubsub import pubsub
from optparse import OptionParser, OptionGroup
import threading
import time
import sys
import re
import ais

#hier block encapsulating all the signal processing after the source
#could probably be split into its own file
class ais_rx(gr.hier_block2):
    def __init__(self, freq, rate, designator, queue, use_viterbi=False):
        gr.hier_block2.__init__(self,
                                "ais_rx",
                                gr.io_signature(1,1,gr.sizeof_gr_complex),
                                gr.io_signature(0,0,0))

        self.coeffs = filter.firdes.low_pass(1, rate, 7000, 1000)
        self._filter_decimation = 12 #fixed, TODO make settable via params or better yet do resampling
        self.filter = filter.freq_xlating_fir_filter_ccf(self._filter_decimation,
                                                     self.coeffs,
                                                     freq,
                                                     rate)

        self._bits_per_sec = 9600.0
        self._samples_per_symbol = rate / self._filter_decimation / self._bits_per_sec
        options = {}
        options[ "viterbi" ] = use_viterbi
        options[ "samples_per_symbol" ] = self._samples_per_symbol
        options[ "gain_mu" ] = 0.3
        options[ "mu" ] = 0.5
        options[ "omega_relative_limit" ] = 0.003
        options[ "bits_per_sec" ] = self._bits_per_sec
        options[ "fftlen" ] = 4096 #trades off accuracy of freq estimation in presence of noise, vs. delay time.
        options[ "samp_rate" ] = rate / self._filter_decimation
        self.demod = ais.ais_demod(options) #ais_demod takes in complex baseband and spits out 1-bit packed bitstream
        self.unstuff = ais.unstuff() #undoes bit stuffing operation
        self.start_correlator = digital.correlate_access_code_tag_bb("1010101010101010", 0, "ais_preamble") #should mark start of packet
        self.stop_correlator = digital.correlate_access_code_tag_bb("01111110", 0, "ais_frame") #should mark start and end of packet
        self.parse = ais.parse(queue, designator) #ais_parse.cc, calculates CRC, parses data into NMEA AIVDM message, moves data onto queue

        self.connect(self,
                     self.filter,
                     self.demod,
                     self.unstuff,
                     self.start_correlator,
                     self.stop_correlator,
                     self.parse) #parse posts messages to the queue, which the main loop reads and prints

class ais_radio (gr.top_block, pubsub):
  def __init__(self, options):
    gr.top_block.__init__(self)
    pubsub.__init__(self)
    self._options = options
    self._queue = gr.msg_queue()

    self._u = self._setup_source(options)
    self._rate = self.get_rate()
    print "Rate is %i" % (self._rate,)

    self._rx_path1 = ais_rx(161.975e6 - 162.0e6, options.rate, "A", self._queue, options.viterbi)
    self._rx_path2 = ais_rx(162.025e6 - 162.0e6, options.rate, "B", self._queue, options.viterbi)
    self.connect(self._u, self._rx_path1)
    self.connect(self._u, self._rx_path2)

    #now subscribe to set various options via pubsub
    self.subscribe("gain", self.set_gain)
    self.subscribe("rate", self.set_rate)

    self.publish("gain", self.get_gain)
    self.publish("rate", self.get_rate)

    self._async_sender = gru.msgq_runner(self._queue, self.send)

  def send(self, msg):
    print msg.to_string()
    sys.stdout.flush()

  @staticmethod
  def add_radio_options(parser):
    group = OptionGroup(parser, "Receiver setup options")

    #Choose source
    group.add_option("-s","--source", type="string", default="uhd",
                      help="Choose source: uhd, osmocom, <filename>, or <ip:port> [default=%default]")

    #UHD/Osmocom args
    group.add_option("-R", "--subdev", type="string",
                      help="select USRP Rx side A or B", metavar="SUBDEV")
    group.add_option("-A", "--antenna", type="string",
                      help="select which antenna to use on daughterboard")
    group.add_option("-D", "--args", type="string",
                      help="arguments to pass to radio constructor", default="")
    group.add_option("-g", "--gain", type="int", default=None,
                      help="set RF gain", metavar="dB")
    parser.add_option("-e", "--error", type="eng_float", default=0,
                        help="set offset error of device in PPM [default=%default]")
    #RX path args
    group.add_option("-r", "--rate", type="eng_float", default=250e3,
                      help="set sample rate [default=%default]")

    group.add_option("-v", "--viterbi", action="store_true", default=False,
                     help="Use experimental Viterbi-based GMSK demodulator [default=%default]")

    parser.add_option_group(group)

  def live_source(self):
    return self._options.source=="uhd" or self._options.source=="osmocom"

  def set_gain(self, gain):
    if self.live_source():
        self._u.set_gain(gain)
        print "Gain is %f" % self.get_gain()
    return self.get_gain()

  def set_rate(self, rate):
    self._rx_path1.set_rate(rate)
    self._rx_path2.set_rate(rate)
    return self._u.set_rate(rate) if self.live_source() else self._rate

  def set_threshold(self, threshold):
    self._rx_path.set_threshold(threshold)

  def get_gain(self):
    return self._u.get_gain() if self.live_source() else 0

  def get_rate(self):
    return self._u.get_samp_rate() if self.live_source() else self._rate

  def _setup_source(self, options):
    if options.source == "uhd":
      #UHD source by default
      from gnuradio import uhd
      src = uhd.single_usrp_source(options.args, uhd.io_type_t.COMPLEX_FLOAT32, 1)

      if(options.subdev):
        src.set_subdev_spec(options.subdev, 0)

      if not src.set_center_freq(162.0e6 * (1 + options.error/1.e6)):
        print "Failed to set initial frequency"
      else:
        print "Tuned to %.3fMHz" % (src.get_center_freq() / 1.e6)

      #check for GPSDO
      #if you have a GPSDO, UHD will automatically set the timestamp to UTC time
      #as well as automatically set the clock to lock to GPSDO.
      if src.get_time_source(0) != 'gpsdo':
        src.set_time_now(uhd.time_spec(0.0))

      if options.antenna is not None:
        src.set_antenna(options.antenna)

      src.set_samp_rate(options.rate)

      if options.gain is None: #set to halfway
        g = src.get_gain_range()
        options.gain = (g.start()+g.stop()) / 2.0

      print "Setting gain to %i" % options.gain
      src.set_gain(options.gain)
      print "Gain is %i" % src.get_gain()

    #TODO: detect if you're using an RTLSDR or Jawbreaker
    #and set up accordingly.
    elif options.source == "osmocom": #RTLSDR dongle or HackRF Jawbreaker
        import osmosdr
        src = osmosdr.source(options.args)
        src.set_sample_rate(options.rate)
        src.get_samp_rate = src.get_sample_rate #alias for UHD compatibility
        if not src.set_center_freq(162.0e6 * (1 + options.error/1.e6)):
            print "Failed to set initial frequency"
        else:
            print "Tuned to %.3fMHz" % (src.get_center_freq() / 1.e6)

        if options.gain is None:
            options.gain = 34
        src.set_gain(options.gain)
        print "Gain is %i" % src.get_gain()

    else:
      #semantically detect whether it's ip.ip.ip.ip:port or filename
      self._rate = options.rate
      if ':' in options.source:
        try:
          ip, port = re.search("(.*)\:(\d{1,5})", options.source).groups()
        except:
          raise Exception("Please input UDP source e.g. 192.168.10.1:12345")
        src = blocks.udp_source(gr.sizeof_gr_complex, ip, int(port))
        print "Using UDP source %s:%s" % (ip, port)
      else:
        src = blocks.file_source(gr.sizeof_gr_complex, options.source)
        print "Using file source %s" % options.source

    return src

  def close(self):
    src = None
