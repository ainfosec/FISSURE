# -*- coding: UTF-8 -*-

import wx
import pmt
from gnuradio import gr, blocks

wxDATA_EVENT = wx.NewEventType()
def EVT_DATA_EVENT(win, func):
	win.Connect(-1, -1, wxDATA_EVENT, func)

class DataEvent(wx.PyEvent):
	def __init__(self, data):
		wx.PyEvent.__init__(self)
		self.SetEventType (wxDATA_EVENT)
		self.data = data

	def Clone (self):
		self.__class__ (self.GetId())

class rdsPanel(gr.sync_block):
	def __init__(self, freq, *args, **kwds):
		gr.sync_block.__init__(
			self,
			name = "rds_panel",
			in_sig = None,
			out_sig = None,
		)
		self.message_port_register_in(pmt.intern('in'))
		self.set_msg_handler(pmt.intern('in'), self.handle_msg)

		self.panel = rdsWxPanel(freq, *args, **kwds);

	def handle_msg(self, msg):
		if(pmt.is_tuple(msg)):
			t = pmt.to_long(pmt.tuple_ref(msg, 0))
			m = pmt.symbol_to_string(pmt.tuple_ref(msg, 1))
			de = DataEvent([t, m])
			wx.PostEvent(self.panel, de)
			del de

	def set_frequency(self, freq=None):
		freq_str = "xxx.xx"
		if freq is not None:
			if isinstance(freq, float) or isinstance(freq, int):
				freq_str = "%.2f" % (float(freq) / 1e6)
			else:
				freq_str = str(freq)

		de = DataEvent([7, freq_str])
		wx.PostEvent(self.panel, de)
		del de


class rdsWxPanel(wx.Panel):
	def __init__(self, freq, *args, **kwds):
		kwds["style"] = wx.TAB_TRAVERSAL
		wx.Panel.__init__(self, *args, **kwds)
		self.label_1 = wx.StaticText(self, -1, "Frequency")
		self.label_2 = wx.StaticText(self, -1, "Station Name")
		self.label_3 = wx.StaticText(self, -1, "Program Type")
		self.label_4 = wx.StaticText(self, -1, "PI")
		self.label_5 = wx.StaticText(self, -1, "Radio Text")
		self.label_6 = wx.StaticText(self, -1, "Clock Time")
		self.label_7 = wx.StaticText(self, -1, "Alt. Frequencies")
		self.frequency = wx.StaticText(self, -1, "xxx.xx")
		self.station_name = wx.StaticText(self, -1, "xxxxxxxx")
		self.program_type = wx.StaticText(self, -1, "xxxxxxxxxxx")
		self.program_information = wx.StaticText(self, -1, "xxxx")
		self.tp_flag = wx.StaticText(self, -1, "TP")
		self.ta_flag = wx.StaticText(self, -1, "TA")
		self.musicspeech_flag = wx.StaticText(self, -1, "MUS/SPE")
		self.monostereo_flag = wx.StaticText(self, -1, "MN/ST")
		self.artificialhead_flag = wx.StaticText(self, -1, "AH")
		self.compressed_flag = wx.StaticText(self, -1, "CMP")
		self.staticpty_flag = wx.StaticText(self, -1, "stPTY")
		self.radiotext = wx.StaticText(self, -1, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
		self.clocktime = wx.StaticText(self, -1, "xxxxxxxxxxxxxxxxxxxxx")
		self.alt_freq = wx.StaticText(self, -1, "xxxxxxxxxxxxxxx")

		self.__set_properties()
		self.__do_layout()
		if isinstance(freq, float) or isinstance(freq, int):
			freq_str = "%.2f" % (float(freq) / 1e6)
		else:
			freq_str = str(freq)
		self.frequency.SetLabel(freq_str)
		EVT_DATA_EVENT (self, self.display_data)

	def __set_properties(self):
		font_bold = wx.Font(16, wx.DEFAULT, wx.NORMAL, wx.BOLD, 0, "")
		font_normal = wx.Font(16, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "")
		font_small = wx.Font(10, wx.DEFAULT, wx.NORMAL, wx.BOLD, 0, "")

		self.frequency.SetFont(font_bold)
		self.station_name.SetFont(font_bold)
		self.program_type.SetFont(font_bold)
		self.program_information.SetFont(font_bold)
		self.tp_flag.SetFont(font_normal)
		self.ta_flag.SetFont(font_normal)
		self.musicspeech_flag.SetFont(font_normal)
		self.monostereo_flag.SetFont(font_normal)
		self.artificialhead_flag.SetFont(font_normal)
		self.compressed_flag.SetFont(font_normal)
		self.staticpty_flag.SetFont(font_normal)
		self.radiotext.SetFont(font_small)
		self.clocktime.SetFont(font_small)
		self.alt_freq.SetFont(font_small)

	def __do_layout(self):
		sizer_0 = wx.BoxSizer(wx.VERTICAL)
		sizer_1 = wx.BoxSizer(wx.HORIZONTAL)
		sizer_2 = wx.BoxSizer(wx.HORIZONTAL)
		sizer_3 = wx.BoxSizer(wx.HORIZONTAL)
		sizer_4 = wx.BoxSizer(wx.HORIZONTAL)

		flag = wx.ALIGN_CENTER_VERTICAL|wx.LEFT

		# arguments: window, proportion, flag, border
		sizer_1.Add(self.label_1, 0, flag)
		sizer_1.Add(self.frequency, 0, flag, 20)
		sizer_1.Add(self.label_2, 0, flag, 20)
		sizer_1.Add(self.station_name, 0, flag, 20)
		sizer_1.Add(self.label_3, 0, flag, 20)
		sizer_1.Add(self.program_type, 0, flag, 20)
		sizer_1.Add(self.label_4, 0, flag, 20)
		sizer_1.Add(self.program_information, 0, flag, 20)
		sizer_0.Add(sizer_1, 1, wx.ALIGN_CENTER)

		sizer_2.Add(self.tp_flag, 0, flag)
		sizer_2.Add(self.ta_flag, 0, flag, 30)
		sizer_2.Add(self.musicspeech_flag, 0, flag, 30)
		sizer_2.Add(self.monostereo_flag, 0, flag, 30)
		sizer_2.Add(self.artificialhead_flag, 0, flag, 30)
		sizer_2.Add(self.compressed_flag, 0, flag, 30)
		sizer_2.Add(self.staticpty_flag, 0, flag, 30)
		sizer_0.Add(sizer_2, 1, wx.ALIGN_CENTER)

		sizer_3.Add(self.label_6, 0, flag, 10)
		self.clocktime.SetSizeHints(250, -1)
		sizer_3.Add(self.clocktime, 0, flag, 10)
		sizer_3.Add(self.label_7, 0, flag, 10)
		self.alt_freq.SetSizeHints(200, -1)
		sizer_3.Add(self.alt_freq, 0, flag, 10)
		sizer_0.Add(sizer_3, 0, wx.ALIGN_CENTER)

		sizer_4.Add(self.label_5, 0, flag)
		sizer_4.Add(self.radiotext, 0, flag, 10)
		sizer_0.Add(sizer_4, 0, wx.ALIGN_CENTER)

		self.SetSizer(sizer_0)

	def display_data(self, event):
		msg_type = event.data[0]
		msg = unicode(event.data[1], errors='replace')
		if (msg_type==0):     #program information
			self.program_information.SetLabel(msg)
		elif (msg_type==1):   #station name
			self.station_name.SetLabel(msg)
		elif (msg_type==2):   #program type
			self.program_type.SetLabel(msg)
		elif (msg_type==3):   #flags
			flags=msg
			if (flags[0]=='1'):
				self.tp_flag.SetForegroundColour(wx.RED)
			else:
				self.tp_flag.SetForegroundColour(wx.LIGHT_GREY)
			if (flags[1]=='1'):
				self.ta_flag.SetForegroundColour(wx.RED)
			else:
				self.ta_flag.SetForegroundColour(wx.LIGHT_GREY)
			if (flags[2]=='1'):
				self.musicspeech_flag.SetLabel("Music")
				self.musicspeech_flag.SetForegroundColour(wx.RED)
			else:
				self.musicspeech_flag.SetLabel("Speech")
				self.musicspeech_flag.SetForegroundColour(wx.RED)
			if (flags[3]=='1'):
				self.monostereo_flag.SetLabel("Mono")
				self.monostereo_flag.SetForegroundColour(wx.RED)
			else:
				self.monostereo_flag.SetLabel("Stereo")
				self.monostereo_flag.SetForegroundColour(wx.RED)
			if (flags[4]=='1'):
				self.artificialhead_flag.SetForegroundColour(wx.RED)
			else:
				self.artificialhead_flag.SetForegroundColour(wx.LIGHT_GREY)
			if (flags[5]=='1'):
				self.compressed_flag.SetForegroundColour(wx.RED)
			else:
				self.compressed_flag.SetForegroundColour(wx.LIGHT_GREY)
			if (flags[6]=='1'):
				self.staticpty_flag.SetForegroundColour(wx.RED)
			else:
				self.staticpty_flag.SetForegroundColour(wx.LIGHT_GREY)
		elif (msg_type==4):   #radiotext
			self.radiotext.SetLabel(msg)
		elif (msg_type==5):   #clocktime
			self.clocktime.SetLabel(msg)
		elif (msg_type==6):   #alternative frequencies
			self.alt_freq.SetLabel(msg)
		elif (msg_type==7):   #update freq label
			self.frequency.SetLabel(msg)
			self.clear_data()

		self.Layout()

	def clear_data(self):
		self.program_information.SetLabel("xxxx")
		self.station_name.SetLabel("xxxxxxxx")
		self.program_type.SetLabel("xxxxxxxxxxx")
		self.ta_flag.SetForegroundColour(wx.BLACK)
		self.tp_flag.SetForegroundColour(wx.BLACK)
		self.musicspeech_flag.SetLabel("MUS/SPE")
		self.musicspeech_flag.SetForegroundColour(wx.BLACK)
		self.monostereo_flag.SetLabel("MN/ST")
		self.monostereo_flag.SetForegroundColour(wx.BLACK)
		self.artificialhead_flag.SetForegroundColour(wx.BLACK)
		self.compressed_flag.SetForegroundColour(wx.BLACK)
		self.staticpty_flag.SetForegroundColour(wx.BLACK)
		self.radiotext.SetLabel("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
		self.clocktime.SetLabel("xxxxxxxxxxxx")
		self.alt_freq.SetLabel("xxxxxxxxxxxxxxxxx")

