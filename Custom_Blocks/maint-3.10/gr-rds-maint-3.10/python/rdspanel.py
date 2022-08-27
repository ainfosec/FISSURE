import pmt
from gnuradio import gr, blocks

from PyQt5 import Qt, QtCore, QtWidgets
from PyQt5.QtCore import pyqtSlot, pyqtSignal

class rdsPanel(gr.sync_block, QtWidgets.QWidget):

        msg_signal = pyqtSignal(int, str)

        def __init__(self, freq, *args, **kwds):
                gr.sync_block.__init__(
                        self,
                        name = "rds_panel",
                        in_sig = None,
                        out_sig = None,
                )
                self.message_port_register_in(pmt.intern('in'))
                self.set_msg_handler(pmt.intern('in'), self.handle_msg)

                QtWidgets.QWidget.__init__(self)
                self.msg_signal.connect(self.msg_slot)

                vlayout = Qt.QVBoxLayout()

                hlayout = Qt.QHBoxLayout()

                hlayout.addWidget(Qt.QLabel("Frequency"))
                self.freq = Qt.QLabel("%.1f" % (float(freq) / 1e6))
                self.freq.setStyleSheet("font-weight: bold")
                hlayout.addWidget(self.freq)
                hlayout.addWidget(Qt.QLabel("Station Name"))
                self.station= Qt.QLabel("")
                self.station.setStyleSheet("font-weight: bold")
                hlayout.addWidget(self.station)
                hlayout.addWidget(Qt.QLabel("Program Type"))
                self.program = Qt.QLabel("")
                self.program.setStyleSheet("font-weight: bold")
                hlayout.addWidget(self.program)
                hlayout.addWidget(Qt.QLabel("PI"))
                self.pi = Qt.QLabel("")
                self.pi.setStyleSheet("font-weight: bold")
                hlayout.addWidget(self.pi)

                vlayout.addLayout(hlayout)

                hlayout = Qt.QHBoxLayout()
                self.TP = Qt.QLabel("TP")
                self.TP.setStyleSheet("font-weight: bold; color: gray")
                hlayout.addWidget(self.TP)
                self.TA = Qt.QLabel("TA")
                self.TA.setStyleSheet("font-weight: bold; color: gray")
                hlayout.addWidget(self.TA)
                self.music = Qt.QLabel("music")
                self.music.setStyleSheet("font-weight: bold; color: gray")
                hlayout.addWidget(self.music)
                self.stereo = Qt.QLabel("stereo")
                self.stereo.setStyleSheet("font-weight: bold; color: gray")
                hlayout.addWidget(self.stereo)
                self.AH = Qt.QLabel("AH")
                self.AH.setStyleSheet("font-weight: bold; color: gray")
                hlayout.addWidget(self.AH)
                self.CMP = Qt.QLabel("CMP")
                self.CMP.setStyleSheet("font-weight: bold; color: gray")
                hlayout.addWidget(self.CMP)
                self.stPTY = Qt.QLabel("stPTY")
                self.stPTY.setStyleSheet("font-weight: bold; color: gray")
                hlayout.addWidget(self.stPTY)

                vlayout.addLayout(hlayout)

                hlayout = Qt.QHBoxLayout()

                hlayout.addWidget(Qt.QLabel("Clock Time"))
                self.clock_time = Qt.QLabel("")
                self.clock_time.setStyleSheet("font-weight: bold")
                hlayout.addWidget(self.clock_time)
                hlayout.addWidget(Qt.QLabel("Alt. Frequencies"))
                self.alt_freq = Qt.QLabel("")
                self.alt_freq.setStyleSheet("font-weight: bold")
                hlayout.addWidget(self.alt_freq)

                vlayout.addLayout(hlayout)

                hlayout = Qt.QHBoxLayout()

                hlayout.addWidget(Qt.QLabel("Radiotext"))
                self.radiotext = Qt.QLabel("")
                self.radiotext.setStyleSheet("font-weight: bold")
                hlayout.addWidget(self.radiotext)

                vlayout.addLayout(hlayout)

                self.setLayout(vlayout)

        def set_frequency(self, freq):
                freq_str = "%.1f" % float(freq)
                self.msg_signal.emit(7, freq_str)

        def clear_data(self):
                self.station.setText("")
                self.program.setText("")
                self.pi.setText("")
                self.TP.setStyleSheet("font-weight: bold; color: gray")
                self.TA.setStyleSheet("font-weight: bold; color: gray")
                self.music.setStyleSheet("font-weight: bold; color: gray")
                self.stereo.setStyleSheet("font-weight: bold; color: gray")
                self.AH.setStyleSheet("font-weight: bold; color: gray")
                self.CMP.setStyleSheet("font-weight: bold; color: gray")
                self.stPTY.setStyleSheet("font-weight: bold; color: gray")
                self.clock_time.setText("")
                self.alt_freq.setText("")
                self.radiotext.setText("")

        def handle_msg(self, msg):

                if(not pmt.is_tuple(msg)):
                        return

                msg_type = pmt.to_long(pmt.tuple_ref(msg, 0))
                msg = pmt.symbol_to_string(pmt.tuple_ref(msg, 1))
                msg = msg

                self.msg_signal.emit(msg_type, msg)

        @pyqtSlot(int, str)
        def msg_slot(self, msg_type, msg):

                if (msg_type==0):     #program information
                        self.program.setText(msg)
                elif (msg_type==1):   #station name
                        self.station.setText(msg)
                elif (msg_type==2):   #program type
                        self.pi.setText(msg)
                elif (msg_type==3):   #flags
                        flags=msg
                        if (flags[0]=='1'):
                                self.TP.setStyleSheet("font-weight: bold; color: red")
                        else:
                                self.TP.setStyleSheet("font-weight: bold; color: gray")
                        if (flags[1]=='1'):
                                self.TA.setStyleSheet("font-weight: bold; color: red")
                        else:
                                self.TA.setStyleSheet("font-weight: bold; color: gray")
                        if (flags[2]=='1'):
                                self.music.setText("Music")
                                self.music.setStyleSheet("font-weight: bold; color: red")
                        else:
                                self.music.setText("Speech")
                                self.music.setStyleSheet("font-weight: bold; color: red")
                        if (flags[3]=='1'):
                                self.stereo.setText("Stereo")
                                self.stereo.setStyleSheet("font-weight: bold; color: red")
                        else:
                                self.stereo.setText("Mono")
                                self.stereo.setStyleSheet("font-weight: bold; color: red")
                        if (flags[4]=='1'):
                                self.AH.setStyleSheet("font-weight: bold; color: red")
                        else:
                                self.AH.setStyleSheet("font-weight: bold; color: gray")
                        if (flags[5]=='1'):
                                self.CMP.setStyleSheet("font-weight: bold; color: red")
                        else:
                                self.CMP.setStyleSheet("font-weight: bold; color: gray")
                        if (flags[6]=='1'):
                                self.stPTY.setStyleSheet("font-weight: bold; color: red")
                        else:
                                self.stPTY.setStyleSheet("font-weight: bold; color: gray")
                elif (msg_type==4):   #radiotext
                        self.radiotext.setText(msg)
                elif (msg_type==5):   #clocktime
                        self.clock_time.setText(msg)
                elif (msg_type==6):   #alternative frequencies
                        self.alt_freq.setText(msg)
                elif (msg_type==7):   #alternative frequencies
                        self.freq.setText(msg)
                        self.clear_data()
