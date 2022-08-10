#!/usr/bin/env python
#
#Copyright 2015 Pavel Yazev <pyazev@gmail.com>
# 
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
# 
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this software; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
#
# Ubuntu 16.04

import sys
import pmt
from gnuradio import gr


# Detect Operating System
import subprocess
process = subprocess.Popen('lsb_release -d', shell=True, stdout=subprocess.PIPE)
stdout = process.communicate()[0]
        
# Select Radio Button
if "Ubuntu 16.04" in stdout:

    try:
        from PyQt4 import QtCore, QtGui

    except ImportError:
        sys.stderr.write("Error: Program requires PyQt4 and gr-qtgui.\n")
        sys.exit(1)


    class console(gr.basic_block, QtGui.QTextEdit):
        def __init__(self):
            gr.basic_block.__init__(self, name="console", in_sig=[], out_sig=[])
            QtGui.QTextEdit.__init__(self)
            self.message_port_register_in(pmt.intern("in"))
            self.set_msg_handler(pmt.intern("in"), self.handle_msg)

            QtCore.QObject.connect(self, QtCore.SIGNAL("console_update"), self.update)

            self.font = self.document().defaultFont();
            self.font.setFamily("Courier New");
            self.font.setStyleStrategy(QtGui.QFont.NoAntialias);
            self.document().setDefaultFont(self.font);
           

        def handle_msg(self, msg):
            if(pmt.dict_has_key( msg, pmt.to_pmt("log_msg"))):        
                log_msg = pmt.dict_ref( msg, pmt.to_pmt("log_msg"), pmt.PMT_NIL)
                self.console_msg = pmt.to_python(log_msg)
                self.emit(QtCore.SIGNAL("console_update"))
            
        def update(self):    
            self.append(self.console_msg)
            self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())
            #self.moveCursor(QtGui.QTextCursor.End)

        def work(self, input_items, output_items):
            pass   


elif "Ubuntu 18.04" in stdout:
    # Ubuntu 18.04

    try:
        from PyQt5 import QtCore, QtGui, QtWidgets
        from PyQt5.QtCore import QObject, pyqtSignal

    except ImportError:
        sys.stderr.write("Error: Program requires PyQt5 and gr-qtgui.\n")
        sys.exit(1)


    class console(gr.basic_block, QtWidgets.QTextEdit):
        console_update = pyqtSignal()
        def __init__(self):              
            gr.basic_block.__init__(self, name="console", in_sig=[], out_sig=[])
            QtWidgets.QTextEdit.__init__(self)
            self.message_port_register_in(pmt.intern("in"))
            self.set_msg_handler(pmt.intern("in"), self.handle_msg)
            
            #QObject.connect(self, QtCore.SIGNAL("console_update"), self.update)

            self.console_update.connect(self.update)

            self.font = self.document().defaultFont();
            self.font.setFamily("Courier New");
            self.font.setStyleStrategy(QtGui.QFont.NoAntialias);
            self.document().setDefaultFont(self.font);
           

        def handle_msg(self, msg):
            if(pmt.dict_has_key( msg, pmt.to_pmt("log_msg"))):        
                log_msg = pmt.dict_ref( msg, pmt.to_pmt("log_msg"), pmt.PMT_NIL)
                self.console_msg = pmt.to_python(log_msg)
                self.console_update.emit()
            
        def update(self):    
            self.append(self.console_msg)
            self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())
            #self.moveCursor(QtGui.QTextCursor.End)

        def work(self, input_items, output_items):
            pass  








