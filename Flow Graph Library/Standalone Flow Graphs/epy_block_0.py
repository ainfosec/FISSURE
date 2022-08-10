"""
Morse code vector source
"""

#  epy_block_0.py
#  revised 09/10/2019 - finish code table
#  revised 09/11/2019 - test for bad character
#  revised 09/27/2019 - get input from a Message Edit block (code from Volker Schroer dl1ksv)

import numpy as np
from gnuradio import gr

import pmt

textboxValue = ""

Morse = {
  # codes from https://www.itu.int/rec/R-REC-M.1677-1-200910-I/en
    "A": "1,0,1,1,1",
    "B": "1,1,1,0,1,0,1,0,1",
    "C": "1,1,1,0,1,0,1,1,1,0,1",
    "D": "1,1,1,0,1,0,1",
    "E": "1",
    "F": "1,0,1,0,1,1,1,0,1",
    "G": "1,1,1,0,1,1,1,0,1",
    "H": "1,0,1,0,1,0,1",
    "I": "1,0,1",
    "J": "1,0,1,1,1,0,1,1,1,0,1,1,1",
    "K": "1,1,1,0,1,0,1,1,1",
    "L": "1,0,1,1,1,0,1,0,1",
    "M": "1,1,1,0,1,1,1",
    "N": "1,1,1,0,1",
    "O": "1,1,1,0,1,1,1,0,1,1,1",
    "P": "1,0,1,1,1,0,1,1,1,0,1",
    "Q": "1,1,1,0,1,1,1,0,1,0,1,1,1",
    "R": "1,0,1,1,1,0,1",
    "S": "1,0,1,0,1",
    "T": "1,1,1",
    "U": "1,0,1,0,1,1,1",
    "V": "1,0,1,0,1,0,1,1,1",
    "W": "1,0,1,1,1,0,1,1,1",
    "X": "1,1,1,0,1,0,1,0,1,1,1",
    "Y": "1,1,1,0,1,0,1,1,1,0,1,1,1",
    "Z": "1,1,1,0,1,1,1,0,1,0,1",
    " ": "0",            # space
    "1": "1,0,1,1,1,0,1,1,1,0,1,1,1,0,1,1,1",
    "2": "1,0,1,0,1,1,1,0,1,1,1,0,1,1,1",
    "3": "1,0,1,0,1,0,1,1,1,0,1,1,1",
    "4": "1,0,1,0,1,0,1,0,1,1,1",
    "5": "1,0,1,0,1,0,1,0,1",
    "6": "1,1,1,0,1,0,1,0,1,0,1",
    "7": "1,1,1,0,1,1,1,0,1,0,1,0,1",
    "8": "1,1,1,0,1,1,1,0,1,1,1,0,1,0,1",
    "9": "1,1,1,0,1,1,1,0,1,1,1,0,1,1,1,0,1",
    "0": "1,1,1,0,1,1,1,0,1,1,1,0,1,1,1,0,1,1,1",
    ".": "1,0,1,1,1,0,1,0,1,1,1,0,1,0,1,1,1",          # period
    ",": "1,1,1,0,1,1,1,0,1,0,1,0,1,1,1,0,1,1,1",      # comma
    ":": "1,1,1,0,1,1,1,0,1,1,1,0,1,0,1,0,1",          # colon
    "?": "1,0,1,0,1,1,1,0,1,1,1,0,1,0,1",              # question
    "'": "1,0,1,1,1,0,1,1,1,0,1,1,1,0,1,1,1,0,1",      # apostrophe
    "-": "1,1,1,0,1,0,1,0,1,0,1,0,1,1,1",              # dash or minus
    "/": "1,1,1,0,1,0,1,0,1,1,1,0,1",                  # slash
    "(": "1,1,1,0,1,0,1,1,1,0,1,1,1,0,1",              # left parenthesis
    ")": "1,1,1,0,1,0,1,1,1,0,1,1,1,0,1,0,1,1,1",      # right parenthesis
    "\"": "1,0,1,1,1,0,1,0,1,0,1,1,1,0,1",             # quote
    "=": "1,1,1,0,1,0,1,0,1,0,1,1,1",                  # equals
    "+": "1,0,1,1,1,0,1,0,1,1,1,0,1",                  # plus
    "@": "1,0,1,1,1,0,1,1,1,0,1,0,1,1,1,0,1",          # at sign (@)
  # these punctuation marks are not included in the ITU recommendation,
  # but are found in https://en.wikipedia.org/wiki/Morse_code
    "!": "1,1,1,0,1,0,1,1,1,0,1,0,1,1,1,0,1,1,1",      # exclamation point
    "&": "1,0,1,1,1,0,1,0,1,0,1",                      # ampersand (also prosign for 'WAIT')
    ";": "1,1,1,0,1,0,1,1,1,0,1,0,1,1,1,0,1",          # semicolon
    "_": "1,0,1,0,1,1,1,0,1,1,1,0,1,0,1,1,1",          # underscore
    "$": "1,0,1,0,1,0,1,1,1,0,1,0,1,0,1,1,1"           # dollar sign
      }

class mc_sync_block(gr.sync_block):
    """
    reads input from a message port
    generates a vector of Morse code bits
    """
    def __init__(self):
        gr.sync_block.__init__(self,
            name = "Morse code vector source",
            in_sig = None,
            out_sig = [np.byte])
        self.message_port_register_in(pmt.intern('msg_in'))
        self.message_port_register_out(pmt.intern('clear_input'))
        self.set_msg_handler(pmt.intern('msg_in'), self.handle_msg)

    def handle_msg(self, msg):
        global textboxValue
        textboxValue = pmt.symbol_to_string (msg)
        # print (textboxValue)
    
    def work(self, input_items, output_items):
        global Morse
        global textboxValue
        bit_stream = ""
        if (len (textboxValue) > 0):
            for in0 in textboxValue:
                # get next char
                inChar = str (in0)
                # convert to upper case
                ch = inChar.upper()
                # test for character in table
                if (not(ch in Morse)):
                # print ("bad char", ch)
                    ch = "?"        # replace bad character with a '?'
                # build vector
                _dots = str (Morse.get(ch))
                # print (ch, _dots)
                bit_stream += (_dots + ",0,0,0,")    # letter space

            bit_stream += "0,0,0,0"    # finish with word space
            # print (bit_stream)

            # get length of string
            _len = len(bit_stream)
            # num of elements = (length+1) / 2
            _num_elem = int((_len+1) / 2)

            # convert and store elements in output array
            for x in range (_len):
                y = int(x / 2)
                if (bit_stream[x] == '1'):
                    output_items[0][y] = 1
                elif (bit_stream[x] == '0'):
                    output_items[0][y] = 0
                else:
                    continue    # skip commas

            # clear input line
            textboxValue = ""
            self.message_port_pub(pmt.intern('clear_input'), pmt.intern(''))
        else:
            _num_elem = 0

        return (_num_elem)
