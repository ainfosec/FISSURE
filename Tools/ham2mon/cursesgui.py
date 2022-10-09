#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on Sun Jul  5 17:16:22 2015

@author: madengr
"""
import locale
locale.setlocale(locale.LC_ALL, '')
import curses
import time
import numpy as np


class SpectrumWindow(object):
    """Curses spectrum display window

    Args:
        screen (object): a curses screen object

    Attributes:
        max_db (float): Top of window in dB
        min_db (float): Bottom of window in dB
        threshold_db (float): Threshold horizontal line
    """
    def __init__(self, screen):
        self.screen = screen

        # Set default values
        self.max_db = 50.0
        self.min_db = -20.0
        self.threshold_db = 20.0

        # Create a window object in top half of the screen, within the border
        screen_dims = screen.getmaxyx()
        height = int(screen_dims[0]/2.0)
        width = screen_dims[1]-2
        self.win = curses.newwin(height, width, 1, 1)
        self.dims = self.win.getmaxyx()

        # Right end of window resreved for string of N charachters
        self.chars = 7

    def draw_spectrum(self, data):
        """Scales input spectral data to window dimensions and draws bar graph

        Args:
            data (numpy.ndarray): FFT power spectrum data in linear, not dB

        Test cases for data with min_db=-100 and max_db=0 on 80x24 terminal:
            1.0E-10 draws nothing since it is not above -100 dB
            1.1E-10 draws one row
            1.0E-05 draws 5 rows
            1.0E+00 draws 10 rows
            1.0E+01 draws 10 rows
        """
        # Keep min_db to 10 dB below max_db
        if self.min_db > (self.max_db - 10):
            self.min_db = self.max_db - 10

        # Split the data into N window bins
        # N is window width between border (i.e. self.dims[1]-2 )
        # Data must be at least as long as the window width or crash
        # Use the maximum value from each input data bin for the window bin
        win_bins = np.array_split(data, self.dims[1]-self.chars)
        win_bin_max = []
        for win_bin in win_bins:
            win_bin_max.append(np.max(win_bin))

        # Convert to dB
        win_bin_max_db = 10*np.log10(win_bin_max)

        # The plot windows starts from max_db at the top
        # and draws DOWNWARD to min_db (remember this is a curses window).
        # Thus linear scaling goes from min_y=1 at the top
        # and draws DOWNWARD to max_y=dims[0]-1 at the bottom
        # The "1" and "-1" is to account for the border at top and bottom
        min_y = 1
        max_y = self.dims[0]-1

        # Scaling factor for plot
        scale = (min_y-max_y)/(self.max_db-self.min_db)

        # Generate y position, clip to window, and convert to int
        pos_y = (win_bin_max_db - self.max_db) * scale
        pos_y = np.clip(pos_y, min_y, max_y)
        pos_y = pos_y.astype(int)

         # Clear previous contents, draw border, and title
        self.win.clear()
        self.win.border(0)
        self.win.addnstr(0, int(self.dims[1]/2-4), "SPECTRUM", 8,
                         curses.color_pair(4))

        # Draw the bars
        for pos_x in range(len(pos_y)):
            # Invert the y fill since we want bars
            # Offset x (column) by 1 so it does not start on the border
            self.win.vline(pos_y[pos_x], pos_x+1, "*", max_y-pos_y[pos_x])

        # Draw the max_db and min_db strings
        string = ">" + "%+03d" % self.max_db
        self.win.addnstr(0, 1 + self.dims[1] - self.chars, string, self.chars,
                         curses.color_pair(1))
        string = ">" + "%+03d" % self.min_db
        self.win.addnstr(max_y, 1 + self.dims[1] - self.chars, string,
                         self.chars, curses.color_pair(3))

        # Generate threshold line, clip to window, and convert to int
        pos_yt = (self.threshold_db - self.max_db) * scale
        pos_yt = np.clip(pos_yt, min_y, max_y-1)
        pos_yt = pos_yt.astype(int)

        # Draw the theshold line
        # x=1 start to account for left border
        self.win.hline(pos_yt, 1, "-", len(pos_y))

        # Draw the theshold string
        string = ">" + "%+03d" % self.threshold_db
        self.win.addnstr(pos_yt, (1 + self.dims[1] - self.chars), string,
                         self.chars, curses.color_pair(2))

       # Hide cursor
        self.win.leaveok(1)

        # Update virtual window
        self.win.noutrefresh()

    def proc_keyb(self, keyb):
        """Process keystrokes

        Args:
            keyb (int): keystroke in ASCII

        Returns:
            bool: True if receiver needs tuning, False if not

        """
        if  keyb == ord('t'):
            self.threshold_db += 5
            return True
        elif keyb == ord('r'):
            self.threshold_db -= 5
            return True
        elif keyb == ord('T'):
            self.threshold_db += 1
            return True
        elif keyb == ord('R'):
            self.threshold_db -= 1
            return True
        elif keyb == ord('p'):
            self.max_db += 10
        elif keyb == ord('o'):
            self.max_db -= 10
        elif keyb == ord('w'):
            self.min_db += 10
        elif keyb == ord('q'):
            self.min_db -= 10
        else:
            pass
        return False


class ChannelWindow(object):
    """Curses channel display window

    Args:
        screen (object): a curses screen object
    """
    # pylint: disable=too-few-public-methods

    def __init__(self, screen):
        self.screen = screen

        # Create a window object in the bottom half of the screen
        # Make it about 1/3 the screen width
        # Place on left side and to the right of the border
        screen_dims = screen.getmaxyx()
        height = int(screen_dims[0]/2.0)-2
        width = int(screen_dims[1]/3.0)-1
        self.win = curses.newwin(height, width, height + 3, 1)
        self.dims = self.win.getmaxyx()

    def draw_channels(self, gui_tuned_channels):
        """Draws tuned channels list

        Args:
            rf_channels [string]: List of strings in MHz
        """

        # Clear previous contents, draw border, and title
        self.win.clear()
        self.win.border(0)
        self.win.addnstr(0, int(self.dims[1]/2-4), "CHANNELS", 8,
                         curses.color_pair(4))

        # Limit the displayed channels to no more than two rows
        max_length = 2*(self.dims[0]-2)
        if len(gui_tuned_channels) > max_length:
            gui_tuned_channels = gui_tuned_channels[:max_length]
        else:
            pass

        # Draw the tuned channels prefixed by index in list (demodulator index)
        for idx, gui_tuned_channel in enumerate(gui_tuned_channels):
            text = str(idx) + ": " + gui_tuned_channel
            if idx < self.dims[0]-2:
                # Display in first column
                self.win.addnstr(idx+1, 1, text, 11)
            else:
                # Display in second column
                self.win.addnstr(idx-self.dims[0]+3, 13, text, 11)

        # Hide cursor
        self.win.leaveok(1)

        # Update virtual window
        self.win.noutrefresh()


class LockoutWindow(object):
    """Curses lockout channel display window

    Args:
        screen (object): a curses screen object
    """
    # pylint: disable=too-few-public-methods

    def __init__(self, screen):
        self.screen = screen

        # Create a window object in the bottom half of the screen
        # Make it about 1/4 the screen width
        # Place on left side and to the right of the border
        screen_dims = screen.getmaxyx()
        height = int(screen_dims[0]/2.0)-2
        width = int(screen_dims[1]/4.0)-5
        self.win = curses.newwin(height, width, height + 3, 26)
        self.dims = self.win.getmaxyx()

    def draw_channels(self, gui_lockout_channels):
        """Draws tuned channels list

        Args:
            rf_channels [string]: List of strings in MHz
        """
        # Clear previous contents, draw border, and title
        self.win.clear()
        self.win.border(0)
        self.win.addnstr(0, int(self.dims[1]/2-3), "LOCKOUT", 7,
                         curses.color_pair(4))

        # Draw the lockout channels
        for idx, gui_lockout_channel in enumerate(gui_lockout_channels):
            # Don't draw past height of window
            if idx <= self.dims[0]-3:
                text = "   " + gui_lockout_channel
                self.win.addnstr(idx+1, 1, text, 11)
            else:
                pass

        # Hide cursor
        self.win.leaveok(1)

        # Update virtual window
        self.win.noutrefresh()

    def proc_keyb_set_lockout(self, keyb):
        """Process keystrokes to lock out channels 0 - 9

        Args:
            keyb (int): keystroke in ASCII

        Returns:
            bool: True if scanner needs adjusting, False if not
        """
        # pylint: disable=no-self-use

        # Check if keys 0 - 9 pressed
        if keyb - 48 in range(10):
            return True
        else:
            return False

    def proc_keyb_clear_lockout(self, keyb):
        """Process keystrokes to clear lockout with "l"

        Args:
            keyb (int): keystroke in ASCII

        Returns:
            bool: True if scanner needs adjusting, False if not
        """
        # pylint: disable=no-self-use

        # Check if 'l' is pressed
        if keyb == ord('l'):
            return True
        else:
            return False


class RxWindow(object):
    """Curses receiver paramater window

    Args:
    screen (object): a curses screen object

    Attributes:
        center_freq (float): Hardware RF center frequency in Hz
        samp_rate (float): Hardware sample rate in sps (1E6 min)
        gain_db (int): Hardware RF gain in dB
        if_gain_db (int): Hardware IF gain in dB
        bb_gain_db (int): Hardware BB gain in dB
        squelch_db (int): Squelch in dB
        volume_dB (int): Volume in dB
        record (bool): Record audio to file if True
        lockout_file_name (string): Name of file with channels to lockout
        priority_file_name (string): Name of file with channels for priority
    """
    # pylint: disable=too-many-instance-attributes

    def __init__(self, screen):
        self.screen = screen

        # Set default values
        self.center_freq = 146E6
        self.samp_rate = 2E6
        self.freq_entry = 'None'
        self.gain_db = 0
        self.if_gain_db = 16
        self.bb_gain_db = 16
        self.squelch_db = -60
        self.volume_db = 0
        self.type_demod = 0
        self.record = True
        self.lockout_file_name = ""
        self.priority_file_name = ""

        # Create a window object in the bottom half of the screen
        # Make it about 1/3 the screen width
        # Place on right side and to the left of the border
        screen_dims = screen.getmaxyx()
        height = int(screen_dims[0]/2.0)-2
        width = int(screen_dims[1]/2.0)-2
        self.win = curses.newwin(height, width, height + 3,
                                 int(screen_dims[1]-width-1))
        self.dims = self.win.getmaxyx()

    def draw_rx(self):
        """Draws receiver paramaters
        """

        # Clear previous contents, draw border, and title
        self.win.clear()
        self.win.border(0)
        self.win.addnstr(0, int(self.dims[1]/2-4), "RECEIVER", 8,
                         curses.color_pair(4))

        # Draw the receiver info prefix fields
        text = "RF Freq (MHz) : "
        self.win.addnstr(1, 1, text, 15)
        text = "RF Gain (dB)  : "
        self.win.addnstr(2, 1, text, 15)
        text = "IF Gain (dB)  : "
        self.win.addnstr(3, 1, text, 15)
        text = "BB Gain (dB)  : "
        self.win.addnstr(4, 1, text, 15)   
        text = "BB Rate (Msps): "
        self.win.addnstr(5, 1, text, 15)
        text = "BB Sql  (dB)  : "
        self.win.addnstr(6, 1, text, 15)
        text = "AF Vol  (dB)  : "
        self.win.addnstr(7, 1, text, 15)
        text = "Record        : "
        self.win.addnstr(8, 1, text, 15)
        text = "Demod Type    : "
        self.win.addnstr(9, 1, text, 15)
        # text = "Files         : "
        # self.win.addnstr(10, 1, text, 15)

        # Draw the receiver info suffix fields
        if self.freq_entry != 'None':
            text = self.freq_entry
        else:
            text = '{:.3f}'.format((self.center_freq)/1E6)
        self.win.addnstr(1, 17, text, 8, curses.color_pair(5))
        text = str(self.gain_db)
        self.win.addnstr(2, 17, text, 8, curses.color_pair(5))
        text = str(self.if_gain_db)
        self.win.addnstr(3, 17, text, 8, curses.color_pair(5))
        text = str(self.bb_gain_db)
        self.win.addnstr(4, 17, text, 8, curses.color_pair(5))
        text = str(self.samp_rate/1E6)
        self.win.addnstr(5, 17, text, 8)
        text = str(self.squelch_db)
        self.win.addnstr(6, 17, text, 8, curses.color_pair(5))
        text = str(self.volume_db)
        self.win.addnstr(7, 17, text, 8, curses.color_pair(5))
        text = str(self.record)
        self.win.addnstr(8, 17, text, 8)
        text = str(self.type_demod)
        self.win.addnstr(9, 17, text, 8)
        # text = str(self.lockout_file_name) + " " + str(self.priority_file_name)
        # self.win.addnstr(10, 17, text, 20)

        # Hide cursor
        self.win.leaveok(1)

        # Update virtual window
        self.win.noutrefresh()

    def proc_keyb_hard(self, keyb):
        """Process keystrokes to adjust hard receiver settings

        Tune center_freq in 100 MHz steps with 'x' and 'c'
        Tune center_freq in 10 MHz steps with 'v' and 'c'
        Tune center_freq in 1 MHz steps with 'm' and 'n'
        Tune center_freq in 100 kHz steps with 'k' and 'j'

        Args:
            keyb (int): keystroke in ASCII

        Returns:
            bool: True if receiver needs adjusting, False if not
        """
        # pylint: disable=too-many-return-statements
        # pylint: disable=too-many-branches

        # Tune self.center_freq in 100 MHz steps with 'x' and 'c'
        if keyb == ord('x'):
            self.center_freq += 1E8
            return True
        elif keyb == ord('z'):
            self.center_freq -= 1E8
            return True
        # Tune self.center_freq in 10 MHz steps with 'v' and 'c'
        elif keyb == ord('v'):
            self.center_freq += 1E7
            return True
        elif keyb == ord('c'):
            self.center_freq -= 1E7
            return True
        # Tune self.center_freq in 1 MHz steps with 'm' and 'n'
        elif  keyb == ord('m'):
            self.center_freq += 1E6
            return True
        elif keyb == ord('n'):
            self.center_freq -= 1E6
            return True
        # Tune self.center_freq in 100 kHz steps with 'k' and 'j'
        elif keyb == ord('k'):
            self.center_freq += 1E5
            return True
        elif keyb == ord('j'):
            self.center_freq -= 1E5
            return True
        elif keyb == ord('/'):
            # set mode to frequency entry
            self.freq_entry = ''
            return False
        elif keyb == 27:  # ESC
            # end frequncy entry mode without seting the frequency
            self.freq_entry = 'None'
            return False
        elif keyb == ord('\n'):
            # set the frequency from what was entered
            try:
                self.center_freq = float(self.freq_entry) * 1E6
            except:
                pass
            self.freq_entry = 'None'
            return True
        elif self.freq_entry != 'None' and (keyb - 48 in range (10) or keyb == ord('.')):
            # build up frequency from 1-9 and '.'
            self.freq_entry = self.freq_entry + chr(keyb)
            return False
        elif keyb == 127:  # BKSP
            self.freq_entry = self.freq_entry[:-1]
            return False
        else:
            return False

    def proc_keyb_soft(self, keyb):
        """Process keystrokes to adjust soft receiver settings

        Tune gain_db in 10 dB steps with 'g' and 'f'
        Tune squelch_db in 1 dB steps with 's' and 'a'
        Tune volume_db in 1 dB steps with '.' and ','

        Args:
            keyb (int): keystroke in ASCII

        Returns:
            bool: True if receiver needs tuning, False if not
        """
        # pylint: disable=too-many-return-statements
        # pylint: disable=too-many-branches

        # Tune self.gain_db in 10 dB steps with 'g' and 'f'
        if keyb == ord('g'):
            self.gain_db += 10
            return True
        elif keyb == ord('f'):
            self.gain_db -= 10
            return True

        # Tune self.gain_db in 1 dB steps with 'G' and 'F'
        if keyb == ord('G'):
            self.gain_db += 1
            return True
        elif keyb == ord('F'):
            self.gain_db -= 1
            return True

        # Tune self.if_gain_db in 10 dB steps with 'u' and 'y'
        if keyb == ord('u'):
            self.if_gain_db += 10
            return True
        elif keyb == ord('y'):
            self.if_gain_db -= 10
            return True

        # Tune self.if_gain_db in 1 dB steps with 'U' and 'Y'
        if keyb == ord('U'):
            self.if_gain_db += 1
            return True
        elif keyb == ord('Y'):
            self.if_gain_db -= 1
            return True

        # Tune self.bb_gain_db in 10 dB steps with ']' and '['
        if keyb == ord(']'):
            self.bb_gain_db += 10
            return True
        elif keyb == ord('['):
            self.bb_gain_db -= 10
            return True

        # Tune self.bb_gain_db in 1 dB steps with '}' and '{'
        if keyb == ord('}'):
            self.bb_gain_db += 1
            return True
        elif keyb == ord('{'):
            self.bb_gain_db -= 1
            return True

        # Tune self.squelch_db in 1 dB steps with 's' and 'a'
        elif keyb == ord('s'):
            self.squelch_db += 1
            return True
        elif keyb == ord('a'):
            self.squelch_db -= 1
            return True
        # Tune self.volume_db in 1 dB steps with '.' and ','
        elif keyb == ord('.'):
            self.volume_db += 1
            return True
        elif keyb == ord(','):
            self.volume_db -= 1
            return True
        else:# pylint: disable=too-many-return-statements
            return False

def setup_screen(screen):
    """Sets up screen
    """
    # Set screen to getch() is non-blocking
    screen.nodelay(1)

    # Define some colors
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
    curses.init_pair(5, curses.COLOR_YELLOW, curses.COLOR_BLACK)

    # Add border
    screen.border(0)

def main():
    """Test most of the GUI (except lockout processing)

    Initialize and set up screen
    Create windows
    Generate dummy spectrum data
    Update windows with dummy values
    Process keyboard strokes
    """
    # Use the curses.wrapper() to crash cleanly
    # Note the screen object is passed from the wrapper()
    # http://stackoverflow.com/questions/9854511/ppos_ython-curses-dilemma
    # The issue is the debuuger won't work with the wrapper()
    # So enable the next 2 lines and don't pass screen to main()
    screen = curses.initscr()
    curses.start_color()

    # Setup the screen
    setup_screen(screen)

    # Create windows
    specwin = SpectrumWindow(screen)
    chanwin = ChannelWindow(screen)
    lockoutwin = LockoutWindow(screen)
    rxwin = RxWindow(screen)

    while 1:
        # Generate some random spectrum data from -dyanmic_range to 0 dB
        #   then offset_db
        length = 128
        dynamic_range_db = 100
        offset_db = 50
        data = np.power(10, (-dynamic_range_db*np.random.rand(length)/10)\
            + offset_db/10)
        #data = 1E-5*np.ones(length)
        specwin.draw_spectrum(data)

        # Put some dummy values in the channel, lockout, and receiver windows
        chanwin.draw_channels(['144.100', '142.40', '145.00', '144.10',\
        '142.40', '145.00', '144.10', '142.40', '145.00', '144.10', '142.40',\
        '145.00', '142.40', '145.00', '144.10', '142.400', '145.00', '145.00'])
        lockoutwin.draw_channels(['144.100', '142.40', '145.00'])
        rxwin.draw_rx()

        # Update physical screen
        curses.doupdate()

        # Check for keystrokes and process
        keyb = screen.getch()
        specwin.proc_keyb(keyb)
        rxwin.proc_keyb_hard(keyb)
        rxwin.proc_keyb_soft(keyb)

        # Sleep to get about a 10 Hz refresh
        time.sleep(0.1)

if __name__ == '__main__':
    try:
        #curses.wrapper(main)
        main()
    except KeyboardInterrupt:
        pass
