#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 gr-ainfosec author.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#


import numpy, scipy
from gnuradio import gr
import pmt
import time

class ook_generator(gr.sync_block):
    """
    docstring for block ook_generator
    """
    def __init__(self, chip0_pattern, chip1_pattern, burst_interval, sample_rate, chip0_duration, chip1_duration, number_of_bursts, sequence, repetition_interval):
        gr.sync_block.__init__(self,
            name="ook_generator",
            in_sig=[numpy.complex64],
            out_sig=[numpy.complex64])
            
        self.chip0_pattern = chip0_pattern
        self.chip1_pattern = chip1_pattern
        self.burst_interval = burst_interval
        self.sample_rate = sample_rate
        self.chip0_duration = chip0_duration
        self.chip1_duration = chip1_duration
        self.number_of_bursts = int(number_of_bursts)
        self.sequence = sequence
        self.repetition_interval = repetition_interval

        self.replay_index = 0
        self.pri_timer = time.time()
        
        self.generateSignal()
        
        self.update_ook_signal = False

    def work(self, input_items, output_items):
        in0 = input_items[0]
        out = output_items[0]
        input_len = len(input_items[0])
                
        # Transmit OOK Signal
        if time.time() < self.pri_timer + self.repetition_interval:  # Last Window Adds Delay
            
            # Whole Window
            if self.replay_index + input_len < len(self.replay_data):
                out[:] = self.replay_data[self.replay_index:self.replay_index + input_len]
                self.replay_index = self.replay_index + input_len
                
            # Partial Window/End
            else:                   
                # End of OOK Signal
                if self.replay_index == len(self.replay_data):
                    out[:] = in0
                    
                # Partial Window at End
                else:
                    chunk1 = self.replay_data[self.replay_index:]
                    chunk2 = numpy.zeros(self.replay_index + input_len - len(self.replay_data))                    
                    self.replay_index = len(self.replay_data)
                    out[:] = numpy.concatenate([chunk1, chunk2])
                
        # Time Expired (One Window of Delay Added Here)
        else:
            self.replay_index = 0  
            self.pri_timer = time.time()           
            out[:] = in0
            
            # Update Signal on Parameter Update
            if self.update_ook_signal == True:
                self.update_ook_signal = False
                self.generateSignal()

        return len(output_items[0])

  
    def set_chip0_pattern(self,chip0_pattern):
        self.chip0_pattern = chip0_pattern
        self.update_ook_signal = True
        
    def set_chip1_pattern(self,chip1_pattern):
        self.chip1_pattern = chip1_pattern
        self.update_ook_signal = True
        
    def set_burst_interval(self,burst_interval):
        self.burst_interval = burst_interval
        self.update_ook_signal = True

    def set_sample_rate(self,sample_rate):
        self.sample_rate = sample_rate
        self.update_ook_signal = True

    def set_chip0_duration(self,chip0_duration):
        self.chip0_duration = chip0_duration
        self.update_ook_signal = True
        
    def set_chip1_duration(self,chip1_duration):
        self.chip1_duration = chip1_duration
        self.update_ook_signal = True
        
    def set_number_of_bursts(self,number_of_bursts):
        self.number_of_bursts = number_of_bursts
        self.update_ook_signal = True

    def set_sequence(self,sequence):
        self.sequence = sequence
        self.update_ook_signal = True

    def set_repetition_interval(self,repetition_interval):
        self.repetition_interval = repetition_interval
        self.update_ook_signal = True
        
    def generateSignal(self):
        """ Generates the OOK signal from the parameter values.
        """
        # Determine Samples
        chip0_samples = int(float(self.chip0_duration) * 1e-6 * float(self.sample_rate))  # in us and S/s
        chip1_samples = int(float(self.chip1_duration) * 1e-6 * float(self.sample_rate))
        
        # Convert Bits to Chips
        sequence = self.sequence.replace(' ','')
        chip_stream = ''
        for n in range(0,len(sequence)):
            if sequence[n] == "0":
                chip_stream = chip_stream + self.chip0_pattern
            elif sequence[n] == "1":
                chip_stream = chip_stream + self.chip1_pattern
            else:
                print("Invalid chip/bit sequence. Enter as a series of 0's and 1's.")
                
        # Convert Chips to Samples
        chip_samples = ''
        for n in range(0,len(chip_stream)):
            if chip_stream[n] == "0":
                chip_samples = chip_samples + chip_stream[n] * chip0_samples
            elif chip_stream[n] == "1":
                chip_samples = chip_samples + chip_stream[n] * chip1_samples
                
        # Add in Bursts
        burst_samples = ''
        for n in range(0,int(self.number_of_bursts)):
            burst_samples = burst_samples + chip_samples + "0" * int(float(self.burst_interval) * 1e-6 * float(self.sample_rate))

        # Format Samples
        sample_array = numpy.array([int(sample) for sample in burst_samples])
        signal_array = numpy.zeros(len(sample_array), dtype=numpy.complex64)
        signal_array.real = sample_array
          
        self.replay_data = signal_array
