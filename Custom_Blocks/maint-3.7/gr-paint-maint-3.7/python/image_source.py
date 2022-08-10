#!/usr/bin/env python
# vim: tabstop=4:softtabstop=4:shiftwidth=4:noexpandtab:
# -*- coding: utf-8 -*-
# 
# Copyright 2015,2016 Chris Kuethe <chris.kuethe@gmail.com>
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

import numpy
from gnuradio import gr
from PIL import Image
from PIL import ImageOps
import pmt

class image_source(gr.sync_block):
	"""
	Given an image file readable by Python-Imaging, this block produces
	monochrome lines suitable for input to spectrum_paint
	"""

	image_file = None
	image_flip = False
	bt709_map = True
	image_invert = False
	autocontrast = False
	repeatmode = 1
	image_data = None
	eof = False

	def __init__(self, image_file, image_flip=False, bt709_map=True, image_invert=False, autocontrast=False, repeatmode=1):
		gr.sync_block.__init__(self,
			name="image_source",
			in_sig=None,
			out_sig=[numpy.uint8])

		self.image_file = image_file
		self.image_flip = image_flip
		self.bt709_map = bt709_map
		self.image_invert = image_invert
		self.autocontrast = autocontrast
		self.repeatmode = repeatmode

		self.load_image()

	def load_image(self):
		"""decode the image into a buffer"""
		self.image_data = Image.open(self.image_file)
		self.image_data = ImageOps.grayscale(self.image_data)

		if self.autocontrast:
			# may or may not improve the look of the transmitted spectrum
			self.image_data = ImageOps.autocontrast(self.image_data)

		if self.image_invert:
			# may or may not improve the look of the transmitted spectrum
			self.image_data = ImageOps.invert(self.image_data)

		if self.image_flip:
			# set to true for waterfalls that scroll from the top
			self.image_data = ImageOps.flip(self.image_data)

		(self.image_width, self.image_height) = self.image_data.size
		max_width = 4096.0
		if self.image_width > max_width:
			scaling = max_width / self.image_width
			newsize = (int(self.image_width * scaling), int(self.image_height * scaling))
			(self.image_width, self.image_height) = newsize
			self.image_data = self.image_data.resize(newsize)
		self.set_output_multiple(self.image_width)

		self.image_data = list(self.image_data.getdata())
		if self.bt709_map:
			# scale brightness according to ITU-R BT.709
			self.image_data = map( lambda x: x * 219 / 255 + 16,  self.image_data)
		self.image_len = len(self.image_data)
		if self.repeatmode != 2:
			print "paint.image_source: %d bytes, %dpx width" % (self.image_len, self.image_width)
		self.line_num = 0

	def work(self, input_items, output_items):
		if self.eof:
			return -1
		out = output_items[0]
		self.add_item_tag(0, self.nitems_written(0), pmt.intern("image_width"), pmt.from_long(self.image_width))
		self.add_item_tag(0, self.nitems_written(0), pmt.intern("line_num"), pmt.from_long(self.line_num))
		out[:self.image_width] = self.image_data[self.image_width*self.line_num: self.image_width*(1+self.line_num)]

		self.line_num += 1
		if self.line_num >= self.image_height:
			self.line_num = 0
			if self.repeatmode == 0:
				self.eof = True
			if self.repeatmode == 2:
				self.load_image()
		return self.image_width
