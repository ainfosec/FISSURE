import time
import numpy as np
from types import *
import signal

import gtk, gobject
import gtk.glade
gtk.gdk.threads_init()

import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import matplotlib.path as path
from matplotlib.backends.backend_gtkagg import FigureCanvasGTKAgg as FigureCanvas

class SensorWindow(object):
	def __init__(self, mainThread, gladefile = 'sensor_window.glade'):
		self.builder = gtk.Builder()
		self.builder.add_from_file(gladefile)
		self.builder.connect_signals(self)

		self._stopped = False
		self.mainThread = mainThread

		self.fig = plt.figure()
		self.numLines = 1

		# lines plot
		self.ax = self.fig.add_subplot(111)
		self.ax.set_xlabel('Time')
		self.ax.set_ylabel('Power')
		self.ax.xaxis.set_animated(True)
		self.ax.yaxis.set_animated(True)
		self.ax.set_title('Light Intensity')
		self.ax.grid(True)

		self.start = time.time()
		self.background1 = None
		self.prev_time = self.start
		self.prev_pixel_offset = 0
		self.x0 = 0
		self.value = [0] * self.numLines

		self.ax.set_ylim(-1, 256)

		self.lines = []
		for i in range(self.numLines):
			line, = self.ax.plot([], [], animated = True, lw = 2)
			self.lines.append(line)

		self.canvas = FigureCanvas(self.fig)

		self.graphview = self.builder.get_object("box2")
		self.graphview.pack_start(self.canvas)
		self.graphview.reorder_child(self.canvas, 0)

		self.img = self.builder.get_object("image1")
		self.img.set_from_file("off.svg")
		self.lamp = False

		self.canvas.show()

		gobject.idle_add(self.update_line)
		self.canvas.mpl_connect('draw_event', self.on_draw)

		self.barpath = []


	def close_window(self, obj):
		print "closing window"
		self.builder.get_object("window1").destroy()

	def destroy_callback(self, obj):
		print "destroying window"
		self.mainThread.stop()
		self._stopped = True

	def close_from_mainthread(self):
		print "close from mainthread"
		self.builder.get_object("window1").destroy()


	def toggle_lamp(self):
		print "toggle lamp!!"
		self.img = self.builder.get_object("image1")
		if(self.lamp):
			self.lamp = False
			self.img.set_from_file("off.svg")
		else:
			self.lamp = True
			self.img.set_from_file("on.svg")

	def update_line(self, *args):

		if self._stopped:
			self.destroy_callback(None)
			return False

		if self.background1 is None:
			return True

		cur_time = time.time()
		pixel_offset = int((cur_time - self.start) * 40.)
		dx_pixel = pixel_offset - self.prev_pixel_offset
		self.prev_pixel_offset = pixel_offset
		dx_data = self.get_dx_data(dx_pixel) #cur_time - self.prev_time)

		x0 = self.x0
		self.x0 += dx_data
		self.prev_time = cur_time

		self.ax.set_xlim(self.x0-2, self.x0+0.1)

		# restore background which will plot lines from previous plots
		self.restore_background_shifted(dx_pixel) #x0, self.x0)

		# now plot line segment within [x0, x0+dx_data],
		# Note that we're only plotting a line between [x0, x0+dx_data].
		xx = np.array([x0, self.x0])
		for i in range(len(self.lines)):
			line = self.lines[i]
			line.set_xdata(xx)

			# the for loop below could be improved by using collection.
			line.set_ydata(np.array([self.value[i], self.value[i]]))
			self.ax.draw_artist(line)

		self.background2 = self.canvas.copy_from_bbox(self.get_bg_bbox())

		self.ax.draw_artist(self.ax.xaxis)
		self.ax.draw_artist(self.ax.yaxis)

		self.canvas.blit(self.ax.get_figure().bbox)
		return True

	def get_dx_data(self, dx_pixel):
		tp = self.ax.transData.inverted().transform_point
		x0, y0 = tp((0, 0))
		x1, y1 = tp((dx_pixel, 0))
		return (x1 - x0)

	def get_bg_bbox(self):
		return self.ax.bbox.padded(-3)

	def save_bg(self):
		self.background1 = self.canvas.copy_from_bbox(self.ax.get_figure().bbox)
		self.background2 = self.canvas.copy_from_bbox(self.get_bg_bbox())

	def on_draw(self, *args):
		self.save_bg()
		return False

	def restore_background_shifted(self, dx_pixel):
		"""
		restore bacground shifted by dx in data coordinate. This only
		works if the data coordinate system is linear.
		"""

		# restore the clean slate background
		self.canvas.restore_region(self.background1)

		# restore subregion (x1+dx, y1, x2, y2) of the second bg
		# in a offset position (x1-dx, y1)
		x1, y1, x2, y2 = self.background2.get_extents()
		self.canvas.restore_region(self.background2,
					bbox=(x1+dx_pixel, y1, x2, y2),
					xy=(x1-dx_pixel, y1))

		return dx_pixel

	def update(self, data):
		if type(data) == ListType:
			assert(len(self.lines) == len(data))
			self.value = data
		else:
			assert(len(self.lines) == 1)
			self.value = [data]

