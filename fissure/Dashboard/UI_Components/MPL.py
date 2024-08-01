from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
from PyQt5 import QtWidgets

import math
import matplotlib
import matplotlib.figure
import matplotlib.pyplot
import numpy as np

matplotlib.set_loglevel("INFO")


class MPLCanvas(FigureCanvasQTAgg):
    def __init__(
        self,
        parent=None,
        dpi=100,
        title=None,
        ylim=None,
        width=401,
        height=401,
        border=[0.1, 0.9, 0.01, 0.99, 0, 0],
        colorbar_fraction=0.038,
        xlabels=["0", "", "1000", "", "2000", "", "3000", "", "4000", "", "5000", "", "6000"],
        ylabels=["0", "5", "10", "15", "20"],
        bg_color=None,
        face_color=None,
        text_color=None,
    ):
        """
        Creates a plot with colorbar and places it in a figure canvas.
        """
        self.plot_width = width
        self.plot_height = height

        # Background Color
        # background_color = (244.0/255, 244.0/255, 244.0/255, 1)  #QtGui.QColor(242,241,240)
        rgb = tuple(int(face_color.lstrip("#")[i : i + 2], 16) for i in (0, 2, 4))
        background_color = (float(rgb[0]) / 255, float(rgb[1]) / 255, float(rgb[2]) / 255)

        # Set up the Figure
        self.fig = matplotlib.figure.Figure(dpi=dpi)
        self.axes = self.fig.add_subplot(111)  # face_color is plotted as rgb in wideband_data

        # ~ # Ignore hold() Deprecation Warnings
        # ~ with warnings.catch_warnings():
        # ~ warnings.simplefilter("ignore")
        # ~ warnings.filterwarnings("ignore", module="matplotlib")
        # ~ #self.axes.hold(False)  # FIX: To clear an axes you can manually use cla(),
        # ~ or to clear an entire figure use clf()

        self.fig.subplots_adjust(
            left=border[0], right=border[1], bottom=border[2], top=border[3], wspace=border[4], hspace=border[5]
        )

        # Create the Data Arrays
        temp_plot_data = np.ones((self.plot_height, self.plot_width, 3)) * background_color  # background color (1,1,1)

        # Do the Plotting
        img = self.axes.imshow(temp_plot_data, cmap="rainbow", clim=(-60, 40))
        self.cbar = self.fig.colorbar(img, fraction=colorbar_fraction * ylim / 500, pad=0.04)
        self.configureAxes(
            title, "Frequency (MHz)", xlabels, "Time Elapsed", ylabels, ylim, bg_color, face_color, text_color
        )

        # Other
        FigureCanvasQTAgg.__init__(self, self.fig)
        self.setParent(parent)
        FigureCanvasQTAgg.setSizePolicy(self, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        FigureCanvasQTAgg.updateGeometry(self)


    def configureAxesZoom1(self, xmin, xmax, wideband_height):
        """
        Configures the axes for wideband zoom. Not implemented yet.
        """
        try:
            # Define the Size
            self.axes.axis([0, self.plot_width, self.plot_height, 0])

            # Font
            # axis_font = {'fontname':'DejaVu Sans', 'size':'11'}
            # axis_font = {'size':'11'}

            # xlim
            # xlim1 = int(xmin/1e6)/5 #  (number/6000)*1200
            # xlim2 = 1+int(xmax/1e6)/5
            # self.axes.set_xlim([xlim1, xlim2])
            # print(self.axes.get_xlim())

            # xtick Locations
            xspan = int(xmax / 1e6) - int(xmin / 1e6)
            steps = 12
            xstep = float(xspan) / steps / 5
            xticks = []
            for n in range(0, steps):
                xticks.append(float((xmin / 1e6) / 5 + n * (xstep / 1)))
                # print(float((xmin/1e6)/5+n*(xstep/1)))
            xticks.append(float((xmax / 1e6)) / 5)
            # self.axes.set_xticks(xticks)
            start, end = self.axes.get_xlim()
            self.axes.set_xticks(np.arange(start, end, 100))

            # xticklabels
            xlabels = []
            for n in range(0, steps + 1):
                xlabels.append(str(int(xticks[n] * 5)))
            self.axes.set_xticklabels(xlabels)

            # xlabel
            self.axes.set_xlabel("Frequency (MHz)")

            # ylim
            self.axes.set_ylim([wideband_height, 0])

            # yticks
            start, end = self.axes.get_ylim()
            self.axes.set_yticks(np.arange(end, start, 100))

            # yticklabels
            ylabels = ["0", "5", "10", "15", "20", "25", "30", "35", "40"]
            self.axes.set_yticklabels(ylabels[0 : len(np.arange(end, start, 100))])
            self.axes.yaxis.grid("on")

            # ylabel
            self.axes.set_ylabel("Time Elapsed (s)")

            # Grid
            self.axes.xaxis.grid("on")
            self.axes.yaxis.grid("on")

            # Font Size
            for item in (
                [self.axes.title, self.axes.xaxis.label, self.axes.yaxis.label]
                + self.axes.get_xticklabels()
                + self.axes.get_yticklabels()
            ):
                item.set_fontsize(9)

        ########################################

        # title='Detector History',xlabel='Frequency (MHz)',ylabel='Time Elapsed (s)',
        # xlabels=['0', '','1000', '', '2000', '', '3000', '', '4000', '', '5000', '', '6000'],
        # ylabels=['0', '5', '10', '15', '20', '25', '30', '35', '40'],ylim=wideband_height

        # Font Size
        # for item in (
        #     [self.axes.title, self.axes.xaxis.label, self.axes.yaxis.label]
        #     + self.axes.get_xticklabels()
        #     + self.axes.get_yticklabels()
        # ):
        #     item.set_fontsize(11)

        # Set the Labels, Gridlines
        # axis_font = {'fontname':'Bitstream Vera Sans', 'size':'12'}

        # self.axes.set_xlabel(xlabel, **axis_font)

        # start, end = self.axes.get_xlim()
        # self.axes.set_xticks(np.arange(start,end,100))

        # self.axes.set_xticklabels(xlabels[0:len(np.arange(start,end,100))])
        # self.axes.xaxis.grid('on')

        # self.axes.set_ylim([ylim, 0])
        # self.axes.set_ylabel(ylabel, **axis_font)

        # start, end = self.axes.get_ylim()
        # self.axes.set_yticks(np.arange(end,start,100))

        # self.axes.set_yticklabels(ylabels[0:len(np.arange(end,start,100))])

        except:
            pass


    def plotPoint(self, x, y, color, point_size, wideband_data):
        """
        Plots a wideband signal.
        """
        # Colors in Pixels Surrounding a Point, (r,g,b) Color Values are Normalized (0-1)
        wideband_data[int(y) - 10 : int(y) + 10, 2 * int(x) - point_size : 2 * int(x) + point_size] = color


    def configureAxes(self, title, xlabel, xlabels, ylabel, ylabels, ylim, background_color, face_color, text_color):
        """
        Configures the axes, needs to be called for every plot because hold(False) will redo the axes setup.
        """
        try:
            # Define the Size
            self.axes.axis([0, self.plot_width, self.plot_height, 0])

            self.axes.set_xlabel(xlabel)

            start, end = self.axes.get_xlim()
            self.axes.set_xticks(np.arange(start, end, 100))

            self.axes.set_xticklabels(xlabels[0 : len(np.arange(start, end, 100))])
            self.axes.xaxis.grid("on")

            self.axes.set_ylim([ylim, 0])
            self.axes.set_ylabel(ylabel)

            start, end = self.axes.get_ylim()
            self.axes.set_yticks(np.arange(end, start, 100))

            self.axes.set_yticklabels(ylabels[0 : len(np.arange(end, start, 100))])
            self.axes.yaxis.grid("on")

            for item in (
                [self.axes.title, self.axes.xaxis.label, self.axes.yaxis.label]
                + self.axes.get_xticklabels()
                + self.axes.get_yticklabels()
            ):
                item.set_fontsize(9)
                item.set_color(text_color)

            self.fig.set_facecolor(background_color)
            self.cbar.ax.tick_params(labelsize=11, color=text_color)
            matplotlib.pyplot.setp(matplotlib.pyplot.getp(self.cbar.ax.axes, "yticklabels"), color=text_color)
            self.cbar.set_label(label="Power (dB)", color=text_color)
            self.axes.tick_params(axis="x", colors=text_color)
            self.axes.tick_params(axis="y", colors=text_color)

        except:
            pass


    def computeColormapValue(self, power_level):
        """
        Takes the power level in dBm, normalizes it to the colorbar limits, and then looks up the corresponding
        color value in the colormap array
        """
        # Colorbar Limits
        min_power = -60
        max_power = 40

        # Normalize to the Colorbar Limits
        computed_power_level = 1 * (power_level - min_power) / (max_power - min_power)

        # Look up the Value in the 256 Length Colormap Array
        colormap_value = matplotlib.cm.rainbow(computed_power_level)[0:3]

        return colormap_value


class MPLTuningCanvas(FigureCanvasQTAgg):
    def __init__(self, parent=None, dpi=100, title=None, ylim=None, bg_color=None, face_color=None, text_color=None):
        """Class for creating the tuning graphic"""
        self.plot_width = 601
        self.plot_height = 401

        # Background Color
        # background_color = (242.0/255, 241.0/255, 240.0/255, 1)  #QtGui.QColor(242,241,240)
        # background_color = (251.0/255, 251.0/255, 251.0/255, 1)

        # Set up the Figure
        fig = matplotlib.figure.Figure(dpi=dpi)
        self.fig = fig

        self.axes = fig.add_axes([0.03, 0.25, 0.94, 0.8])
        # self.axes.axis('off')
        self.axes.spines["top"].set_visible(False)
        self.axes.spines["right"].set_visible(False)
        # self.axes.spines['bottom'].set_visible(False)
        self.axes.spines["left"].set_visible(False)

        # ~ # Ignore hold() Deprecation Warnings
        # ~ with warnings.catch_warnings():
        # ~ warnings.simplefilter("ignore")
        # ~ warnings.filterwarnings("ignore", module="matplotlib")
        # ~ #self.axes.hold(False)  # FIX: To clear an axes you can manually use cla(),
        # ~ or to clear an entire figure use clf()

        # Remove the Colors
        # fig.frameon = False
        # for item in [fig, self.axes]:
        # item.patch.set_visible(False)  # Makes it white instead of transparent in newer version

        # Configure Axes
        self.configureAxes(
            title=title,
            xlabel="Frequency (MHz)",
            ylabel="",
            ylabels="",
            ylim=ylim,
            background_color=bg_color,
            face_color=face_color,
            text_color=text_color,
        )

        # Other
        FigureCanvasQTAgg.__init__(self, fig)
        self.setParent(parent)
        FigureCanvasQTAgg.setSizePolicy(self, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        FigureCanvasQTAgg.updateGeometry(self)

        fig.canvas.mpl_connect("axes_leave_event", self.leave_axes)
        fig.canvas.mpl_connect("motion_notify_event", self.on_motion)

        # Initialize Clicking Variables
        self.clicks = 0
        self.bands = []
        self.first_point = 0
        self.first_click = 0
        self.second_click = 0
        self.needs_update = False
        self.band_height = 36

        # Tuned Location
        self.tuned = None

        # Frequency Limits (MHz)
        self.freq_start_limit = 1
        self.freq_end_limit = 6000


    def updateTuned(self, current_band, current_freq, bandwidth):
        """
        Updates the location of the tuned rectangle.
        """
        # Delete Existing Rectangle
        if self.tuned is not None:
            self.tuned.remove()
            del self.tuned

        # Draw New Rectangle
        current_freq = float(current_freq) / 10
        bandwidth = float(bandwidth) / 10
        self.tuned = self.axes.add_patch(
            matplotlib.patches.Rectangle(
                (current_freq - (bandwidth / 2), (self.band_height * (current_band))),
                bandwidth,
                self.band_height,
                facecolor="yellow",
                alpha=0.85,
            )
        )
        self.draw()


    def onclick(self, event):
        """
        Called when the mouse is clicked on Tuning figure.
        """
        # Valid Click
        if event.xdata is not None:

            # Left Click
            if event.button == 1:
                # First Click
                if self.clicks == 0:
                    self.clicks = 1
                    self.first_point = event.xdata

                # Second Click
                elif self.clicks == 1:
                    self.clicks = 0
                    self.second_point = event.xdata

                    if len(self.bands) < 10:  # Limit the number of bands to 10
                        # Plot the Band
                        if len(self.bands) > 0:
                            if self.bands[-1].get_facecolor()[0] == 1:  # Delete existing red band
                                self.bands[-1].remove()
                                del self.bands[-1]
                        h = self.axes.add_patch(
                            matplotlib.patches.Rectangle(
                                (self.first_point, (self.band_height * (len(self.bands) + 1))),
                                self.second_point - self.first_point,
                                self.band_height,
                                facecolor="red",
                                edgecolor="Black",
                            )
                        )
                        self.bands.append(h)
                        self.first_click = self.first_point * 10
                        self.second_click = self.second_point * 10

                        # Account for Hardware Frequency Limits
                        if self.first_click < self.freq_start_limit:
                            self.first_click = self.freq_start_limit
                        if self.first_click > self.freq_end_limit:
                            self.first_click = self.freq_end_limit
                        if self.second_click > self.freq_end_limit:
                            self.second_click = self.freq_end_limit
                        if self.second_click < self.freq_start_limit:
                            self.second_click = self.freq_start_limit

                        self.needs_update = True
                self.draw()

            # Right Click
            elif event.button == 3:
                # Delete the Last Band Added if it is Red
                if len(self.bands) > 0 and self.bands[-1].get_facecolor()[0] == 1:
                    self.bands[-1].remove()
                    del self.bands[-1]
                    self.draw()

    # def enter_axes(self, event):
    # """ Called when the mouse enters the Tuning axes
    # """
    # print('enter_axes', event.inaxes)
    # self.draw()


    def leave_axes(self, event):
        """Called when the mouse leaves the Tuning axes"""
        # Hide the Mouseover Text
        text_x = int(self.axes.get_xlim()[0]) + 1
        for txt in self.axes.texts:
            if txt.get_position() == (text_x, 500):
                txt.remove()

        self.draw()


    def on_motion(self, event):
        """
        Gets the mouse over coordinates upon movement.
        """
        if event.inaxes:
            xpos = event.xdata
            freq_text = str(int(xpos * 10))

            text_x = int(self.axes.get_xlim()[0]) + 1

            # Delete Old Text
            for txt in self.axes.texts:
                if txt.get_position() == (text_x, 500):
                    txt.remove()

            # Draw New Text
            self.axes.text(text_x, 500, freq_text, fontsize=11, bbox=dict(facecolor="red", alpha=0.5))
            self.draw()


    def configureAxes(self, title, xlabel, ylabel, ylabels, ylim, background_color, face_color, text_color):
        """
        Configures the axes, needs to be called for every plot because hold(False) will redo the axes setup.
        """
        # Define the Size
        self.axes.axis([0, self.plot_width, self.plot_height, 0])

        # xlim
        self.axes.set_xlim([0, 601])

        # xtick Locations
        xspan = 6000
        steps = 6
        xstep = float(xspan) / steps
        xticks = []
        for n in range(0, steps):
            xticks.append(int(n * (xstep / 10)))
        xticks.append(600)
        self.axes.set_xticks(xticks)

        # xtick Labels
        xlabels = ["0", "1000", "2000", "3000", "4000", "5000", "6000"]
        self.axes.set_xticklabels(xlabels)

        # xaxis Label
        self.axes.set_xlabel(xlabel)

        # Title
        self.axes.set_title(title)

        # Grid
        self.axes.xaxis.grid("on")
        self.axes.set_axisbelow(True)

        # Y Values
        self.axes.set_ylim([ylim, 0])
        self.axes.set_ylabel(ylabel)
        self.axes.set_yticks([x * 100 for x in (range(0, len(ylabels)))], minor=False)
        self.axes.set_yticklabels(ylabels)
        self.axes.yaxis.grid("on")

        # Font Size
        for item in (
            [self.axes.title, self.axes.xaxis.label, self.axes.yaxis.label]
            + self.axes.get_xticklabels()
            + self.axes.get_yticklabels()
        ):
            item.set_fontsize(9)
            item.set_color(text_color)

        self.axes.set_facecolor(face_color)
        self.fig.set_facecolor(background_color)
        self.axes.tick_params(axis="x", colors=text_color)
        self.axes.tick_params(axis="y", colors=text_color)


    def configureAxesZoom(self, xmin, xmax):
        """
        Configures the axes, needs to be called for every plot because hold(False) will redo the axes setup.
        """
        # Define the Size
        self.axes.axis([0, self.plot_width, self.plot_height, 0])

        # xlim
        self.axes.set_xlim([int(xmin / 1e6) / 10, 1 + int(xmax / 1e6) / 10])

        # xtick Locations
        xspan = int(xmax / 1e6) - int(xmin / 1e6)
        steps = 10
        xstep = float(xspan) / steps
        xticks = []
        for n in range(0, steps):
            xticks.append(float((xmin / 10e6) + n * (xstep / 10)))
        xticks.append(float((xmax / 10e6)))
        self.axes.set_xticks(xticks)

        # xlabels
        xlabels = []
        for n in range(0, steps + 1):
            xlabels.append(str(int(xticks[n] * 10)))
        self.axes.set_xticklabels(xlabels)

        # Grid
        self.axes.xaxis.grid("on")

        # Font Size
        for item in (
            [self.axes.title, self.axes.xaxis.label, self.axes.yaxis.label]
            + self.axes.get_xticklabels()
            + self.axes.get_yticklabels()
        ):
            item.set_fontsize(9)

        # Draw
        self.draw()


class MPL_IQCanvas(FigureCanvasQTAgg):
    def __init__(self, parent=None, dpi=100, title=None, ylim=None, bg_color=None, face_color=None, text_color=None):
        """
        Creates a plot for IQ data and places it in a figure canvas.
        """
        # Background Color
        # ~ background_color = (242.0/255, 241.0/255, 240.0/255, 1)  #QtGui.QColor(242,241,240)
        # rgb = tuple(int(bg_color.lstrip('#')[i:i+2], 16) for i in (0, 2, 4))
        # background_color = (float(rgb[0])/255, float(rgb[1])/255, float(rgb[2])/255, 1)
        # ~ border_color = (25.0/255, 54.0/255, 93.0/255, 1)

        # Set up the Figure
        # ~ self.fig = Figure(dpi=dpi, facecolor=background_color, linewidth=1, edgecolor=border_color)
        self.fig = matplotlib.figure.Figure(dpi=dpi)
        self.fig.subplots_adjust(left=0.1, right=0.95, bottom=0.1, top=0.94, wspace=0, hspace=0)

        # Do the Plotting
        self.polar_used = False
        self.configureAxes(False, bg_color, face_color, text_color)
        self.applyLabels(title, "Samples", "Amplitude (LSB)", None, None, text_color)

        # Other
        FigureCanvasQTAgg.__init__(self, self.fig)
        self.setParent(parent)
        FigureCanvasQTAgg.setSizePolicy(self, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        FigureCanvasQTAgg.updateGeometry(self)

        # Cursor
        self.cursor_enable = False
        self.cursor1 = None
        self.cursor2 = None
        self.fill_rect = None
        self.click = 1
        self.txt = None  # self.axes.text(0.0, 0.0, '', transform=self.axes.transAxes)
        self.text_color = text_color
        cid = self.fig.canvas.mpl_connect("button_press_event", self.onclick)


    def applyLabels(self, title, xlabel, ylabel, ylabels, ylim, text_color):
        """
        Configures the axes, needs to be called for every plot because hold(False) will redo the axes setup.
        """
        try:
            # Define the Size
            # self.axes.axis([0, width, height, 0])

            # Set the Labels, Gridlines
            # self.axes.set_title(title)

            self.axes.set_xlabel(xlabel, color=text_color)
            self.axes.xaxis.grid("on")

            self.axes.set_ylabel(ylabel, color=text_color)
            self.axes.yaxis.grid("on")

        except:
            pass


    def configureAxes(self, polar, background_color, face_color, text_color):
        """
        Configures the axes after a polar/projection change. Must be done before plot. Gridlines and labels after plot.
        """
        # Plot Type
        self.fig.clear()  # Suppresses MatplotlibDeprecationWarning
        if polar:
            self.axes = self.fig.add_subplot(111, polar=True)
            self.polar_used = True
        else:
            self.axes = self.fig.add_subplot(111, polar=False)
            self.polar_used = False

        # ~ # Ignore hold() Deprecation Warnings
        # ~ with warnings.catch_warnings():
        # ~ warnings.simplefilter("ignore")
        # ~ warnings.filterwarnings("ignore", module="matplotlib")
        # ~ #self.axes.hold(False)  # FIX: To clear an axes you can manually use cla(),
        # ~ or to clear an entire figure use clf()

        for item in (
            [self.axes.title, self.axes.xaxis.label, self.axes.yaxis.label]
            + self.axes.get_xticklabels()
            + self.axes.get_yticklabels()
        ):
            item.set_fontsize(9)
            item.set_color(text_color)

        self.axes.set_facecolor(face_color)
        self.fig.set_facecolor(background_color)
        self.axes.tick_params(axis="x", colors=text_color)
        self.axes.tick_params(axis="y", colors=text_color)
        self.text_color = text_color


    def clearPlot(self):
        """
        Clears the plot data.
        """
        for artist in self.axes.lines + self.axes.collections:
            artist.remove()
        self.cursor1 = None
        self.cursor2 = None
        self.fill_rect = None
        self.txt = None

    # def mouse_move(self, event):
    # if self.cursor_enable:
    # # Mouse Move Checkbox
    # if self.mouse_move_enable:
    # if not event.inaxes:
    # return
    # x, y = event.xdata, event.ydata
    # #indx = min(np.searchsorted(self.x, x), len(self.x) - 1)
    # #x = self.x[indx]
    # #y = self.y[indx]
    # ## update the line positions
    # self.lx.set_ydata(y)
    # self.ly.set_xdata(x)
    # self.axes.figure.canvas.draw()


    def onclick(self, event):
        """
        Called when the mouse is clicked on IQ Viewer figure.
        """
        if self.cursor_enable:
            # Valid Click
            if event.xdata is not None:
                # Left Click
                if event.button == 1:
                    x = event.xdata
                    if self.click == 1:
                        if self.cursor1 is not None:
                            self.cursor1.remove()
                        if self.cursor2 is not None:
                            self.cursor2.remove()
                        if self.fill_rect is not None:
                            self.fill_rect.remove()
                            self.fill_rect = None
                        self.cursor1 = self.axes.axvline(color=self.text_color, linewidth=1)
                        self.cursor1.set_xdata(x)
                        if self.txt is not None:
                            self.txt.remove()
                            self.txt = None
                        self.click = 2
                    elif self.click == 2:
                        self.cursor2 = self.axes.axvline(color=self.text_color, linewidth=1)
                        self.cursor2.set_xdata(x)
                        try:
                            x_diff = math.floor(abs(self.cursor2.get_xdata() - self.cursor1.get_xdata()))
                            self.fill_rect = self.axes.add_patch(
                                matplotlib.patches.Rectangle(
                                    (math.floor(self.cursor1.get_xdata()), self.axes.get_ybound()[0]),
                                    x_diff,
                                    self.axes.get_ybound()[1] - self.axes.get_ybound()[0],
                                    facecolor="yellow",
                                    alpha=0.85,
                                )
                            )
                        except:
                            x_diff = math.floor(abs(self.cursor2.get_xdata()[0] - self.cursor1.get_xdata()[0]))
                            self.fill_rect = self.axes.add_patch(
                                matplotlib.patches.Rectangle(
                                    (math.floor(self.cursor1.get_xdata()[0]), self.axes.get_ybound()[0]),
                                    x_diff,
                                    self.axes.get_ybound()[1] - self.axes.get_ybound()[0],
                                    facecolor="yellow",
                                    alpha=0.85,
                                )
                            )
                        self.click = 1
                        if self.txt is None:
                            self.txt = self.axes.text(
                                0.01, 0.01, str(int(x_diff)), transform=self.axes.transAxes, color=self.text_color
                            )
                    self.draw()

                # Right Click
                if event.button == 3:
                    if self.cursor1 is None and self.cursor2 is None:
                        pass
                    else:
                        if self.click == 1:
                            self.cursor2.remove()
                            self.cursor2 = None
                            self.click = 2

                        elif self.click == 2:
                            self.cursor1.remove()
                            self.cursor1 = None
                            self.click = 1

                        # Remove Fill and Text
                        if self.fill_rect is not None:
                            self.fill_rect.remove()
                            self.fill_rect = None
                        if self.txt is not None:
                            self.txt.remove()
                            self.txt = None

                        self.draw()


class MPLEntropyCanvas(FigureCanvasQTAgg):
    def __init__(self, parent=None, dpi=100, title=None):
        """
        Creates a plot for the bit entropy data and places it in a figure canvas.
        """
        # Background Color
        background_color = (242.0 / 255, 241.0 / 255, 240.0 / 255, 1)  # QtGui.QColor(242,241,240)

        # Set up the Figure
        fig = matplotlib.pyplot.figure(dpi=dpi, facecolor=background_color)
        self.axes = fig.add_subplot(111)

        # ~ # Ignore hold() Deprecation Warnings
        # ~ with warnings.catch_warnings():
        # ~ warnings.simplefilter("ignore")
        # ~ warnings.filterwarnings("ignore", module="matplotlib")
        # ~ #self.axes.hold(False)  # FIX: To clear an axes you can manually use cla(),
        # ~ or to clear an entire figure use clf()

        fig.subplots_adjust(left=0.1, right=0.95, bottom=0.1, top=0.95, wspace=0, hspace=0)

        # Do the Plotting
        self.configureAxes(title, "Bit Position", "Entropy", None, None)

        # Other
        FigureCanvasQTAgg.__init__(self, fig)
        self.setParent(parent)
        FigureCanvasQTAgg.setSizePolicy(self, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        FigureCanvasQTAgg.updateGeometry(self)


    def configureAxes(self, title, xlabel, ylabel, ylabels, ylim):
        """
        Configures the axes, needs to be called for every plot because hold(False) will redo the axes setup.
        """
        try:
            # Define the Size
            # self.axes.axis([0, width, height, 0])

            # Set the Limits
            self.axes.set_ylim([-0.1, 1.1])

            # Set the Labels, Gridlines
            self.axes.set_title(title)

            self.axes.set_xlabel(xlabel)
            self.axes.xaxis.grid("on")

            self.axes.set_ylabel(ylabel)
            self.axes.yaxis.grid("on")
        except:
            pass
