from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from PyQt5 import QtWidgets
import matplotlib.patches as patches


class MyTuningMplCanvas(FigureCanvas):
    def __init__(self, parent=None, dpi=100, title=None, ylim=None, bg_color=None, face_color=None, text_color=None):
        """ Class for creating the tuning graphic
        """
        self.plot_width = 601
        self.plot_height = 401

        # Set up the Figure
        fig = Figure(dpi=dpi)
        self.fig = fig

        self.axes = fig.add_axes([0.03, 0.25, 0.94, 0.8])
        #self.axes.axis('off')
        self.axes.spines['top'].set_visible(False)
        self.axes.spines['right'].set_visible(False)
        #self.axes.spines['bottom'].set_visible(False)
        self.axes.spines['left'].set_visible(False)

        # Remove the Colors
        #fig.frameon = False
        #for item in [fig, self.axes]:
            #item.patch.set_visible(False)  # Makes it white instead of transparent in newer version

        # Configure Axes
        self.configureAxes(title=title,xlabel='Frequency (MHz)',ylabel='',ylabels='',ylim=ylim,background_color=bg_color,face_color=face_color,text_color=text_color)

        # Other
        FigureCanvas.__init__(self, fig)
        self.setParent(parent)
        FigureCanvas.setSizePolicy(self, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        FigureCanvas.updateGeometry(self)

        cid = fig.canvas.mpl_connect('button_press_event', self.onclick)
        #fig.canvas.mpl_connect('axes_enter_event', self.enter_axes)
        fig.canvas.mpl_connect('axes_leave_event', self.leave_axes)
        fig.canvas.mpl_connect('motion_notify_event', self.on_motion)

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
        """ Updates the location of the tuned rectangle.
        """
        # Delete Existing Rectangle
        if self.tuned != None:
            self.tuned.remove()
            del self.tuned

        # Draw New Rectangle
        current_freq = float(current_freq)/10
        bandwidth = float(bandwidth)/10
        self.tuned = self.axes.add_patch(patches.Rectangle((current_freq-(bandwidth/2), (self.band_height*(current_band))),bandwidth,self.band_height,facecolor="yellow",alpha=0.85))
        self.draw()

    def onclick(self,event):
        """ Called when the mouse is clicked on Tuning figure
        """
        # Valid Click
        if event.xdata != None:

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
                        h = self.axes.add_patch(patches.Rectangle((self.first_point, (self.band_height*(len(self.bands)+1))),self.second_point-self.first_point,self.band_height,facecolor="red",edgecolor="Black"))
                        self.bands.append(h)
                        self.first_click = self.first_point*10
                        self.second_click = self.second_point*10

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

    #def enter_axes(self, event):
        #""" Called when the mouse enters the Tuning axes
        #"""
        #print('enter_axes', event.inaxes)
        #self.draw()

    def leave_axes(self, event):
        """ Called when the mouse leaves the Tuning axes
        """
        # Hide the Mouseover Text
        text_x = int(self.axes.get_xlim()[0]) + 1
        for txt in self.axes.texts:
            if txt.get_position() == (text_x,500):
                txt.remove()

        self.draw()

    def on_motion(self, event):
        """ Gets the mouse over coordinates upon movement
        """
        if event.inaxes:
            xpos = event.xdata
            freq_text = (str(int(xpos*10)))

            text_x = int(self.axes.get_xlim()[0]) + 1

            # Delete Old Text
            for txt in self.axes.texts:
                if txt.get_position() == (text_x,500):
                    txt.remove()

            # Draw New Text
            self.axes.text(text_x,500,freq_text,fontsize=11,bbox=dict(facecolor='red', alpha=0.5))
            self.draw()

    def configureAxes(self, title, xlabel, ylabel, ylabels, ylim,background_color,face_color,text_color):
        """ Configures the axes, needs to be called for every plot because hold(False) will redo the axes setup
        """
        # Define the Size
        self.axes.axis([0, self.plot_width, self.plot_height, 0])

        # xlim
        self.axes.set_xlim([0, 601])

        # xtick Locations
        xspan = 6000
        steps = 6
        xstep = float(xspan)/steps
        xticks = []
        for n in range(0,steps):
            xticks.append(int(n*(xstep/10)))
        xticks.append(600)
        self.axes.set_xticks(xticks)

        # xtick Labels
        xlabels = ['0', '1000', '2000', '3000', '4000', '5000', '6000']
        self.axes.set_xticklabels(xlabels)

        # xaxis Label
        self.axes.set_xlabel(xlabel)

        # Title
        self.axes.set_title(title)

        # Grid
        self.axes.xaxis.grid('on')
        self.axes.set_axisbelow(True)

        # Y Values
        self.axes.set_ylim([ylim, 0])
        self.axes.set_ylabel(ylabel)
        self.axes.set_yticks([x*100 for x in (range(0,len(ylabels)))], minor=False)
        self.axes.set_yticklabels(ylabels)
        self.axes.yaxis.grid('on')

        # Font Size
        for item in ([self.axes.title, self.axes.xaxis.label, self.axes.yaxis.label] + self.axes.get_xticklabels() + self.axes.get_yticklabels()):
            item.set_fontsize(9)
            item.set_color(text_color)

        self.axes.set_facecolor(face_color)
        self.fig.set_facecolor(background_color)
        self.axes.tick_params(axis='x', colors=text_color)
        self.axes.tick_params(axis='y', colors=text_color)

    # ~ def configureAxes(self, title, xlabel, ylabel, ylabels, ylim):
        # ~ """ Configures the axes, needs to be called for every plot because hold(False) will redo the axes setup
        # ~ """
        # ~ # Define the Size
        # ~ self.axes.axis([0, self.plot_width, self.plot_height, 0])

        # ~ # xlim
        # ~ self.axes.set_xlim([0, 601])

        # ~ # xtick Locations
        # ~ xspan = 6000
        # ~ steps = 6
        # ~ xstep = float(xspan)/steps
        # ~ xticks = []
        # ~ for n in range(0,steps):
            # ~ xticks.append(int(n*(xstep/10)))
        # ~ xticks.append(600)
        # ~ self.axes.set_xticks(xticks)

        # ~ # xtick Labels
        # ~ xlabels = ['0', '1000', '2000', '3000', '4000', '5000', '6000']
        # ~ self.axes.set_xticklabels(xlabels)

        # ~ # xaxis Label
        # ~ self.axes.set_xlabel(xlabel)

        # ~ # Title
        # ~ self.axes.set_title(title)

        # ~ # Grid
        # ~ self.axes.xaxis.grid('on')
        # ~ self.axes.set_axisbelow(True)

        # ~ # Y Values
        # ~ self.axes.set_ylim([ylim, 0])
        # ~ self.axes.set_ylabel(ylabel)
        # ~ self.axes.set_yticks([x*100 for x in (range(0,len(ylabels)))], minor=False)
        # ~ self.axes.set_yticklabels(ylabels)
        # ~ self.axes.yaxis.grid('on')

        # ~ # Font Size
        # ~ for item in ([self.axes.title, self.axes.xaxis.label, self.axes.yaxis.label] + self.axes.get_xticklabels() + self.axes.get_yticklabels()):
            # ~ item.set_fontsize(9)

    def configureAxesZoom(self, xmin, xmax):
        """ Configures the axes, needs to be called for every plot because hold(False) will redo the axes setup
        """
        # Define the Size
        self.axes.axis([0, self.plot_width, self.plot_height, 0])

        # xlim
        self.axes.set_xlim([int(xmin/1e6)/10, 1+int(xmax/1e6)/10])

        # xtick Locations
        xspan = int(xmax/1e6)-int(xmin/1e6)
        steps = 10
        xstep = float(xspan)/steps
        xticks = []
        for n in range(0,steps):
            xticks.append(float((xmin/10e6)+n*(xstep/10)))
        xticks.append(float((xmax/10e6)))
        self.axes.set_xticks(xticks)

        # xlabels
        xlabels = []
        for n in range(0,steps+1):
            xlabels.append(str(int(xticks[n]*10)))
        self.axes.set_xticklabels(xlabels)

        # Grid
        self.axes.xaxis.grid('on')

        # Font Size
        for item in ([self.axes.title, self.axes.xaxis.label, self.axes.yaxis.label] + self.axes.get_xticklabels() + self.axes.get_yticklabels()):
            item.set_fontsize(9)

        # Draw
        self.draw()

