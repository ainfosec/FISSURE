import math
import matplotlib.patches as patches

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from PyQt5 import QtWidgets

class MyIQ_MplCanvas(FigureCanvas):
    def __init__(self, parent=None, dpi=100, title=None, ylim=None, bg_color=None, face_color=None, text_color=None):
        """ Creates a plot for IQ data and places it in a figure canvas
        """
        # Set up the Figure
        self.fig = Figure(dpi=dpi)
        self.fig.subplots_adjust(left=0.1,right=0.95,bottom=0.1,top=0.94,wspace=0,hspace=0)

        # Do the Plotting
        self.polar_used = False
        self.configureAxes(False,bg_color,face_color,text_color)
        self.applyLabels(title,'Samples','Amplitude (LSB)',None,None,text_color)

        # Other
        FigureCanvas.__init__(self, self.fig)
        self.setParent(parent)
        FigureCanvas.setSizePolicy(self, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        FigureCanvas.updateGeometry(self)

        # Cursor
        self.cursor_enable = False
        self.cursor1 = None
        self.cursor2 = None
        self.fill_rect = None
        self.click = 1
        self.txt = None  #self.axes.text(0.0, 0.0, '', transform=self.axes.transAxes)
        self.text_color = text_color
        cid = self.fig.canvas.mpl_connect('button_press_event', self.onclick)

    def applyLabels(self, title, xlabel, ylabel, ylabels, ylim, text_color):
        """ Configures the axes, needs to be called for every plot because hold(False) will redo the axes setup
        """
        try:
            # Define the Size
            #self.axes.axis([0, width, height, 0])

            # Set the Labels, Gridlines
            #self.axes.set_title(title)

            self.axes.set_xlabel(xlabel,color=text_color)
            self.axes.xaxis.grid('on')

            self.axes.set_ylabel(ylabel,color=text_color)
            self.axes.yaxis.grid('on')

        except:
            pass

    def configureAxes(self,polar,background_color,face_color,text_color):
        """ Configures the axes after a polar/projection change. Must be done before plot. Gridlines and labels after plot.
        """
        # Plot Type
        self.fig.clear()  # Suppresses MatplotlibDeprecationWarning
        if polar:
            self.axes = self.fig.add_subplot(111,polar=True)
            self.polar_used = True
        else:
            self.axes = self.fig.add_subplot(111,polar=False)
            self.polar_used = False

        for item in ([self.axes.title, self.axes.xaxis.label, self.axes.yaxis.label] + self.axes.get_xticklabels() + self.axes.get_yticklabels()):
            item.set_fontsize(9)
            item.set_color(text_color)

        self.axes.set_facecolor(face_color)
        self.fig.set_facecolor(background_color)
        self.axes.tick_params(axis='x', colors=text_color)
        self.axes.tick_params(axis='y', colors=text_color)
        self.text_color = text_color

    def clearPlot(self):
        """ Clears the plot data.
        """
        for artist in self.axes.lines + self.axes.collections:
            artist.remove()
        self.cursor1 = None
        self.cursor2 = None
        self.fill_rect = None
        self.txt = None

    #def mouse_move(self, event):
        #if self.cursor_enable:
            ## Mouse Move Checkbox
            #if self.mouse_move_enable:
                #if not event.inaxes:
                    #return
                #x, y = event.xdata, event.ydata
                ##indx = min(np.searchsorted(self.x, x), len(self.x) - 1)
                ##x = self.x[indx]
                ##y = self.y[indx]
                ### update the line positions
                #self.lx.set_ydata(y)
                #self.ly.set_xdata(x)
                #self.axes.figure.canvas.draw()

    def onclick(self,event):
        """ Called when the mouse is clicked on Tuning figure
        """
        if self.cursor_enable:
            # Valid Click
            if event.xdata != None:

                # Left Click
                if event.button == 1:
                    x = event.xdata
                    if self.click == 1:
                        if self.cursor1 != None:
                            self.cursor1.remove()
                        if self.cursor2 != None:
                            self.cursor2.remove()
                        if self.fill_rect != None:
                            self.fill_rect.remove()
                            self.fill_rect = None
                        self.cursor1 = self.axes.axvline(color=self.text_color,linewidth=1)
                        self.cursor1.set_xdata(x)
                        if self.txt != None:
                            self.txt.remove()
                            self.txt = None
                        self.click = 2
                    elif self.click == 2:
                        self.cursor2 = self.axes.axvline(color=self.text_color,linewidth=1)
                        self.cursor2.set_xdata(x)
                        try:
                            x_diff = math.floor(abs(self.cursor2.get_xdata()-self.cursor1.get_xdata()))
                            self.fill_rect = self.axes.add_patch(patches.Rectangle((math.floor(self.cursor1.get_xdata()),self.axes.get_ybound()[0]),x_diff,self.axes.get_ybound()[1]-self.axes.get_ybound()[0],facecolor="yellow",alpha=0.85))
                        except:
                            x_diff = math.floor(abs(self.cursor2.get_xdata()[0]-self.cursor1.get_xdata()[0]))
                            self.fill_rect = self.axes.add_patch(patches.Rectangle((math.floor(self.cursor1.get_xdata()[0]),self.axes.get_ybound()[0]),x_diff,self.axes.get_ybound()[1]-self.axes.get_ybound()[0],facecolor="yellow",alpha=0.85))
                        self.click = 1
                        if self.txt == None:
                            self.txt = self.axes.text(0.01, 0.01, str(int(x_diff)), transform=self.axes.transAxes, color=self.text_color)
                    self.draw()

                # Right Click
                if event.button == 3:
                    if self.cursor1 == None and self.cursor2 == None:
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
                        if self.fill_rect != None:
                            self.fill_rect.remove()
                            self.fill_rect = None
                        if self.txt != None:
                            self.txt.remove()
                            self.txt = None

                        self.draw()

