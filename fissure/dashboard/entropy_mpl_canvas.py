from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from PyQt5 import QtWidgets

class EntropyMplCanvas(FigureCanvas):
    def __init__(self, parent=None, dpi=100, title=None):
        """ Creates a plot for the bit entropy data and places it in a figure canvas
        """
        # Background Color
        background_color = (242.0/255, 241.0/255, 240.0/255, 1)  #QtGui.QColor(242,241,240)

        # Set up the Figure
        fig = Figure(dpi=dpi, facecolor=background_color)
        self.axes = fig.add_subplot(111)

        # ~ # Ignore hold() Deprecation Warnings
        # ~ with warnings.catch_warnings():
            # ~ warnings.simplefilter("ignore")
            # ~ warnings.filterwarnings("ignore", module="matplotlib")
            # ~ #self.axes.hold(False)  # FIX: To clear an axes you can manually use cla(), or to clear an entire figure use clf()

        fig.subplots_adjust(left=0.1,right=0.95,bottom=0.1,top=0.95,wspace=0,hspace=0)

        # Do the Plotting
        self.configureAxes(title,'Bit Position','Entropy',None,None)

        # Other
        FigureCanvas.__init__(self, fig)
        self.setParent(parent)
        FigureCanvas.setSizePolicy(self, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        FigureCanvas.updateGeometry(self)

    def configureAxes(self, title, xlabel, ylabel, ylabels, ylim):
        """ Configures the axes, needs to be called for every plot because hold(False) will redo the axes setup
        """
        try:
            # Define the Size
            #self.axes.axis([0, width, height, 0])

            # Set the Limits
            self.axes.set_ylim([-.1, 1.1])

            # Set the Labels, Gridlines
            self.axes.set_title(title)

            self.axes.set_xlabel(xlabel)
            self.axes.xaxis.grid('on')

            self.axes.set_ylabel(ylabel)
            self.axes.yaxis.grid('on')
        except:
            pass
