import numpy as np
from matplotlib import cm
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from PyQt5 import QtWidgets

class MyMplCanvas(FigureCanvas):
    def __init__(self, parent=None, dpi=100, title=None, ylim=None, width=401, height=401, border = [0.1,0.9,0.01,0.99,0,0], colorbar_fraction = 0.038, xlabels=['0', '','1000', '', '2000', '', '3000', '', '4000', '', '5000', '', '6000'], ylabels=['0', '5', '10', '15', '20'], bg_color=None, face_color=None, text_color=None):
        """ Creates a plot with colorbar and places it in a figure canvas
        """
        self.plot_width = width
        self.plot_height = height

        # Background Color
        rgb = tuple(int(face_color.lstrip('#')[i:i+2], 16) for i in (0, 2, 4))
        background_color = (float(rgb[0])/255, float(rgb[1])/255, float(rgb[2])/255)

        # Set up the Figure
        self.fig = Figure(dpi=dpi)
        self.axes = self.fig.add_subplot(111)

        self.fig.subplots_adjust(left=border[0],right=border[1],bottom=border[2],top=border[3],wspace=border[4],hspace=border[5])

        # Create the Data Arrays
        temp_plot_data = np.ones((self.plot_height,self.plot_width,3))*background_color  # background color (1,1,1)

        # Do the Plotting
        img = self.axes.imshow(temp_plot_data, cmap='rainbow', clim=(-60,40))
        self.cbar = self.fig.colorbar(img, fraction=colorbar_fraction*ylim/500, pad=.04)
        self.configureAxes(title,'Frequency (MHz)',xlabels,'Time Elapsed',ylabels,ylim,bg_color,face_color,text_color)

        # ~ # Do the Plotting
        # ~ img = self.axes.imshow(temp_plot_data, cmap='rainbow', clim=(-60,40))
        # ~ self.configureAxes(title,'Frequency (MHz)',xlabels,'Time Elapsed',ylabels,ylim)
        # ~ cbar = fig.colorbar(img, fraction=colorbar_fraction*ylim/500, pad=.04, label='Power (dB)')
        # ~ cbar.ax.tick_params(labelsize=11)

        # Other
        FigureCanvas.__init__(self, self.fig)
        self.setParent(parent)
        FigureCanvas.setSizePolicy(self, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        FigureCanvas.updateGeometry(self)

    def configureAxesZoom1(self, xmin, xmax, wideband_height):
        """ Configures the axes for wideband zoom. Not implemented yet.
        """
        try:
            # Define the Size
            self.axes.axis([0, self.plot_width, self.plot_height, 0])

            # Font
            #axis_font = {'fontname':'DejaVu Sans', 'size':'11'}
            #axis_font = {'size':'11'}

            # xlim
            #xlim1 = int(xmin/1e6)/5 #  (number/6000)*1200
            #xlim2 = 1+int(xmax/1e6)/5
            #self.axes.set_xlim([xlim1, xlim2])
            #print(self.axes.get_xlim())

            # xtick Locations
            xspan = int(xmax/1e6)-int(xmin/1e6)
            steps = 12
            xstep = float(xspan)/steps/5
            xticks = []
            for n in range(0,steps):
                xticks.append(float((xmin/1e6)/5+n*(xstep/1)))
                #print(float((xmin/1e6)/5+n*(xstep/1)))
            xticks.append(float((xmax/1e6))/5)
            #self.axes.set_xticks(xticks)
            start, end = self.axes.get_xlim()
            self.axes.set_xticks(np.arange(start,end,100))

            # xticklabels
            xlabels = []
            for n in range(0,steps+1):
                xlabels.append(str(int(xticks[n]*5)))
            self.axes.set_xticklabels(xlabels)

            # xlabel
            self.axes.set_xlabel('Frequency (MHz)')

            # ylim
            self.axes.set_ylim([wideband_height, 0])

            # yticks
            start, end = self.axes.get_ylim()
            self.axes.set_yticks(np.arange(end,start,100))

            # yticklabels
            ylabels = ['0', '5', '10', '15', '20', '25', '30', '35', '40']
            self.axes.set_yticklabels(ylabels[0:len(np.arange(end,start,100))])
            self.axes.yaxis.grid('on')

            # ylabel
            self.axes.set_ylabel('Time Elapsed (s)')

            # Grid
            self.axes.xaxis.grid('on')
            self.axes.yaxis.grid('on')

            # Font Size
            for item in ([self.axes.title, self.axes.xaxis.label, self.axes.yaxis.label] + self.axes.get_xticklabels() + self.axes.get_yticklabels()):
                item.set_fontsize(9)


        ########################################

        #title='Detector History',xlabel='Frequency (MHz)',ylabel='Time Elapsed (s)', xlabels=['0', '','1000', '', '2000', '', '3000', '', '4000', '', '5000', '', '6000'],ylabels=['0', '5', '10', '15', '20', '25', '30', '35', '40'],ylim=wideband_height

        # Font Size
        #for item in ([self.axes.title, self.axes.xaxis.label, self.axes.yaxis.label] + self.axes.get_xticklabels() + self.axes.get_yticklabels()):
            #item.set_fontsize(11)

        # Set the Labels, Gridlines
        #axis_font = {'fontname':'Bitstream Vera Sans', 'size':'12'}

        #self.axes.set_xlabel(xlabel, **axis_font)

        #start, end = self.axes.get_xlim()
        #self.axes.set_xticks(np.arange(start,end,100))

        #self.axes.set_xticklabels(xlabels[0:len(np.arange(start,end,100))])
        #self.axes.xaxis.grid('on')

        #self.axes.set_ylim([ylim, 0])
        #self.axes.set_ylabel(ylabel, **axis_font)

        #start, end = self.axes.get_ylim()
        #self.axes.set_yticks(np.arange(end,start,100))

        #self.axes.set_yticklabels(ylabels[0:len(np.arange(end,start,100))])


        except:
            pass


    def plotPoint(self, x, y, color, point_size, wideband_data):
        """ Plots a wideband signal
        """
        # Colors in Pixels Surrounding a Point, (r,g,b) Color Values are Normalized (0-1)
        wideband_data[int(y)-10:int(y)+10, 2*int(x)-point_size:2*int(x)+point_size] = color


    # def plotNarrowbandPoint(self, x, y, color, point_size, narrowband_data):
        # """ Plots a narrowband signal
        # """
        # # Colors in Pixels Surrounding a Point, (r,g,b) Color Values are Normalized (0-1)
        # narrowband_data[int(y)-point_size:int(y)+point_size, 4*int(x)-point_size:4*int(x)+point_size] = color


    def configureAxes(self, title, xlabel, xlabels, ylabel, ylabels, ylim, background_color, face_color, text_color):
        """ Configures the axes, needs to be called for every plot because hold(False) will redo the axes setup
        """
        try:
            # Define the Size
            self.axes.axis([0, self.plot_width, self.plot_height, 0])

            self.axes.set_xlabel(xlabel)

            start, end = self.axes.get_xlim()
            self.axes.set_xticks(np.arange(start,end,100))

            self.axes.set_xticklabels(xlabels[0:len(np.arange(start,end,100))])
            self.axes.xaxis.grid('on')

            self.axes.set_ylim([ylim, 0])
            self.axes.set_ylabel(ylabel)

            start, end = self.axes.get_ylim()
            self.axes.set_yticks(np.arange(end,start,100))

            self.axes.set_yticklabels(ylabels[0:len(np.arange(end,start,100))])
            self.axes.yaxis.grid('on')

            for item in ([self.axes.title, self.axes.xaxis.label, self.axes.yaxis.label] + self.axes.get_xticklabels() + self.axes.get_yticklabels()):
                item.set_fontsize(9)
                item.set_color(text_color)

            self.fig.set_facecolor(background_color)
            self.cbar.ax.tick_params(labelsize=11, color=text_color)
            plt.setp(plt.getp(self.cbar.ax.axes, 'yticklabels'), color=text_color)
            self.cbar.set_label(label='Power (dB)',color=text_color)
            self.axes.tick_params(axis='x', colors=text_color)
            self.axes.tick_params(axis='y', colors=text_color)

        except:
            pass

        # ~ try:
            # ~ # Define the Size
            # ~ self.axes.axis([0, self.plot_width, self.plot_height, 0])

            # ~ # Set the Labels, Gridlines
            # ~ #axis_font = {'fontname':'Bitstream Vera Sans', 'size':'12'}
            # ~ #axis_font = {'fontname':'DejaVu Sans', 'size':'11'}
            # ~ #axis_font = {'size':'11'}

            # ~ self.axes.set_xlabel(xlabel)

            # ~ start, end = self.axes.get_xlim()
            # ~ self.axes.set_xticks(np.arange(start,end,100))

            # ~ self.axes.set_xticklabels(xlabels[0:len(np.arange(start,end,100))])
            # ~ self.axes.xaxis.grid('on')

            # ~ self.axes.set_ylim([ylim, 0])
            # ~ self.axes.set_ylabel(ylabel)

            # ~ start, end = self.axes.get_ylim()
            # ~ self.axes.set_yticks(np.arange(end,start,100))

            # ~ self.axes.set_yticklabels(ylabels[0:len(np.arange(end,start,100))])
            # ~ self.axes.yaxis.grid('on')

            # ~ for item in ([self.axes.title, self.axes.xaxis.label, self.axes.yaxis.label] + self.axes.get_xticklabels() + self.axes.get_yticklabels()):
                # ~ item.set_fontsize(9)

        # ~ except:
            # ~ pass

    def computeColormapValue(self, power_level):
        """ Takes the power level in dBm, normalizes it to the colorbar limits, and then looks up the corresponding
            color value in the colormap array
        """
        # Colorbar Limits
        min_power = -60
        max_power = 40

        # Normalize to the Colorbar Limits
        computed_power_level = 1*(power_level-min_power)/(max_power-min_power)

        # Look up the Value in the 256 Length Colormap Array
        colormap_value = cm.rainbow(computed_power_level)[0:3]

        return colormap_value
