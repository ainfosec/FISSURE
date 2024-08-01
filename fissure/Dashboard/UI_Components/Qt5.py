from . import UI_Types
from .MPL import MPLEntropyCanvas
from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT
from PyQt5 import QtCore, QtGui, QtWidgets
import fissure.utils


import ast
import os
import subprocess
import yaml
import asyncio
import qasync


class MiscChooser(QtWidgets.QDialog, UI_Types.Chooser):
    def __init__(self, parent, label_text, chooser_items):
        """
        Multi-purpose combobox.
        """
        QtWidgets.QDialog.__init__(self, parent)
        self.parent = parent
        self.setupUi(self)
        self.return_value = ""

        # Prevent Resizing/Maximizing
        self.setFixedSize(205, 120)

        # Connect Slots
        self.pushButton_ok.clicked.connect(self._slotOK_Clicked)
        self.pushButton_cancel.clicked.connect(self._slotCancelClicked)

        # Update Label Text
        self.label1_1.setText(label_text)

        # Update Combobox Items
        self.comboBox_1.addItems(chooser_items)


    def _slotOK_Clicked(self):
        self.return_value = str(self.comboBox_1.currentText())
        self.close()


    def _slotCancelClicked(self):
        self.reject()


class NewSOI(QtWidgets.QDialog, UI_Types.New_SOI):
    def __init__(self, parent):
        """
        Creates a new Signal of Interest in Protocol Discovery.
        """
        QtWidgets.QDialog.__init__(self, parent)
        self.parent = parent
        self.setupUi(self)
        self.return_value = ""

        # Prevent Resizing/Maximizing
        self.setFixedSize(380, 300)

        # Connect Slots
        self.pushButton_ok.clicked.connect(self._slotOK_Clicked)
        self.pushButton_cancel.clicked.connect(self._slotCancelClicked)

        # Fill in Default Values as Last SOI
        if len(self.parent.target_soi) > 0:
            self.textEdit_frequency.setPlainText(str(self.parent.target_soi[0]))
            self.textEdit_modulation.setPlainText(str(self.parent.target_soi[1]))
            self.textEdit_bandwidth.setPlainText(str(self.parent.target_soi[2]))

            if self.parent.target_soi[3] == "True":
                self.comboBox_continuous.setCurrentIndex(0)
            else:
                self.comboBox_continuous.setCurrentIndex(1)

            self.textEdit_start_frequency.setPlainText(str(self.parent.target_soi[4]))
            self.textEdit_end_frequency.setPlainText(str(self.parent.target_soi[5]))
            self.textEdit_notes.setPlainText(str(self.parent.target_soi[6]))


    def _slotOK_Clicked(self):
        self.return_value = "1"

        # Assemble the Target SOI
        get_frequency = str(self.textEdit_frequency.toPlainText())
        get_modulation = str(self.textEdit_modulation.toPlainText())
        get_bandwidth = str(self.textEdit_bandwidth.toPlainText())
        get_continuous = str(self.comboBox_continuous.currentText())
        get_start_frequency = str(self.textEdit_start_frequency.toPlainText())
        get_end_frequency = str(self.textEdit_end_frequency.toPlainText())
        get_notes = str(self.textEdit_notes.toPlainText())

        self.parent.target_soi = [
            get_frequency,
            get_modulation,
            get_bandwidth,
            get_continuous,
            get_start_frequency,
            get_end_frequency,
            get_notes,
        ]
        self.close()


    def _slotCancelClicked(self):
        self.reject()


class CustomColor(QtWidgets.QDialog, UI_Types.CustomColor):
    def __init__(self, parent):
        """
        Allows user to choose values for custom color themes.
        """
        QtWidgets.QDialog.__init__(self, parent)
        self.parent = parent
        self.setupUi(self)
        self.return_value = ""

        # Prevent Resizing/Maximizing
        self.setFixedSize(390, 525)

        # Connect Slots
        self.pushButton_ok.clicked.connect(self._slotOK_Clicked)
        self.pushButton_cancel.clicked.connect(self._slotCancelClicked)
        self.pushButton_color1.clicked.connect(lambda: self._slotColor_Clicked(self.textEdit_color1))
        self.pushButton_color2.clicked.connect(lambda: self._slotColor_Clicked(self.textEdit_color2))
        self.pushButton_color3.clicked.connect(lambda: self._slotColor_Clicked(self.textEdit_color3))
        self.pushButton_color4.clicked.connect(lambda: self._slotColor_Clicked(self.textEdit_color4))
        self.pushButton_color5.clicked.connect(lambda: self._slotColor_Clicked(self.textEdit_color5))
        self.pushButton_color6.clicked.connect(lambda: self._slotColor_Clicked(self.textEdit_color6))
        self.pushButton_color7.clicked.connect(lambda: self._slotColor_Clicked(self.textEdit_color7))
        self.pushButton_color8.clicked.connect(lambda: self._slotColor_Clicked(self.textEdit_color8))
        self.pushButton_color9.clicked.connect(lambda: self._slotColor_Clicked(self.textEdit_color9))
        self.pushButton_color10.clicked.connect(lambda: self._slotColor_Clicked(self.textEdit_color10))
        self.pushButton_color11.clicked.connect(lambda: self._slotColor_Clicked(self.textEdit_color11))
        self.pushButton_color12.clicked.connect(lambda: self._slotColor_Clicked(self.textEdit_color12))
        self.pushButton_color13.clicked.connect(lambda: self._slotColor_Clicked(self.textEdit_color13))

        self.comboBox_autofill.currentIndexChanged.connect(self._slotAutofillChanged)

        # Fill in Default Values
        self.comboBox_autofill.setCurrentIndex(2)
        self._slotAutofillChanged()

    def _slotAutofillChanged(self):
        """
        Populate the values on launch and after selecting autofill option.
        """
        if str(self.comboBox_autofill.currentText()) == "Custom":
            if len(self.parent.backend.settings["color1"]) == 7:
                self.textEdit_color1.setPlainText(str(self.parent.backend.settings["color1"]))
            if len(self.parent.backend.settings["color2"]) == 7:
                self.textEdit_color2.setPlainText(str(self.parent.backend.settings["color2"]))
            if len(self.parent.backend.settings["color3"]) == 7:
                self.textEdit_color3.setPlainText(str(self.parent.backend.settings["color3"]))
            if len(self.parent.backend.settings["color4"]) == 7:
                self.textEdit_color4.setPlainText(str(self.parent.backend.settings["color4"]))
            if len(self.parent.backend.settings["color5"]) == 7:
                self.textEdit_color5.setPlainText(str(self.parent.backend.settings["color5"]))
            if len(self.parent.backend.settings["color6"]) == 7:
                self.textEdit_color6.setPlainText(str(self.parent.backend.settings["color6"]))
            if len(self.parent.backend.settings["color7"]) == 7:
                self.textEdit_color7.setPlainText(str(self.parent.backend.settings["color7"]))
            if len(self.parent.backend.settings["color8"]) == 7:
                self.textEdit_color8.setPlainText(str(self.parent.backend.settings["color8"]))
            if len(self.parent.backend.settings["color9"]) == 7:
                self.textEdit_color9.setPlainText(str(self.parent.backend.settings["color9"]))
            if len(self.parent.backend.settings["color10"]) == 7:
                self.textEdit_color10.setPlainText(str(self.parent.backend.settings["color10"]))
            if len(self.parent.backend.settings["color11"]) == 7:
                self.textEdit_color11.setPlainText(str(self.parent.backend.settings["color11"]))
            if len(self.parent.backend.settings["color12"]) == 7:
                self.textEdit_color12.setPlainText(str(self.parent.backend.settings["color12"]))
            if len(self.parent.backend.settings["color13"]) == 7:
                self.textEdit_color13.setPlainText(str(self.parent.backend.settings["color13"]))
            if self.parent.backend.settings["icon_style"] == "Light":
                self.comboBox_icon_style.setCurrentIndex(0)
            else:
                self.comboBox_icon_style.setCurrentIndex(1)

        elif str(self.comboBox_autofill.currentText()) == "Light":
            self.textEdit_color1.setPlainText("#F4F4F4")
            self.textEdit_color2.setPlainText("#FBFBFB")
            self.textEdit_color3.setPlainText("#17365D")
            self.textEdit_color4.setPlainText("#000000")
            self.textEdit_color5.setPlainText("#FFFFFF")
            self.textEdit_color6.setPlainText("#FEFEFE")
            self.textEdit_color7.setPlainText("#EFEFEF")
            self.textEdit_color8.setPlainText("#FEFEFE")
            self.textEdit_color9.setPlainText("#EFEFEF")
            self.textEdit_color10.setPlainText("#FEFEFE")
            self.textEdit_color11.setPlainText("#F8F8F8")
            self.textEdit_color12.setPlainText("#000000")
            self.textEdit_color13.setPlainText("#C0C0C0")
            self.comboBox_icon_style.setCurrentIndex(0)

        elif str(self.comboBox_autofill.currentText()) == "Dark":
            self.textEdit_color1.setPlainText("#121212")
            self.textEdit_color2.setPlainText("#292929")
            self.textEdit_color3.setPlainText("#002D63")
            self.textEdit_color4.setPlainText("#CCCCCC")
            self.textEdit_color5.setPlainText("#444444")
            self.textEdit_color6.setPlainText("#AAAAAA")
            self.textEdit_color7.setPlainText("#666666")
            self.textEdit_color8.setPlainText("#DDDDDD")
            self.textEdit_color9.setPlainText("#999999")
            self.textEdit_color10.setPlainText("#AFAFAF")
            self.textEdit_color11.setPlainText("#6F6F6F")
            self.textEdit_color12.setPlainText("#000000")
            self.textEdit_color13.setPlainText("#666666")
            self.comboBox_icon_style.setCurrentIndex(1)


    def _slotOK_Clicked(self):
        """
        Saves the color values and closes the dialog.
        """
        self.return_value = "1"

        # Save the Colors
        get_color1 = str(self.textEdit_color1.toPlainText())
        get_color2 = str(self.textEdit_color2.toPlainText())
        get_color3 = str(self.textEdit_color3.toPlainText())
        get_color4 = str(self.textEdit_color4.toPlainText())
        get_color5 = str(self.textEdit_color5.toPlainText())
        get_color6 = str(self.textEdit_color6.toPlainText())
        get_color7 = str(self.textEdit_color7.toPlainText())
        get_color8 = str(self.textEdit_color8.toPlainText())
        get_color9 = str(self.textEdit_color9.toPlainText())
        get_color10 = str(self.textEdit_color10.toPlainText())
        get_color11 = str(self.textEdit_color11.toPlainText())
        get_color12 = str(self.textEdit_color12.toPlainText())
        get_color13 = str(self.textEdit_color13.toPlainText())
        get_icon_style = str(self.comboBox_icon_style.currentText())
        if len(get_color1) == 7:  # "#123456/#RRGGBB"
            self.parent.backend.settings["color1"] = get_color1
        if len(get_color2) == 7:
            self.parent.backend.settings["color2"] = get_color2
        if len(get_color3) == 7:
            self.parent.backend.settings["color3"] = get_color3
        if len(get_color4) == 7:
            self.parent.backend.settings["color4"] = get_color4
        if len(get_color5) == 7:
            self.parent.backend.settings["color5"] = get_color5
        if len(get_color6) == 7:
            self.parent.backend.settings["color6"] = get_color6
        if len(get_color7) == 7:
            self.parent.backend.settings["color7"] = get_color7
        if len(get_color8) == 7:
            self.parent.backend.settings["color8"] = get_color8
        if len(get_color9) == 7:
            self.parent.backend.settings["color9"] = get_color9
        if len(get_color10) == 7:
            self.parent.backend.settings["color10"] = get_color10
        if len(get_color11) == 7:
            self.parent.backend.settings["color11"] = get_color11
        if len(get_color12) == 7:
            self.parent.backend.settings["color12"] = get_color12
        if len(get_color13) == 7:
            self.parent.backend.settings["color13"] = get_color13
        self.parent.backend.settings["icon_style"] = get_icon_style

        self.close()


    def _slotCancelClicked(self):
        """
        Closes the dialog without saving changes.
        """
        self.reject()


    def _slotColor_Clicked(self, textEdit_widget):
        """
        Opens the color selector for a color type.
        """
        # Open the Selector
        get_color = QtWidgets.QColorDialog.getColor()
        if get_color.isValid():
            textEdit_widget.setPlainText(str(get_color.name()).upper())


class MyPlotWindow(QtWidgets.QDialog):
    def __init__(self, parent=None, entropy_data=None, width=700, height=700):
        QtWidgets.QDialog.__init__(self)
        # ~ label = QtWidgets.QLabel(self)
        # ~ label.setText(my_text)
        scroll = QtWidgets.QScrollArea(self)
        scroll.setGeometry(QtCore.QRect(0, 0, width, height))
        # ~ scroll.setWidget(label)
        scroll.setWidgetResizable(True)

        okButton = QtWidgets.QPushButton("OK", self)
        okButton.clicked.connect(self.closeWindow)
        okButton.setGeometry(QtCore.QRect(300, 650, 100, 30))

        # Create Matplotlib Widget
        entropy_mpl_widget = MPLEntropyCanvas(self)
        # ~ entropy_mpl_widget.move(0,0)
        entropy_mpl_widget.setGeometry(50, 0, 600, 600)

        # Add a Toolbar
        mpl_toolbar = NavigationToolbar2QT(entropy_mpl_widget, self)
        mpl_toolbar.setGeometry(QtCore.QRect(175, 600, 525, 35))
        icons_buttons = {
            "Home": QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons","home.png")),
            "Pan": QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons","move.png")),
            "Zoom": QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons","zoom_to_rect.png")),
            "Back": QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons","back.png")),
            "Forward": QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons","forward.png")),
            "Subplots": QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons","subplots.png")),
            "Customize": QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons","qt4_editor_options.png")),
            "Save": QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons","filesave.png")),
        }
        for action in mpl_toolbar.actions():
            if action.text() in icons_buttons:
                action.setIcon(icons_buttons.get(action.text(), QtGui.QIcon()))

        # Plot the Data
        entropy_mpl_widget.axes.plot(range(0, len(entropy_data)), entropy_data, label="pre (default)", marker=".")
        entropy_mpl_widget.configureAxes("Bit Position Entropy Values", "Bit Position", "Entropy", None, None)
        entropy_mpl_widget.draw()


    def closeWindow(self):
        self.accept()


class MyMessageBox(QtWidgets.QDialog):
    def __init__(self, parent=None, my_text="", width=480, height=600):
        QtWidgets.QDialog.__init__(self)
        label = QtWidgets.QLabel(self)
        label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        label.setText(my_text)
        scroll = QtWidgets.QScrollArea(self)
        scroll.setGeometry(QtCore.QRect(10, 20, width, height))
        scroll.setWidget(label)
        scroll.setWidgetResizable(True)
        okButton = QtWidgets.QPushButton(self)
        okButton.clicked.connect(self.closeWindow)
        okButton.setGeometry(QtCore.QRect(int(width / 2 - 40), height + 30, 100, 30))
        okButton.setText("OK")


    def setDimensions(self, new_width, new_height):
        """Resizes the dialog window."""
        self.width = new_width
        # height = new_height


    def closeWindow(self):
        self.accept()


class SigMF_Dialog(QtWidgets.QDialog, UI_Types.SigMF):
    def __init__(self, parent=None, sample_rate=None, hw=None, dataset=None, frequency=None, settings_dictionary=None):
        """
        First thing that executes.
        """
        QtWidgets.QDialog.__init__(self, parent)
        self.setupUi(self)
        self.return_value = ""

        self.settings_dictionary = settings_dictionary

        # Prevent Resizing/Maximizing
        self.setFixedSize(800, 600)

        # Tooltips
        self.checkBox_global_datatype.setToolTip("The SigMF Dataset format of the stored samples in the Dataset file.")
        self.checkBox_global_sample_rate.setToolTip("The sample rate of the signal in samples per second.")
        self.checkBox_global_version.setToolTip(
            "The version of the SigMF specification used to create the Metadata file."
        )
        self.checkBox_global_num_channels.setToolTip(
            "Total number of interleaved channels in the Dataset file. If omitted, this defaults to one."
        )
        self.checkBox_global_sha512.setToolTip("The SHA512 hash of the Dataset file associated with the SigMF file.")
        self.checkBox_global_offset.setToolTip(
            "The index number of the first sample in the Dataset. If not provided, this value defaults to zero. "
            "Typically used when a Recording is split over multiple files. All sample indices in SigMF are "
            "absolute, and so all other indices referenced in metadata for this recording SHOULD be greater "
            "than or equal to this value."
        )
        self.checkBox_global_description.setToolTip("A text description of the SigMF Recording.")
        self.checkBox_global_author.setToolTip(
            "A text identifier for the author potentially including name, handle, email, and/or other ID like "
            'Amateur Call Sign. For example "Bruce Wayne bruce@waynetech.com" or "Bruce (K3X)".'
        )
        self.checkBox_global_meta_doi.setToolTip("The registered DOI (ISO 26324) for a Recording's Metadata file.")
        self.checkBox_global_doi.setToolTip("The registered DOI (ISO 26324) for a Recording's Dataset file.")
        self.checkBox_global_recorder.setToolTip("The name of the software used to make this SigMF Recording.")
        self.checkBox_global_license.setToolTip("A URL for the license document under which the Recording is offered.")
        self.checkBox_global_hw.setToolTip("A text description of the hardware used to make the Recording.")
        self.checkBox_global_dataset.setToolTip("The full filename of the Dataset file this Metadata file describes.")
        self.checkBox_global_trailing_bytes.setToolTip(
            "The number of bytes to ignore at the end of a Non-Conforming Dataset file."
        )
        self.checkBox_global_metadata_only.setToolTip(
            "Indicates the Metadata file is intentionally distributed without the Dataset."
        )
        self.checkBox_global_geolocation.setToolTip("The location of the Recording system.")
        self.checkBox_global_extensions.setToolTip(
            "A list of JSON Objects describing extensions used by this Recording."
        )
        self.checkBox_global_collection.setToolTip(
            "The base filename of a collection with which this Recording is associated."
        )

        self.checkBox_captures_sample_start.setToolTip(
            "The sample index in the Dataset file at which this Segment takes effect."
        )
        self.checkBox_captures_global_index.setToolTip(
            "The index of the sample referenced by sample_start relative to an original sample stream."
        )
        self.checkBox_captures_header_bytes.setToolTip(
            "The number of bytes preceding a chunk of samples that are not sample data, used for NCDs."
        )
        self.checkBox_captures_frequency.setToolTip("The center frequency of the signal in Hz.")
        self.checkBox_captures_datetime.setToolTip(
            "An ISO-8601 string indicating the timestamp of the sample index specified by sample_start."
        )

        # Remember Fields and Fill Known Fields
        self.textEdit_global_sample_rate.setPlainText(sample_rate)
        self.textEdit_global_hw.setPlainText(hw)
        self.textEdit_global_dataset.setPlainText(dataset)
        self.textEdit_captures_frequency.setPlainText(frequency)
        if "core:datatype" in settings_dictionary["global"]:
            pass
            # self.checkBox_global_datatype.setChecked(True)
        if "core:sample_rate" in settings_dictionary["global"]:
            self.checkBox_global_sample_rate.setChecked(True)
        if "core:version" in settings_dictionary["global"]:
            pass
            # self.checkBox_global_version.setChecked(True)
        if "core:num_channels" in settings_dictionary["global"]:
            self.checkBox_global_num_channels.setChecked(True)
        if "core:sha512" in settings_dictionary["global"]:
            # self.textEdit_global_sha512.setPlainText("<calculated>")
            self.checkBox_global_sha512.setChecked(True)
        if "core:offset" in settings_dictionary["global"]:
            self.textEdit_global_offset.setPlainText(str(settings_dictionary["global"]["core:offset"]))
            self.checkBox_global_offset.setChecked(True)
        if "core:description" in settings_dictionary["global"]:
            self.textEdit_global_description.setPlainText(settings_dictionary["global"]["core:description"])
            self.checkBox_global_description.setChecked(True)
        if "core:author" in settings_dictionary["global"]:
            self.textEdit_global_author.setPlainText(settings_dictionary["global"]["core:author"])
            self.checkBox_global_author.setChecked(True)
        if "core:meta_doi" in settings_dictionary["global"]:
            self.textEdit_global_meta_doi.setPlainText(settings_dictionary["global"]["core:meta_doi"])
            self.checkBox_global_meta_doi.setChecked(True)
        if "core:data_doi" in settings_dictionary["global"]:
            self.textEdit_global_data_doi.setPlainText(settings_dictionary["global"]["core:data_doi"])
            self.checkBox_global_doi.setChecked(True)
        if "core:recorder" in settings_dictionary["global"]:
            self.textEdit_global_recorder.setPlainText(settings_dictionary["global"]["core:recorder"])
            self.checkBox_global_recorder.setChecked(True)
        if "core:license" in settings_dictionary["global"]:
            if settings_dictionary["global"]["core:license"] == "https://spdx.org/licenses/":
                self.comboBox_global_license.setCurrentIndex(0)
            elif settings_dictionary["global"]["core:license"] == "https://spdx.org/licenses/MIT.html":
                self.comboBox_global_license.setCurrentIndex(1)
            self.checkBox_global_license.setChecked(True)
        if "core:hw" in settings_dictionary["global"]:
            self.checkBox_global_hw.setChecked(True)
        if "core:dataset" in settings_dictionary["global"]:
            self.checkBox_global_dataset.setChecked(True)
        if "core:trailing_bytes" in settings_dictionary["global"]:
            self.textEdit_global_trailing_bytes.setPlainText(str(settings_dictionary["global"]["core:trailing_bytes"]))
            self.checkBox_global_trailing_bytes.setChecked(True)
        if "core:metadata_only" in settings_dictionary["global"]:
            if settings_dictionary["global"]["core:metadata_only"] is True:
                self.comboBox_global_metadata_only.setCurrentIndex(0)
            else:
                self.comboBox_global_metadata_only.setCurrentIndex(1)
            self.checkBox_global_metadata_only.setChecked(True)
        if "core:geolocation" in settings_dictionary["global"]:
            self.textEdit_global_geolocation.setPlainText(
                ",".join(str(x) for x in settings_dictionary["global"]["core:geolocation"]["coordinates"])
            )
            self.checkBox_global_geolocation.setChecked(True)
        # if 'core:extensions' in settings_dictionary['global']:
        # self.textEdit_global_extensions.setPlainText(
        #     '[' + str(",".join(str(x) for x in settings_dictionary['global']['core:extensions']) + ']')
        # )
        # self.checkBox_global_extensions.setChecked(True)
        if "core:collection" in settings_dictionary["global"]:
            self.textEdit_global_collection.setPlainText(settings_dictionary["global"]["core:collection"])
            self.checkBox_global_collection.setChecked(True)

        if "core:sample_start" in settings_dictionary["captures"][0]:
            self.checkBox_captures_sample_start.setChecked(True)
        if "core:global_index" in settings_dictionary["captures"][0]:
            self.textEdit_captures_global_index.setPlainText(
                str(settings_dictionary["captures"][0]["core:global_index"])
            )
            self.checkBox_captures_global_index.setChecked(True)
        if "core:header_bytes" in settings_dictionary["captures"][0]:
            self.textEdit_captures_header_bytes.setPlainText(
                str(settings_dictionary["captures"][0]["core:header_bytes"])
            )
            self.checkBox_captures_header_bytes.setChecked(True)
        if "core:frequency" in settings_dictionary["captures"][0]:
            self.checkBox_captures_frequency.setChecked(True)
        if "core:datetime" in settings_dictionary["captures"][0]:
            self.checkBox_captures_datetime.setChecked(True)

        # Do SIGNAL/Slots Connections
        self._connectSlots()


    def _connectSlots(self):
        """
        Contains the connect functions for all the signals and slots.
        """
        self.pushButton_apply.clicked.connect(self._slotApplyClicked)
        self.pushButton_cancel.clicked.connect(self._slotCancelClicked)


    def _slotApplyClicked(self):
        """
        The Apply button is clicked in the dialog.
        """
        # Retrieve Values from Dialog
        if self.checkBox_global_datatype.isChecked() is True:
            self.settings_dictionary["global"]["core:datatype"] = str(self.comboBox_global_datatype.currentText())
        else:
            if "core:datatype" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:datatype"]
        if self.checkBox_global_sample_rate.isChecked() is True:
            self.settings_dictionary["global"]["core:sample_rate"] = float(
                str(self.textEdit_global_sample_rate.toPlainText())
            )
        else:
            if "core:sample_rate" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:sample_rate"]
        if self.checkBox_global_version.isChecked() is True:
            self.settings_dictionary["global"]["core:version"] = str(self.comboBox_global_version.currentText())
        else:
            if "core:version" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:version"]
        if self.checkBox_global_num_channels.isChecked() is True:
            self.settings_dictionary["global"]["core:num_channels"] = int(
                self.comboBox_global_num_channels.currentText()
            )
        else:
            if "core:num_channels" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:num_channels"]
        if self.checkBox_global_sha512.isChecked() is True:
            self.settings_dictionary["global"]["core:sha512"] = str(self.textEdit_global_sha512.toPlainText())
        else:
            if "core:sha512" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:sha512"]
        if self.checkBox_global_offset.isChecked() is True:
            self.settings_dictionary["global"]["core:offset"] = int(self.textEdit_global_offset.toPlainText())
        else:
            if "core:offset" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:offset"]
        if self.checkBox_global_description.isChecked() is True:
            self.settings_dictionary["global"]["core:description"] = str(self.textEdit_global_description.toPlainText())
        else:
            if "core:description" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:description"]
        if self.checkBox_global_author.isChecked() is True:
            self.settings_dictionary["global"]["core:author"] = str(self.textEdit_global_author.toPlainText())
        else:
            if "core:author" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:author"]
        if self.checkBox_global_meta_doi.isChecked() is True:
            self.settings_dictionary["global"]["core:meta_doi"] = str(self.textEdit_global_meta_doi.toPlainText())
        else:
            if "core:meta_doi" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:meta_doi"]
        if self.checkBox_global_doi.isChecked() is True:
            self.settings_dictionary["global"]["core:data_doi"] = str(self.textEdit_global_data_doi.toPlainText())
        else:
            if "core:data_doi" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:data_doi"]
        if self.checkBox_global_recorder.isChecked() is True:
            self.settings_dictionary["global"]["core:recorder"] = str(self.textEdit_global_recorder.toPlainText())
        else:
            if "core:recorder" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:recorder"]
        if self.checkBox_global_license.isChecked() is True:
            self.settings_dictionary["global"]["core:license"] = str(self.comboBox_global_license.currentText())
        else:
            if "core:license" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:license"]
        if self.checkBox_global_hw.isChecked() is True:
            self.settings_dictionary["global"]["core:hw"] = str(self.textEdit_global_hw.toPlainText())
        else:
            if "core:hw" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:hw"]
        if self.checkBox_global_dataset.isChecked() is True:
            self.settings_dictionary["global"]["core:dataset"] = str(self.textEdit_global_dataset.toPlainText())
        else:
            if "core:dataset" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:dataset"]
        if self.checkBox_global_trailing_bytes.isChecked() is True:
            self.settings_dictionary["global"]["core:trailing_bytes"] = int(
                self.textEdit_global_trailing_bytes.toPlainText()
            )
        else:
            if "core:trailing_bytes" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:trailing_bytes"]
        if self.checkBox_global_metadata_only.isChecked() is True:
            if str(self.comboBox_global_metadata_only.currentText()) == "True":
                self.settings_dictionary["global"]["core:metadata_only"] = True
            else:
                self.settings_dictionary["global"]["core:metadata_only"] = False
        else:
            if "core:metadata_only" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:metadata_only"]
        if self.checkBox_global_geolocation.isChecked() is True:
            geo_dict = {}
            geo_dict["type"] = "Point"
            geo_dict["coordinates"] = [
                float(x)
                for x in str(self.textEdit_global_geolocation.toPlainText())
                .replace("[", "")
                .replace("]", "")
                .split(",")
            ]
            self.settings_dictionary["global"]["core:geolocation"] = geo_dict
        else:
            if "core:geolocation" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:geolocation"]
        # if self.checkBox_global_extensions.isChecked() is True:
        # self.settings_dictionary['global']['core:extensions'] = [
        #     str(x) for x in str(
        #         self.textEdit_global_extensions.toPlainText()
        #     ).replace('[','').replace(']','').split(',')
        # ]
        # else:
        # if 'core:extensions' in self.settings_dictionary['global']:
        # del self.settings_dictionary['global']['core:extensions']
        if self.checkBox_global_collection.isChecked() is True:
            self.settings_dictionary["global"]["core:collection"] = str(self.textEdit_global_collection.toPlainText())
        else:
            if "core:collection" in self.settings_dictionary["global"]:
                del self.settings_dictionary["global"]["core:collection"]

        if self.checkBox_captures_sample_start.isChecked() is True:
            self.settings_dictionary["captures"][0]["core:sample_start"] = int(
                self.textEdit_captures_sample_start.toPlainText()
            )
        else:
            if "core:sample_start" in self.settings_dictionary["captures"][0]:
                del self.settings_dictionary["captures"][0]["core:sample_start"]
        if self.checkBox_captures_global_index.isChecked() is True:
            self.settings_dictionary["captures"][0]["core:global_index"] = int(
                self.textEdit_captures_global_index.toPlainText()
            )
        else:
            if "core:global_index" in self.settings_dictionary["captures"][0]:
                del self.settings_dictionary["captures"][0]["core:global_index"]
        if self.checkBox_captures_header_bytes.isChecked() is True:
            self.settings_dictionary["captures"][0]["core:header_bytes"] = int(
                self.textEdit_captures_header_bytes.toPlainText()
            )
        else:
            if "core:header_bytes" in self.settings_dictionary["captures"][0]:
                del self.settings_dictionary["captures"][0]["core:header_bytes"]
        if self.checkBox_captures_frequency.isChecked() is True:
            self.settings_dictionary["captures"][0]["core:frequency"] = float(
                self.textEdit_captures_frequency.toPlainText()
            )
        else:
            if "core:frequency" in self.settings_dictionary["captures"][0]:
                del self.settings_dictionary["captures"][0]["core:frequency"]
        if self.checkBox_captures_datetime.isChecked() is True:
            self.settings_dictionary["captures"][0]["core:datetime"] = str(
                self.textEdit_captures_datetime.toPlainText()
            )
        else:
            if "core:datetime" in self.settings_dictionary["captures"][0]:
                del self.settings_dictionary["captures"][0]["core:datetime"]

        # Return Something
        self.return_value = "Ok"
        self.close()


    def _slotCancelClicked(self):
        """
        Closes the dialog without saving changes.
        """
        self.close()


class OptionsDialog(QtWidgets.QDialog, UI_Types.Options):
    def __init__(self, parent=None, opening_tab="Automation", settings_dictionary=None):
        """
        First thing that executes.
        """
        # QtWidgets.QDialog.__init__(self)
        QtWidgets.QDialog.__init__(self, parent)
        self.parent = parent
        self.setupUi(self)
        self.return_value = ""

        self.settings_dictionary = settings_dictionary

        # Prevent Resizing/Maximizing
        self.setFixedSize(640, 450)

        # Do SIGNAL/Slots Connections
        self._connectSlots()

        # Change the Current Tab
        if opening_tab == "Automation":
            self.listWidget_options.setCurrentRow(0)
        elif opening_tab == "TSI":
            self.listWidget_options.setCurrentRow(1)
        elif opening_tab == "PD":
            self.listWidget_options.setCurrentRow(2)
        elif opening_tab == "Attack":
            self.listWidget_options.setCurrentRow(3)
        elif opening_tab == "IQ Data":
            self.listWidget_options.setCurrentRow(4)
        elif opening_tab == "Archive":
            self.listWidget_options.setCurrentRow(5)
        elif opening_tab == "Sensor Nodes":
            self.listWidget_options.setCurrentRow(6)
        elif opening_tab == "Library":
            self.listWidget_options.setCurrentRow(7)
        elif opening_tab == "Log":
            self.listWidget_options.setCurrentRow(8)
        else:
            self.listWidget_options.setCurrentRow(9)
        self._slotOptionsListWidgetChanged()

        # Populate the Tables
        tables = [self.tableWidget_options_automation, self.tableWidget_options_tsi, self.tableWidget_options_pd, self.tableWidget_options_attack,
            self.tableWidget_options_iq, self.tableWidget_options_archive, self.tableWidget_options_sensor_nodes, self.tableWidget_options_library,
            self.tableWidget_options_log, self.tableWidget_options_other]
        for n in range(0,len(tables)):
            for get_row in range(0,tables[n].rowCount()):
                try:
                    get_variable = str(tables[n].verticalHeaderItem(get_row).text())
                    if len(get_variable) > 0:
                        get_value = str(self.settings_dictionary[get_variable])
                        tables[n].setItem(0, get_row, QtWidgets.QTableWidgetItem(get_value))
                except:
                    pass


    def _connectSlots(self):
        """ 
        Contains the connect functions for all the signals and slots.
        """
        self.pushButton_apply.clicked.connect(self._slotOptionsApplyClicked)
        self.pushButton_cancel.clicked.connect(self._slotOptionsCancelClicked)
        #self.buttonBox.button(QtWidgets.QDialogButtonBox.Apply).clicked.connect(self._slotOptionsApplyClicked)
        self.listWidget_options.currentItemChanged.connect(self._slotOptionsListWidgetChanged)


    def _slotOptionsListWidgetChanged(self):
        """ 
        Changes the index of the stacked widget containing the options.
        """
        # Change StackedWidget
        get_index = self.listWidget_options.currentRow()
        self.stackedWidget_options.setCurrentIndex(get_index)


    @qasync.asyncSlot()
    async def _slotOptionsApplyClicked(self):
        """ 
        The Apply button is clicked in the options dialog.
        """
        # Retrieve Values from Options Dialog
        tables = [self.tableWidget_options_automation, self.tableWidget_options_tsi, self.tableWidget_options_pd, self.tableWidget_options_attack,
            self.tableWidget_options_iq, self.tableWidget_options_archive, self.tableWidget_options_sensor_nodes, self.tableWidget_options_library,
            self.tableWidget_options_log, self.tableWidget_options_other]
        variable_names = []
        variable_values = []
        for n in range(0,len(tables)):
            for get_row in range(0,tables[n].rowCount()):
                no_row = False
                try:
                    if len(str(tables[n].verticalHeaderItem(get_row).text())) > 0:
                        variable_names.append(str(tables[n].verticalHeaderItem(get_row).text()))
                    else:
                        no_row = True
                except:
                    no_row = True
                if no_row == False:
                    try:
                        if len(str(tables[n].item(get_row,0).text())) > 0:
                            variable_values.append(str(tables[n].item(get_row,0).text()))
                        else:
                            variable_values.append('')
                    except:
                        variable_values.append('')

        # Update Dictionary
        new_console_logging_level = None
        new_file_logging_level = None        
        if len(variable_names) == len(variable_values):
            for n in range(0,len(variable_names)):
                # Make Exceptions for Lists
                if variable_names[n] == "disabled_running_flow_graph_variables":
                    self.settings_dictionary[variable_names[n]] = ast.literal_eval(variable_values[n])

                # Otherwise Saved as Strings
                else:
                    # Check for Changes with Certain Variables
                    if variable_names[n] == "console_logging_level":
                        if variable_values[n].strip() != self.settings_dictionary[variable_names[n]].strip():
                            if variable_values[n].upper() == "DEBUG":
                                new_console_logging_level = "DEBUG"
                                variable_values[n] = "DEBUG"
                            elif variable_values[n].upper() == "INFO":
                                new_console_logging_level = "INFO"
                                variable_values[n] = "INFO"
                            elif variable_values[n].upper() == "WARNING":
                                new_console_logging_level = "WARNING"
                                variable_values[n] = "WARNING"
                            elif variable_values[n].upper() == "ERROR":
                                new_console_logging_level = "ERROR"
                                variable_values[n] = "ERROR"
                            else:
                                new_console_logging_level = None
                                variable_values[n] = self.settings_dictionary[variable_names[n]]
                                self.parent.errorMessage("Invalid console logging level. New console level will not be saved. Valid levels are: DEBUG, INFO, WARNING, or ERROR.")
                    elif variable_names[n] == "file_logging_level":
                        if variable_values[n].strip() != self.settings_dictionary[variable_names[n]].strip():
                            if variable_values[n].upper() == "DEBUG":
                                new_file_logging_level = "DEBUG"
                                variable_values[n] = "DEBUG"
                            elif variable_values[n].upper() == "INFO":
                                new_file_logging_level = "INFO"
                                variable_values[n] = "INFO"
                            elif variable_values[n].upper() == "WARNING":
                                new_file_logging_level = "WARNING"
                                variable_values[n] = "WARNING"
                            elif variable_values[n].upper() == "ERROR":
                                new_file_logging_level = "ERROR"
                                variable_values[n] = "ERROR"
                            else:
                                new_file_logging_level = None
                                variable_values[n] = self.settings_dictionary[variable_names[n]]
                                self.parent.errorMessage("Invalid file logging level. New file level will not be saved. Valid levels are: DEBUG, INFO, WARNING, or ERROR.")

                    # Save to Current Settings
                    self.settings_dictionary[variable_names[n]] = variable_values[n]              

        # Dump Dictionary to File
        stream = open(os.path.join(fissure.utils.YAML_DIR, "fissure_config.yaml"), 'w')
        yaml.dump(self.settings_dictionary, stream, default_flow_style=False, indent=5)

        # Save the Dictionary
        self.parent.backend.settings = self.settings_dictionary

        # Send Update Messages
        if (new_console_logging_level != None) or (new_file_logging_level != None):
            await self.parent.backend.updateLoggingLevels(new_console_logging_level, new_file_logging_level)

        await self.parent.backend.updateFISSURE_Configuration(self.parent.backend.settings)

        # Return Something
        self.return_value = "Ok"
        self.close()


    def _slotOptionsCancelClicked(self):
        """ 
        The Cancel button is clicked in the options dialog.
        """
        self.close()


class OperationsThread(QtCore.QThread):
    def __init__(self, cmd, get_cwd, parent=None):
        QtCore.QThread.__init__(self, parent)
        self.cmd = cmd
        self.get_cwd = get_cwd


    def run(self):
        try:
            p1 = subprocess.Popen(self.cmd, shell=True, cwd=self.get_cwd)
            (output, err) = p1.communicate()
            p1.wait()
        except:
            print("FAILURE")


class TreeModel(QtCore.QAbstractItemModel):
    def __init__(self, headers, data, parent=None):
        super(TreeModel, self).__init__(parent)
        """ 
        subclassing the standard interface item models must use and
        implementing index(), parent(), rowCount(), columnCount(), and data().
        """

        rootData = [header for header in headers]
        self.rootItem = TreeNode(rootData)
        indent = -1
        self.parents = [self.rootItem]
        self.indentations = [0]
        self.createData(data, indent)


    def createData(self, data, indent):
        for n in range(0, len(data)):
            # Main Collection Folder
            if data[n][0] == 0:
                parent = self.parents[0]
                parent.insertChildren(parent.childCount(), 1, parent.columnCount())

                # Fill Columns
                for m in range(1, len(data[n])):
                    parent.child(parent.childCount() - 1).setData(m - 1, data[n][m])

                # Save
                self.parents.append(parent.child(parent.childCount() - 1))

            # Collection Subdirectories and Files
            else:
                # Indent
                if data[n][0] > data[n - 1][0]:
                    parent = self.parents[-1]
                    self.parents[-1].insertChildren(parent.childCount(), 1, parent.columnCount())

                    # Fill Columns
                    for m in range(1, len(data[n])):
                        parent.child(parent.childCount() - 1).setData(m - 1, data[n][m])

                    # Do Not Make First File a Parent
                    if n < len(data) - 1:
                        if data[n][0] != data[n + 1][0]:
                            self.parents.append(parent.child(parent.childCount() - 1))

                # Restore Indent
                elif data[n][0] < data[n - 1][0]:
                    parent = self.parents[-1].parent()
                    self.parents[-1].parent().insertChildren(parent.childCount(), 1, parent.columnCount())

                    # Fill Columns
                    for m in range(1, len(data[n])):
                        parent.child(parent.childCount() - 1).setData(m - 1, data[n][m])

                    self.parents.append(parent.child(parent.childCount() - 1))

                # Keep Indent
                else:
                    parent = self.parents[-1]
                    self.parents[-1].insertChildren(parent.childCount(), 1, parent.columnCount())

                    # Fill Columns
                    for m in range(1, len(data[n])):
                        parent.child(parent.childCount() - 1).setData(m - 1, data[n][m])


    def index(self, row, column, index=QtCore.QModelIndex()):
        """
        Returns the index of the item in the model specified by the given row, column and parent index
        """

        if not self.hasIndex(row, column, index):
            return QtCore.QModelIndex()
        if not index.isValid():
            item = self.rootItem
        else:
            item = index.internalPointer()
        child = item.child(row)

        if child:
            return self.createIndex(row, column, child)
        return QtCore.QModelIndex()


    def parent(self, index):
        """
        Returns the parent of the model item with the given index
        If the item has no parent, an invalid QModelIndex is returned
        """

        if not index.isValid():
            return QtCore.QModelIndex()
        item = index.internalPointer()
        if not item:
            return QtCore.QModelIndex()

        parent = item.parentItem
        if parent == self.rootItem:
            return QtCore.QModelIndex()
        else:
            return self.createIndex(parent.childNumber(), 0, parent)


    def rowCount(self, index=QtCore.QModelIndex()):
        """
        Returns the number of rows under the given parent
        When the parent is valid it means that rowCount is returning the number of children of parent
        """

        if index.isValid():
            parent = index.internalPointer()
        else:
            parent = self.rootItem
        return parent.childCount()


    def columnCount(self, index=QtCore.QModelIndex()):
        """
        Returns the number of columns for the children of the given parent
        """
        return self.rootItem.columnCount()


    def data(self, index, role=QtCore.Qt.DisplayRole):
        """
        Returns the data stored under the given role for the item referred to by the index
        """
        if index.isValid() and role == QtCore.Qt.DisplayRole:
            return index.internalPointer().data(index.column())
        elif not index.isValid():
            return self.rootItem.data(index.column())


    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        """
        Returns the data for the given role and section in the header with the specified orientation
        """
        if orientation == QtCore.Qt.Horizontal and role == QtCore.Qt.DisplayRole:
            return self.rootItem.data(section)


class TreeNode(object):
    def __init__(self, data, parent=None):
        self.parentItem = parent
        self.itemData = data
        self.children = []


    def child(self, row):
        return self.children[row]


    def childCount(self):
        return len(self.children)


    def childNumber(self):
        if self.parentItem is not None:
            return self.parentItem.children.index(self)


    def columnCount(self):
        return len(self.itemData)


    def data(self, column):
        return self.itemData[column]


    def insertChildren(self, position, count, columns):
        if position < 0 or position > len(self.children):
            return False
        for row in range(count):
            data = [None for v in range(columns)]
            item = TreeNode(data, self)
            self.children.insert(position, item)


    def parent(self):
        return self.parentItem


    def setData(self, column, value):
        if column < 0 or column >= len(self.itemData):
            return False
        self.itemData[column] = value


class JointPlotDialog(QtWidgets.QDialog, UI_Types.JointPlot):
    def __init__(self, parent, feature_list):
        """
        Feature Extract trim settings.
        """
        QtWidgets.QDialog.__init__(self, parent)
        self.parent = parent
        self.setupUi(self)
        self.return_value = []

        # Prevent Resizing/Maximizing
        self.setFixedSize(400, 150)

        # Connect Slots
        self.pushButton_ok.clicked.connect(self._slotOK_Clicked)
        self.pushButton_cancel.clicked.connect(self._slotCancelClicked)

        # Update ComboBoxes
        self.comboBox_joint_plot_feature1.addItems(sorted(feature_list, key=str.lower))
        self.comboBox_joint_plot_feature2.addItems(sorted(feature_list, key=str.lower))


    def _slotOK_Clicked(self):
        self.return_value = [
            str(self.comboBox_joint_plot_feature1.currentText()),
            str(self.comboBox_joint_plot_feature2.currentText()),
        ]
        self.close()


    def _slotCancelClicked(self):
        self.return_value = "Cancel"
        self.reject()


class TrimSettings(QtWidgets.QDialog, UI_Types.Trim):
    def __init__(self, parent, default_value):
        """
        Feature Extract trim settings.
        """
        QtWidgets.QDialog.__init__(self, parent)
        self.parent = parent
        self.setupUi(self)
        self.return_value = []

        # Prevent Resizing/Maximizing
        self.setFixedSize(370, 130)

        # Connect Slots
        self.comboBox_value.currentIndexChanged.connect(self._slotChangeValue)
        self.pushButton_ok.clicked.connect(self._slotOK_Clicked)
        self.pushButton_cancel.clicked.connect(self._slotCancelClicked)

        # Update Label Text
        self.default_value = default_value
        self.textEdit_value.setPlainText(self.default_value)


    def _slotChangeValue(self):
        """Toggles between average and custom value."""
        # Toggle the Value
        if self.comboBox_value.currentIndex() == 0:
            self.textEdit_value.setPlainText(str(self.default_value))
        else:
            self.textEdit_value.setPlainText("0")


    def _slotOK_Clicked(self):
        self.return_value = [self.comboBox_rule.currentIndex(), str(self.textEdit_value.toPlainText())]
        self.close()


    def _slotCancelClicked(self):
        self.reject()


class FeaturesDialog(QtWidgets.QDialog, UI_Types.Features):
    def __init__(self, parent, filename, results, models, features):
        """ 
        Feature Extract trim settings.
        """
        QtWidgets.QDialog.__init__(self,parent)        
        self.parent = parent        
        self.setupUi(self)     
        self.return_value = []
        
        # Prevent Resizing/Maximizing
        self.setFixedSize(1000, 500)
        
        # Update Label
        self.label_file.setText(filename)
        
        # Populate Table      
        self.tableWidget_features.setRowCount(len(models))
        for n in range(0,len(models)):
            header_item = QtWidgets.QTableWidgetItem(models[n])
            header_item.setFont(QtGui.QFont("Ubuntu",10))
            self.tableWidget_features.setVerticalHeaderItem(n,header_item)
            
            result_item = QtWidgets.QTableWidgetItem(results[n])
            result_item.setTextAlignment(QtCore.Qt.AlignCenter)
            self.tableWidget_features.setItem(n,0,result_item)
            
            feature_item = QtWidgets.QTableWidgetItem(str(features[n]))
            feature_item.setTextAlignment(QtCore.Qt.AlignLeft)
            self.tableWidget_features.setItem(n,1,feature_item)
            
        # Resize the Table
        self.tableWidget_features.resizeRowsToContents()
        self.tableWidget_features.resizeColumnsToContents()
        self.tableWidget_features.horizontalHeader().setStretchLastSection(False)
        self.tableWidget_features.horizontalHeader().setStretchLastSection(True)