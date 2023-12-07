import os
from PyQt5 import QtWidgets, uic
form_class10 = uic.loadUiType(os.path.dirname(os.path.realpath(__file__)) + "/UI/sigmf.ui")[0]

class SigMF_Dialog(QtWidgets.QDialog, form_class10):
    def __init__(self, parent=None, sample_rate=None, hw=None, dataset=None, frequency=None, settings_dictionary=None):
        """ First thing that executes.
        """
        QtWidgets.QDialog.__init__(self,parent)
        self.setupUi(self)
        self.return_value = ""

        self.settings_dictionary = settings_dictionary

        # Prevent Resizing/Maximizing
        self.setFixedSize(800, 600)

        # Tooltips
        self.checkBox_global_datatype.setToolTip("The SigMF Dataset format of the stored samples in the Dataset file.")
        self.checkBox_global_sample_rate.setToolTip("The sample rate of the signal in samples per second.")
        self.checkBox_global_version.setToolTip("The version of the SigMF specification used to create the Metadata file.")
        self.checkBox_global_num_channels.setToolTip("Total number of interleaved channels in the Dataset file. If omitted, this defaults to one.")
        self.checkBox_global_sha512.setToolTip("The SHA512 hash of the Dataset file associated with the SigMF file.")
        self.checkBox_global_offset.setToolTip("The index number of the first sample in the Dataset. If not provided, this value defaults to zero. Typically used when a Recording is split over multiple files. All sample indices in SigMF are absolute, and so all other indices referenced in metadata for this recording SHOULD be greater than or equal to this value.")
        self.checkBox_global_description.setToolTip("A text description of the SigMF Recording.")
        self.checkBox_global_author.setToolTip('A text identifier for the author potentially including name, handle, email, and/or other ID like Amateur Call Sign. For example "Bruce Wayne bruce@waynetech.com" or "Bruce (K3X)".')
        self.checkBox_global_meta_doi.setToolTip("The registered DOI (ISO 26324) for a Recording's Metadata file.")
        self.checkBox_global_doi.setToolTip("The registered DOI (ISO 26324) for a Recording's Dataset file.")
        self.checkBox_global_recorder.setToolTip("The name of the software used to make this SigMF Recording.")
        self.checkBox_global_license.setToolTip("A URL for the license document under which the Recording is offered.")
        self.checkBox_global_hw.setToolTip("A text description of the hardware used to make the Recording.")
        self.checkBox_global_dataset.setToolTip("The full filename of the Dataset file this Metadata file describes.")
        self.checkBox_global_trailing_bytes.setToolTip("The number of bytes to ignore at the end of a Non-Conforming Dataset file.")
        self.checkBox_global_metadata_only.setToolTip("Indicates the Metadata file is intentionally distributed without the Dataset.")
        self.checkBox_global_geolocation.setToolTip("The location of the Recording system.")
        self.checkBox_global_extensions.setToolTip("A list of JSON Objects describing extensions used by this Recording.")
        self.checkBox_global_collection.setToolTip("The base filename of a collection with which this Recording is associated.")

        self.checkBox_captures_sample_start.setToolTip("The sample index in the Dataset file at which this Segment takes effect.")
        self.checkBox_captures_global_index.setToolTip("The index of the sample referenced by sample_start relative to an original sample stream.")
        self.checkBox_captures_header_bytes.setToolTip("The number of bytes preceding a chunk of samples that are not sample data, used for NCDs.")
        self.checkBox_captures_frequency.setToolTip("The center frequency of the signal in Hz.")
        self.checkBox_captures_datetime.setToolTip("An ISO-8601 string indicating the timestamp of the sample index specified by sample_start.")

        # Remember Fields and Fill Known Fields
        self.textEdit_global_sample_rate.setPlainText(sample_rate)
        self.textEdit_global_hw.setPlainText(hw)
        self.textEdit_global_dataset.setPlainText(dataset)
        self.textEdit_captures_frequency.setPlainText(frequency)
        if 'core:datatype' in settings_dictionary['global']:
            pass
            #self.checkBox_global_datatype.setChecked(True)
        if 'core:sample_rate' in settings_dictionary['global']:
            self.checkBox_global_sample_rate.setChecked(True)
        if 'core:version' in settings_dictionary['global']:
            pass
            #self.checkBox_global_version.setChecked(True)
        if 'core:num_channels' in settings_dictionary['global']:
            self.checkBox_global_num_channels.setChecked(True)
        if 'core:sha512' in settings_dictionary['global']:
            #self.textEdit_global_sha512.setPlainText("<calculated>")
            self.checkBox_global_sha512.setChecked(True)
        if 'core:offset' in settings_dictionary['global']:
            self.textEdit_global_offset.setPlainText(str(settings_dictionary['global']['core:offset']))
            self.checkBox_global_offset.setChecked(True)
        if 'core:description' in settings_dictionary['global']:
            self.textEdit_global_description.setPlainText(settings_dictionary['global']['core:description'])
            self.checkBox_global_description.setChecked(True)
        if 'core:author' in settings_dictionary['global']:
            self.textEdit_global_author.setPlainText(settings_dictionary['global']['core:author'])
            self.checkBox_global_author.setChecked(True)
        if 'core:meta_doi' in settings_dictionary['global']:
            self.textEdit_global_meta_doi.setPlainText(settings_dictionary['global']['core:meta_doi'])
            self.checkBox_global_meta_doi.setChecked(True)
        if 'core:data_doi' in settings_dictionary['global']:
            self.textEdit_global_data_doi.setPlainText(settings_dictionary['global']['core:data_doi'])
            self.checkBox_global_doi.setChecked(True)
        if 'core:recorder' in settings_dictionary['global']:
            self.textEdit_global_recorder.setPlainText(settings_dictionary['global']['core:recorder'])
            self.checkBox_global_recorder.setChecked(True)
        if 'core:license' in settings_dictionary['global']:
            if settings_dictionary['global']['core:license'] == "https://spdx.org/licenses/":
                self.comboBox_global_license.setCurrentIndex(0)
            elif settings_dictionary['global']['core:license'] == "https://spdx.org/licenses/MIT.html":
                self.comboBox_global_license.setCurrentIndex(1)
            self.checkBox_global_license.setChecked(True)
        if 'core:hw' in settings_dictionary['global']:
            self.checkBox_global_hw.setChecked(True)
        if 'core:dataset' in settings_dictionary['global']:
            self.checkBox_global_dataset.setChecked(True)
        if 'core:trailing_bytes' in settings_dictionary['global']:
            self.textEdit_global_trailing_bytes.setPlainText(str(settings_dictionary['global']['core:trailing_bytes']))
            self.checkBox_global_trailing_bytes.setChecked(True)
        if 'core:metadata_only' in settings_dictionary['global']:
            if settings_dictionary['global']['core:metadata_only'] == True:
                self.comboBox_global_metadata_only.setCurrentIndex(0)
            else:
                self.comboBox_global_metadata_only.setCurrentIndex(1)
            self.checkBox_global_metadata_only.setChecked(True)
        if 'core:geolocation' in settings_dictionary['global']:
            self.textEdit_global_geolocation.setPlainText(",".join(str(x) for x in settings_dictionary['global']['core:geolocation']['coordinates']))
            self.checkBox_global_geolocation.setChecked(True)
        # if 'core:extensions' in settings_dictionary['global']:
            # self.textEdit_global_extensions.setPlainText('[' + str(",".join(str(x) for x in settings_dictionary['global']['core:extensions']) + ']'))
            # self.checkBox_global_extensions.setChecked(True)
        if 'core:collection' in settings_dictionary['global']:
            self.textEdit_global_collection.setPlainText(settings_dictionary['global']['core:collection'])
            self.checkBox_global_collection.setChecked(True)

        if 'core:sample_start' in settings_dictionary['captures'][0]:
            self.checkBox_captures_sample_start.setChecked(True)
        if 'core:global_index' in settings_dictionary['captures'][0]:
            self.textEdit_captures_global_index.setPlainText(str(settings_dictionary['captures'][0]['core:global_index']))
            self.checkBox_captures_global_index.setChecked(True)
        if 'core:header_bytes' in settings_dictionary['captures'][0]:
            self.textEdit_captures_header_bytes.setPlainText(str(settings_dictionary['captures'][0]['core:header_bytes']))
            self.checkBox_captures_header_bytes.setChecked(True)
        if 'core:frequency' in settings_dictionary['captures'][0]:
            self.checkBox_captures_frequency.setChecked(True)
        if 'core:datetime' in settings_dictionary['captures'][0]:
            self.checkBox_captures_datetime.setChecked(True)

        # Do SIGNAL/Slots Connections
        self._connectSlots()

    def _connectSlots(self):
        """ Contains the connect functions for all the signals and slots.
        """
        self.pushButton_apply.clicked.connect(self._slotApplyClicked)
        self.pushButton_cancel.clicked.connect(self._slotCancelClicked)

    def _slotApplyClicked(self):
        """ The Apply button is clicked in the dialog.
        """
        # Retrieve Values from Dialog
        if self.checkBox_global_datatype.isChecked() == True:
            self.settings_dictionary['global']['core:datatype'] = str(self.comboBox_global_datatype.currentText())
        else:
            if 'core:datatype' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:datatype']
        if self.checkBox_global_sample_rate.isChecked() == True:
            self.settings_dictionary['global']['core:sample_rate'] = float(str(self.textEdit_global_sample_rate.toPlainText()))
        else:
            if 'core:sample_rate' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:sample_rate']
        if self.checkBox_global_version.isChecked() == True:
            self.settings_dictionary['global']['core:version'] = str(self.comboBox_global_version.currentText())
        else:
            if 'core:version' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:version']
        if self.checkBox_global_num_channels.isChecked() == True:
            self.settings_dictionary['global']['core:num_channels'] = int(self.comboBox_global_num_channels.currentText())
        else:
            if 'core:num_channels' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:num_channels']
        if self.checkBox_global_sha512.isChecked() == True:
            self.settings_dictionary['global']['core:sha512'] = str(self.textEdit_global_sha512.toPlainText())
        else:
            if 'core:sha512' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:sha512']
        if self.checkBox_global_offset.isChecked() == True:
            self.settings_dictionary['global']['core:offset'] = int(self.textEdit_global_offset.toPlainText())
        else:
            if 'core:offset' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:offset']
        if self.checkBox_global_description.isChecked() == True:
            self.settings_dictionary['global']['core:description'] = str(self.textEdit_global_description.toPlainText())
        else:
            if 'core:description' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:description']
        if self.checkBox_global_author.isChecked() == True:
            self.settings_dictionary['global']['core:author'] = str(self.textEdit_global_author.toPlainText())
        else:
            if 'core:author' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:author']
        if self.checkBox_global_meta_doi.isChecked() == True:
            self.settings_dictionary['global']['core:meta_doi'] = str(self.textEdit_global_meta_doi.toPlainText())
        else:
            if 'core:meta_doi' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:meta_doi']
        if self.checkBox_global_doi.isChecked() == True:
            self.settings_dictionary['global']['core:data_doi'] = str(self.textEdit_global_data_doi.toPlainText())
        else:
            if 'core:data_doi' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:data_doi']
        if self.checkBox_global_recorder.isChecked() == True:
            self.settings_dictionary['global']['core:recorder'] = str(self.textEdit_global_recorder.toPlainText())
        else:
            if 'core:recorder' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:recorder']
        if self.checkBox_global_license.isChecked() == True:
            self.settings_dictionary['global']['core:license'] = str(self.comboBox_global_license.currentText())
        else:
            if 'core:license' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:license']
        if self.checkBox_global_hw.isChecked() == True:
            self.settings_dictionary['global']['core:hw'] = str(self.textEdit_global_hw.toPlainText())
        else:
            if 'core:hw' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:hw']
        if self.checkBox_global_dataset.isChecked() == True:
            self.settings_dictionary['global']['core:dataset'] = str(self.textEdit_global_dataset.toPlainText())
        else:
            if 'core:dataset' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:dataset']
        if self.checkBox_global_trailing_bytes.isChecked() == True:
            self.settings_dictionary['global']['core:trailing_bytes'] = int(self.textEdit_global_trailing_bytes.toPlainText())
        else:
            if 'core:trailing_bytes' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:trailing_bytes']
        if self.checkBox_global_metadata_only.isChecked() == True:
            if str(self.comboBox_global_metadata_only.currentText()) == "True":
                self.settings_dictionary['global']['core:metadata_only'] = True
            else:
                self.settings_dictionary['global']['core:metadata_only'] = False
        else:
            if 'core:metadata_only' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:metadata_only']
        if self.checkBox_global_geolocation.isChecked() == True:
            geo_dict = {}
            geo_dict['type'] = "Point"
            geo_dict['coordinates'] = [float(x) for x in str(self.textEdit_global_geolocation.toPlainText()).replace('[','').replace(']','').split(',')]
            self.settings_dictionary['global']['core:geolocation'] = geo_dict
        else:
            if 'core:geolocation' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:geolocation']
        # if self.checkBox_global_extensions.isChecked() == True:
            # self.settings_dictionary['global']['core:extensions'] = [str(x) for x in str(self.textEdit_global_extensions.toPlainText()).replace('[','').replace(']','').split(',')]
        # else:
            # if 'core:extensions' in self.settings_dictionary['global']:
                # del self.settings_dictionary['global']['core:extensions']
        if self.checkBox_global_collection.isChecked() == True:
            self.settings_dictionary['global']['core:collection'] = str(self.textEdit_global_collection.toPlainText())
        else:
            if 'core:collection' in self.settings_dictionary['global']:
                del self.settings_dictionary['global']['core:collection']

        if self.checkBox_captures_sample_start.isChecked() == True:
            self.settings_dictionary['captures'][0]['core:sample_start'] = int(self.textEdit_captures_sample_start.toPlainText())
        else:
            if 'core:sample_start' in self.settings_dictionary['captures'][0]:
                del self.settings_dictionary['captures'][0]['core:sample_start']
        if self.checkBox_captures_global_index.isChecked() == True:
            self.settings_dictionary['captures'][0]['core:global_index'] = int(self.textEdit_captures_global_index.toPlainText())
        else:
            if 'core:global_index' in self.settings_dictionary['captures'][0]:
                del self.settings_dictionary['captures'][0]['core:global_index']
        if self.checkBox_captures_header_bytes.isChecked() == True:
            self.settings_dictionary['captures'][0]['core:header_bytes'] = int(self.textEdit_captures_header_bytes.toPlainText())
        else:
            if 'core:header_bytes' in self.settings_dictionary['captures'][0]:
                del self.settings_dictionary['captures'][0]['core:header_bytes']
        if self.checkBox_captures_frequency.isChecked() == True:
            self.settings_dictionary['captures'][0]['core:frequency'] = float(self.textEdit_captures_frequency.toPlainText())
        else:
            if 'core:frequency' in self.settings_dictionary['captures'][0]:
                del self.settings_dictionary['captures'][0]['core:frequency']
        if self.checkBox_captures_datetime.isChecked() == True:
            self.settings_dictionary['captures'][0]['core:datetime'] = str(self.textEdit_captures_datetime.toPlainText())
        else:
            if 'core:datetime' in self.settings_dictionary['captures'][0]:
                del self.settings_dictionary['captures'][0]['core:datetime']

        # Return Something
        self.return_value = "Ok"
        self.close()

    def _slotCancelClicked(self):
        """ Closes the dialog without saving changes.
        """
        self.close()
