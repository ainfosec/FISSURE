from PyQt5 import QtCore, QtWidgets

# import fissure.comms
import fissure.utils
import qasync
import os
import time
import requests


@QtCore.pyqtSlot(QtCore.QObject)
def _slotOK_Clicked(TriggersDlg: QtCore.QObject):
    """ 
    The OK button is clicked in the dialog.
    """
    # Return Something
    for row in range(0, TriggersDlg.tableWidget_trigger_info.rowCount()):
        TriggersDlg.return_value.append([str(TriggersDlg.tableWidget_trigger_info.item(row,0).text()), str(TriggersDlg.tableWidget_trigger_info.item(row,1).text()), str(TriggersDlg.tableWidget_trigger_info.item(row,2).text()), str(TriggersDlg.tableWidget_trigger_info.item(row,3).text())])

    TriggersDlg.accept()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotCancelClicked(TriggersDlg: QtCore.QObject):
    """ 
    The Cancel button is clicked in the dialog.
    """
    TriggersDlg.close()  # close() will return None instead of []


@QtCore.pyqtSlot(QtCore.QObject)
def _slotCategoryChanged(TriggersDlg: QtCore.QObject):
    """ 
    Changes the available triggers based on the selected category.
    """
    # Retrieve Category
    get_category = str(TriggersDlg.comboBox_category.currentText())

    # Update Triggers
    TriggersDlg.comboBox_trigger.blockSignals(True)  # Prevents multiple calls
    TriggersDlg.comboBox_trigger.clear()
    trigger_list = list(TriggersDlg.dashboard.backend.library['Triggers'][get_category].keys())
    TriggersDlg.comboBox_trigger.addItems(sorted(trigger_list))
    TriggersDlg.comboBox_trigger.blockSignals(False)
    _slotTriggerChanged(TriggersDlg)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTriggerChanged(TriggersDlg: QtCore.QObject):
    """ 
    Changes the default settings based on the selected trigger.
    """
    # Retrieve Trigger
    get_category = str(TriggersDlg.comboBox_category.currentText())
    get_trigger = str(TriggersDlg.comboBox_trigger.currentText())
    
    # File and Type
    TriggersDlg.label2_filename.setText(TriggersDlg.dashboard.backend.library['Triggers'][get_category][get_trigger]['File'])
    TriggersDlg.label2_type.setText(TriggersDlg.dashboard.backend.library['Triggers'][get_category][get_trigger]['Type'])
    
    # Update Default Settings
    if (get_category == "Time") and (get_trigger == "Sensor Node Time"):
        TriggersDlg.dateTimeEdit_sensor_node_time_trigger_time.setDateTime(QtCore.QDateTime.currentDateTime())
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(1)
    elif (get_category == "Time") and (get_trigger == "Timer"):
        TriggersDlg.textEdit_timer_trigger_timer.setPlainText(str(TriggersDlg.dashboard.backend.library['Triggers']['Time']['Timer']['Default Settings']['Timer Seconds']))
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(2)
    elif (get_category == "Acoustic") and (get_trigger == "Sound Threshold"):
        TriggersDlg.textEdit_sound_threshold_threshold.setPlainText(str(TriggersDlg.dashboard.backend.library['Triggers']['Acoustic']['Sound Threshold']['Default Settings']['Threshold']))
        TriggersDlg.textEdit_sound_threshold_duration.setPlainText(str(TriggersDlg.dashboard.backend.library['Triggers']['Acoustic']['Sound Threshold']['Default Settings']['Duration']))
        TriggersDlg.textEdit_sound_threshold_sample_rate.setPlainText(str(TriggersDlg.dashboard.backend.library['Triggers']['Acoustic']['Sound Threshold']['Default Settings']['Sample Rate']))
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(3)
    elif (get_category == "Filesystem") and (get_trigger == "File Modified"):
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(4)
    elif (get_category == "Filesystem") and (get_trigger == "Folder Modified"):
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(5)
    elif (get_category == "Environmental") and (get_trigger == "Temperature"):
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(6)
    elif (get_category == "Environmental") and (get_trigger == "Weather"):
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(7)
    elif (get_category == "Environmental") and (get_trigger == "Wind"):
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(8)
    elif (get_category == "Environmental") and (get_trigger == "Sunrise/Sunset"):
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(9)
    elif (get_category == "RF") and (get_trigger == "Detect SSID"):
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(10)
    elif (get_category == "Visual") and (get_trigger == "Motion Detector"):
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(11)
    elif (get_category == "RF") and (get_trigger == "GPS Point"):
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(12)
    elif (get_category == "RF") and (get_trigger == "GPS Line"):
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(13)
    elif (get_category == "RF") and (get_trigger == "X10 Demod"):
        TriggersDlg.textEdit_rf_x10_demod_text.setPlainText(str(TriggersDlg.dashboard.backend.library['Triggers']['RF']['X10 Demod']['Default Settings']['Matching Text']))
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(14)
    elif (get_category == "RF") and (get_trigger == "Plane Spotting"):
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(15)
    elif (get_category == "RF") and (get_trigger == "RDS Keyword"):
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(16)
    elif (get_category == "RF") and (get_trigger == "Cellular Tower"):
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(17)
    elif (get_category == "Networking") and (get_trigger == "Webserver Curl"):
        TriggersDlg.textEdit_networking_webserver_curl_ip.setPlainText(str(TriggersDlg.dashboard.backend.library['Triggers']['Networking']['Webserver Curl']['Default Settings']['IP Address']))
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(18)
    elif (get_category == "RF") and (get_trigger == "Power Threshold"):
        TriggersDlg.textEdit_rf_power_threshold_sample_rate.setPlainText(str(TriggersDlg.dashboard.backend.library['Triggers']['RF']['Power Threshold']['Default Settings']['Sample Rate']))
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(19)
    else:
        TriggersDlg.stackedWidget_trigger_info.setCurrentIndex(0)  # Blank


@QtCore.pyqtSlot(QtCore.QObject)
def _slotViewClicked(TriggersDlg: QtCore.QObject):
    """ 
    Open the trigger file associated to the selected trigger.
    """
    # Retrieve Filename
    get_filename = str(TriggersDlg.label2_filename.text())
    full_path = os.path.join(fissure.utils.get_fg_library_dir(TriggersDlg.dashboard.backend.os_info), "Triggers", get_filename)
    
    # File Type
    get_file_type = str(TriggersDlg.label2_type.text())

    # Flow Graph
    if get_file_type == "Flow Graph" or get_file_type == "Flow Graph - GUI":
        # Open the Flow Graph in GNU Radio Companion
        if os.path.isfile(full_path):
            osCommandString = 'gnuradio-companion "' + full_path + '"'
            os.system(osCommandString + " &")
        else:
            TriggersDlg.dashboard.errorMessage("Missing .grc file.")

    # Python Script
    else:
        # Open the Flow Graph in Gedit
        if os.path.isfile(full_path):
            osCommandString = 'gedit "' + full_path + '"'
            os.system(osCommandString + " &")
        else:
            TriggersDlg.dashboard.errorMessage("Missing .py file.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAddClicked(TriggersDlg: QtCore.QObject):
    """ 
    Adds a row to the table of triggers containing the trigger information.
    """
    # Add Values to the Table
    get_filename = str(TriggersDlg.label2_filename.text())
    get_type = str(TriggersDlg.label2_type.text())
    variable_names = "[]"
    variable_values = "[]"
    
    # Time: Sensor Node Time
    if TriggersDlg.stackedWidget_trigger_info.currentIndex() == 1:
        variable_names = ["trigger_time"]
        variable_values = [str(TriggersDlg.dateTimeEdit_sensor_node_time_trigger_time.dateTime().toString('yyyy-MM-dd hh:mm:ss'))]
                
        # # Run with/without Sudo
        # if TriggersDlg.checkBox_attack_single_stage_sudo.isChecked() == True:
            # run_with_sudo = True
        # else:
            # run_with_sudo = False
    
    # Time: Sensor Node Time
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 2:
        variable_names = ["timer_seconds"]
        if str(TriggersDlg.comboBox_timer_units.currentText()) == "Minutes":
            time_seconds = float(str(TriggersDlg.textEdit_timer_trigger_timer.toPlainText())) * 60
        elif str(TriggersDlg.comboBox_timer_units.currentText()) == "Hours":
            time_seconds = float(str(TriggersDlg.textEdit_timer_trigger_timer.toPlainText())) * 60 * 60
        elif str(TriggersDlg.comboBox_timer_units.currentText()) == "Days":
            time_seconds = float(str(TriggersDlg.textEdit_timer_trigger_timer.toPlainText())) * 60 * 60 * 24
        else:
            time_seconds = float(str(TriggersDlg.textEdit_timer_trigger_timer.toPlainText()))
        variable_values = [str(time_seconds)]
        
    # Audio: Sound Threshold
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 3:
        threshold = str(float(str(TriggersDlg.textEdit_sound_threshold_threshold.toPlainText())))
        duration = str(float(str(TriggersDlg.textEdit_sound_threshold_duration.toPlainText())))
        sample_rate = str(float(str(TriggersDlg.textEdit_sound_threshold_sample_rate.toPlainText())))
        variable_names = ["get_threshold","get_duration","get_sample_rate"]
        variable_values = [threshold, duration, sample_rate]    
        
    # Data: File Modified
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 4:
        file_modified = str(TriggersDlg.textEdit_filesystem_file_modified_filepath.toPlainText())
        variable_names = ["file_modified"]
        variable_values = [file_modified]    
        
    # Data: Folder Modified
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 5:
        folder_modified = str(TriggersDlg.textEdit_filesystem_folder_modified_folder.toPlainText())
        variable_names = ["folder_modified"]
        variable_values = [folder_modified]    
        
    # Environmental: Temperature
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 6:
        comparison = str(TriggersDlg.comboBox_environmental_temperature_comparison.currentText())
        temperature = str(TriggersDlg.spinBox_environmental_temperature_temperature.value())
        city = str(TriggersDlg.textEdit_environmental_temperature_city.toPlainText())
        state = str(TriggersDlg.textEdit_environmental_temperature_state.toPlainText())
        country = str(TriggersDlg.textEdit_environmental_temperature_country.toPlainText())
        variable_names = ["comparison","temperature","city_name","state_code","country_code"]
        variable_values = [comparison, temperature, city, state, country]
        
        if len(city) == 0:
            return
        
    # Environmental: Weather
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 7:
        conditions = str(TriggersDlg.comboBox_environmental_weather_conditions.currentText())
        city = str(TriggersDlg.textEdit_environmental_weather_city.toPlainText())
        state = str(TriggersDlg.textEdit_environmental_weather_state.toPlainText())
        country = str(TriggersDlg.textEdit_environmental_weather_country.toPlainText())
        variable_names = ["conditions","city_name","state_code","country_code"]
        variable_values = [conditions, city, state, country]
        
        if len(city) == 0:
            return
        
    # Environmental: Wind
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 8:
        wind_threshold = str(TriggersDlg.spinBox_environmental_wind_threshold.value())
        city = str(TriggersDlg.textEdit_environmental_wind_city.toPlainText())
        state = str(TriggersDlg.textEdit_environmental_wind_state.toPlainText())
        country = str(TriggersDlg.textEdit_environmental_wind_country.toPlainText())
        variable_names = ["wind_threshold","city_name","state_code","country_code"]
        variable_values = [wind_threshold, city, state, country]
        
        if len(city) == 0:
            return
        
    # Environmental: Sunrise/Sunset
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 9:
        sunrise_sunset = str(TriggersDlg.comboBox_environmental_sunrise_sunset.currentText())
        city = str(TriggersDlg.textEdit_environmental_sunrise_city.toPlainText())
        state = str(TriggersDlg.textEdit_environmental_sunrise_state.toPlainText())
        country = str(TriggersDlg.textEdit_environmental_sunsrise_country.toPlainText())
        variable_names = ["sunrise_sunset","city_name","state_code","country_code"]
        variable_values = [sunrise_sunset, city, state, country]
        
        if len(city) == 0:
            return
        
    # Data: Detect SSID
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 10:
        interface = str(TriggersDlg.textEdit_rf_detect_ssid_interface.toPlainText())
        ssid = str(TriggersDlg.textEdit_rf_detect_ssid_ssid.toPlainText())
        variable_names = ["interface", "ssid"]
        variable_values = [interface, ssid]
        
        if (len(interface) == 0) or (len(ssid) == 0):
            return
        
    # Visual: Motion Detector
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 11:
        threshold = str(TriggersDlg.spinBox_visual_motion_detector_threshold.value())
        variable_names = ["motion_frame_threshold"]
        variable_values = [threshold]

    # Data: GPS Point
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 12:
        target_latitude = str(TriggersDlg.textEdit_rf_gps_point_latitude.toPlainText())
        target_longitude = str(TriggersDlg.textEdit_rf_gps_point_longitude.toPlainText())
        distance = str(TriggersDlg.spinBox_rf_gps_point_distance.value())
        variable_names = ["target_latitude", "target_longitude", "distance"]
        variable_values = [target_latitude, target_longitude, distance]

    # Data: GPS Line
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 13:
        line_type = str(TriggersDlg.comboBox_rf_gps_line_type.currentText())
        lat_lon_value = str(TriggersDlg.textEdit_rf_gps_line_value.toPlainText())
        comparison = str(TriggersDlg.comboBox_rf_gps_line_comparison.currentText())
        variable_names = ["latitude", "longitude", "comparison"]
        if line_type == "Latitude":
            variable_values = [lat_lon_value, "None", comparison]
        else:
            variable_values = ["None", lat_lon_value, comparison]

    # Data: X10 Demod
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 14:
        hardware = str(TriggersDlg.comboBox_rf_x10_demod_hardware.currentText())
        matching_text = str(TriggersDlg.textEdit_rf_x10_demod_text.toPlainText())
        variable_names = ["hardware","matching_text"]
        variable_values = [hardware, matching_text]

    # Data: Plane Spotting
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 15:
        hardware = str(TriggersDlg.comboBox_rf_plane_spotting_hardware.currentText())
        icao = str(TriggersDlg.textEdit_rf_plane_spotting_icao.toPlainText())
        variable_names = ["hardware","icao"]
        variable_values = [hardware, icao]

    # Data: RDS Keyword
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 16:
        hardware = str(TriggersDlg.comboBox_rf_rds_keyword_hardware.currentText())
        keyword = str(TriggersDlg.textEdit_rf_rds_keyword_keyword.toPlainText())
        frequency = str(TriggersDlg.doubleSpinBox_rf_rds_keyword_frequency.value())
        variable_names = ["hardware","keyword","frequency"]
        variable_values = [hardware, keyword, frequency]

    # Data: Cellular Tower
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 17:
        hardware = str(TriggersDlg.comboBox_rf_cellular_tower_hardware.currentText())
        pci = str(TriggersDlg.spinBox_rf_cellular_tower_pci.value())
        frequency = str(TriggersDlg.doubleSpinBox_rf_cellular_tower_frequency.value())
        variable_names = ["hardware","pci","frequency"]
        variable_values = [hardware, pci, frequency]
        
    # Data: Webserver Curl
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 18:
        ip_address = str(TriggersDlg.textEdit_networking_webserver_curl_ip.toPlainText())
        port = str(TriggersDlg.spinBox_networking_webserver_curl_port.value())
        variable_names = ["ip_address","port"]
        variable_values = [ip_address, port]
        
    # RF: Power Threshold
    elif TriggersDlg.stackedWidget_trigger_info.currentIndex() == 19:
        hardware = str(TriggersDlg.comboBox_rf_power_threshold_hardware.currentText())
        sample_rate = str(TriggersDlg.textEdit_rf_power_threshold_sample_rate.toPlainText())
        frequency = str(TriggersDlg.doubleSpinBox_rf_power_threshold_frequency.value())
        threshold = str(TriggersDlg.spinBox_rf_power_threshold_threshold.value())
        variable_names = ["hardware","sample_rate","frequency","threshold"]
        variable_values = [hardware, sample_rate, frequency, threshold]

    # New Row
    TriggersDlg.tableWidget_trigger_info.setRowCount(TriggersDlg.tableWidget_trigger_info.rowCount() + 1)

    # Filename
    filename_item = QtWidgets.QTableWidgetItem(get_filename)
    filename_item.setTextAlignment(QtCore.Qt.AlignCenter)
    filename_item.setFlags(filename_item.flags() & ~QtCore.Qt.ItemIsEditable)
    TriggersDlg.tableWidget_trigger_info.setItem(TriggersDlg.tableWidget_trigger_info.rowCount()-1,0,filename_item)
    
    # Type
    type_item = QtWidgets.QTableWidgetItem(get_type)
    type_item.setTextAlignment(QtCore.Qt.AlignCenter)
    type_item.setFlags(type_item.flags() & ~QtCore.Qt.ItemIsEditable)
    TriggersDlg.tableWidget_trigger_info.setItem(TriggersDlg.tableWidget_trigger_info.rowCount()-1,1,type_item)

    # Variable Names
    variable_names_item = QtWidgets.QTableWidgetItem(str(variable_names))
    variable_names_item.setTextAlignment(QtCore.Qt.AlignCenter)
    variable_names_item.setFlags(variable_names_item.flags() & ~QtCore.Qt.ItemIsEditable)
    TriggersDlg.tableWidget_trigger_info.setItem(TriggersDlg.tableWidget_trigger_info.rowCount()-1,2,variable_names_item)

    # Variable Values
    variable_values_item = QtWidgets.QTableWidgetItem(str(variable_values))
    variable_values_item.setTextAlignment(QtCore.Qt.AlignCenter)
    variable_values_item.setFlags(variable_values_item.flags() & ~QtCore.Qt.ItemIsEditable)
    TriggersDlg.tableWidget_trigger_info.setItem(TriggersDlg.tableWidget_trigger_info.rowCount()-1,3,variable_values_item)
    
    # Resize the Table
    TriggersDlg.tableWidget_trigger_info.resizeColumnsToContents()
    #TriggersDlg.tableWidget_trigger_info.setColumnWidth(5,300)
    #TriggersDlg.tableWidget_trigger_info.setColumnWidth(6,300)
    TriggersDlg.tableWidget_trigger_info.resizeRowsToContents()
    TriggersDlg.tableWidget_trigger_info.horizontalHeader().setStretchLastSection(False)
    TriggersDlg.tableWidget_trigger_info.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotRemoveClicked(TriggersDlg: QtCore.QObject):
    """ 
    Removes a row from the table of triggers.
    """
    # Remove from Table
    get_current_row = TriggersDlg.tableWidget_trigger_info.currentRow()
    TriggersDlg.tableWidget_trigger_info.removeRow(get_current_row)
    if get_current_row == 0:
        TriggersDlg.tableWidget_trigger_info.setCurrentCell(0,0)
    else:
        TriggersDlg.tableWidget_trigger_info.setCurrentCell(get_current_row-1,0)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotDataFileModifiedBrowseClicked(TriggersDlg: QtCore.QObject):
    """ 
    Browses for a file location.
    """
    # Browse
    directory = os.path.expanduser("~") # Default Directory
    fname = QtWidgets.QFileDialog.getOpenFileName(None,"Select File...", directory, filter="All Files (*.*)")[0]

    # If a Valid File
    if fname != "":
        TriggersDlg.textEdit_filesystem_file_modified_filepath.setPlainText(str(fname))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotDataFolderModifiedBrowseClicked(TriggersDlg: QtCore.QObject):
    """ 
    Browses for a folder location.
    """
    # Browse
    #directory = os.path.expanduser("~") # Default Directory
    
    # Choose Folder
    get_dir = str(QtWidgets.QFileDialog.getExistingDirectory(TriggersDlg, "Select Directory"))

    # Add Directory to the Combobox
    if len(get_dir) > 0:
        TriggersDlg.textEdit_filesystem_folder_modified_folder.setPlainText(str(get_dir))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotEnvironmentalTemperatureValidateClicked(TriggersDlg: QtCore.QObject):
    """ 
    Checks the location format for wttr.in.
    """
    # Retrieve Values
    location = str(TriggersDlg.textEdit_environmental_temperature_city.toPlainText())
    state_code = str(TriggersDlg.textEdit_environmental_temperature_state.toPlainText())
    country_code = str(TriggersDlg.textEdit_environmental_temperature_country.toPlainText())

    # Validate
    if state_code:
        location += f",{state_code}"
    if country_code:
        location += f",{country_code}"
    url = f"http://wttr.in/{location}?format=%t"
    TriggersDlg.label2_environmental_temperature_validate.setText("Validating: " + url)
    QtWidgets.QApplication.processEvents()
    time.sleep(1)
    response = requests.get(url)
    
    if response.status_code == 200:
        temperature = response.text.strip()
        TriggersDlg.label2_environmental_temperature_validate.setText("Valid location: " + temperature)
    else:
        TriggersDlg.label2_environmental_temperature_validate.setText("Invalid location or connection")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotEnvironmentalWeatherValidateClicked(TriggersDlg: QtCore.QObject):
    """ 
    Checks the location format for wttr.in.
    """
    # Retrieve Values
    location = str(TriggersDlg.textEdit_environmental_weather_city.toPlainText())
    state_code = str(TriggersDlg.textEdit_environmental_weather_state.toPlainText())
    country_code = str(TriggersDlg.textEdit_environmental_weather_country.toPlainText())

    # Validate
    if state_code:
        location += f",{state_code}"
    if country_code:
        location += f",{country_code}"
    url = f"http://wttr.in/{location}?format=%C"
    TriggersDlg.label2_environmental_weather_validate.setText("Validating: " + url)
    QtWidgets.QApplication.processEvents()
    time.sleep(1)
    response = requests.get(url)
    
    if response.status_code == 200:
        conditions = response.text.strip()
        TriggersDlg.label2_environmental_weather_validate.setText("Valid location: " + conditions)
    else:
        TriggersDlg.label2_environmental_weather_validate.setText("Invalid location or connection")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotEnvironmentalWindValidateClicked(TriggersDlg: QtCore.QObject):
    """ 
    Checks the location format for wttr.in.
    """
    # Retrieve Values
    location = str(TriggersDlg.textEdit_environmental_wind_city.toPlainText())
    state_code = str(TriggersDlg.textEdit_environmental_wind_state.toPlainText())
    country_code = str(TriggersDlg.textEdit_environmental_wind_country.toPlainText())

    # Validate
    if state_code:
        location += f",{state_code}"
    if country_code:
        location += f",{country_code}"
    url = f"http://wttr.in/{location}?format=%w"
    TriggersDlg.label2_environmental_wind_validate.setText("Validating: " + url)
    QtWidgets.QApplication.processEvents()
    time.sleep(1)
    response = requests.get(url)
    
    if response.status_code == 200:
        wind = response.text.strip()
        TriggersDlg.label2_environmental_wind_validate.setText("Valid location: " + wind)
    else:
        TriggersDlg.label2_environmental_wind_validate.setText("Invalid location or connection")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotEnvironmentalSunriseValidateClicked(TriggersDlg: QtCore.QObject):
    """ 
    Checks the location format for wttr.in.
    """
    # Retrieve Values
    sunrise_sunset = str(TriggersDlg.comboBox_environmental_sunrise_sunset.currentText())
    location = str(TriggersDlg.textEdit_environmental_sunrise_city.toPlainText())
    state_code = str(TriggersDlg.textEdit_environmental_sunrise_state.toPlainText())
    country_code = str(TriggersDlg.textEdit_environmental_sunsrise_country.toPlainText())

    # Validate
    if state_code:
        location += f",{state_code}"
    if country_code:
        location += f",{country_code}"
        
    if sunrise_sunset == "Sunrise":
        url = f"http://wttr.in/{location}?format=%S"
    else:
        url = f"http://wttr.in/{location}?format=%s"
        
    TriggersDlg.label2_environmental_sunrise_validate.setText("Validating: " + url)
    QtWidgets.QApplication.processEvents()
    time.sleep(1)
    response = requests.get(url)
    
    if response.status_code == 200:
        sunrise_sunset_time = response.text.strip()
        TriggersDlg.label2_environmental_sunrise_validate.setText("Valid location: " + sunrise_sunset_time)
    else:
        TriggersDlg.label2_environmental_sunrise_validate.setText("Invalid location or connection")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotDataDetectSSID_GuessClicked(TriggersDlg: QtCore.QObject):
    """ 
    Populates the text edit with interface names selected for the current sensor node.
    """
    # Look at Interfaces for the Proper Component
    if (TriggersDlg.fissure_tab == "Single-Stage") or (TriggersDlg.fissure_tab == "Multi-Stage"):
        component = "attack"
    elif TriggersDlg.fissure_tab == "Archive Replay":
        component = "archive"
    elif TriggersDlg.fissure_tab == "Autorun Playlist":
        component = "attack"
    else:
        component = "attack"
    
    # Track Guess
    get_sensor_node = ['sensor_node1','sensor_node2','sensor_node3','sensor_node4','sensor_node5']
    if TriggersDlg.guess_index >= len(TriggersDlg.dashboard.backend.settings[get_sensor_node[TriggersDlg.dashboard.active_sensor_node]][component]):
        TriggersDlg.guess_index = 0
        
    # Get Interface Name
    start_point = TriggersDlg.guess_index
    for n in range(start_point,len(TriggersDlg.dashboard.backend.settings[get_sensor_node[TriggersDlg.dashboard.active_sensor_node]][component])):            
        TriggersDlg.guess_index = TriggersDlg.guess_index + 1
        get_interface = TriggersDlg.dashboard.backend.settings[get_sensor_node[TriggersDlg.dashboard.active_sensor_node]][component][n][4]
        if len(get_interface) > 0:
            TriggersDlg.textEdit_rf_detect_ssid_interface.setPlainText(get_interface)
            break