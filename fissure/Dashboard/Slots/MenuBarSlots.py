from PyQt5 import QtCore, QtGui, QtWidgets

import fissure.utils
import os
import re
import subprocess
import yaml
import random
import qasync

from fissure.Dashboard.Slots import (
    # ArchiveTabSlots,
    # AttackTabSlots,
    # DashboardSlots,
    IQDataTabSlots,
    # LibraryTabSlots,
    # LogTabSlots,
    # MenuBarSlots,
    # PDTabSlots,
    # SensorNodesTabSlots,
    # StatusBarSlots,
    # TopBarSlots,
    TSITabSlots,
)

from fissure.Dashboard.UI_Components.Qt5 import (
    CustomColor
)


def __lightMode__(dashboard: QtWidgets.QMainWindow):
    """
    Set default values for Light Mode

    :param dashboard: FISSURE Dashboard
    :type dashboard: QtWidgets.QMainWindow
    """
    dashboard.window.actionLight_Mode.setChecked(True)
    dashboard.window.actionDark_Mode.setChecked(False)
    dashboard.window.actionCustom_Mode.setChecked(False)
    dashboard.backend.settings.update(
        {
            "color1": "#F4F4F4",  # "rgb(244, 244, 244)"
            "color2": "#FBFBFB",  # "rgb(251, 251, 251)"
            "color3": "#17365D",
            "color4": "#000000",
            "color5": "#FFFFFF",
            "color6": "#FEFEFE",
            "color7": "#EFEFEF",
            "color8": "#FEFEFE",
            "color9": "#EFEFEF",
            "color10": "#FEFEFE",
            "color11": "#F8F8F8",
            "color12": "#000000",
            "color13": "#C0C0C0",
            "icon_style": "Light",
            "color_mode": "Light Mode",
        }
    )


def __darkMode__(dashboard: QtWidgets.QMainWindow):
    """
    Set default values for Dark Mode

    :param dashboard: FISSURE Dashboard
    :type dashboard: QtWidgets.QMainWindow
    """
    dashboard.window.actionLight_Mode.setChecked(False)
    dashboard.window.actionDark_Mode.setChecked(True)
    dashboard.window.actionCustom_Mode.setChecked(False)
    dashboard.backend.settings.update(
        {
            "color1": "#121212",  # Background
            "color2": "#292929",  # Frame Background
            "color3": "#002D63",  # Label Background
            "color4": "#CCCCCC",  # Label Text
            "color5": "#444444",  # Text Edit Background
            "color6": "#AAAAAA",  # Button Gradient 1
            "color7": "#666666",  # Button Gradient 2
            "color8": "#DDDDDD",  # Disabled Gradient 1
            "color9": "#999999",  # Disabled Gradient 2
            "color10": "#AFAFAF",  # Hover Gradient 1
            "color11": "#6F6F6F",  # Hover Gradient 2
            "color12": "#000000",  # Button Text
            "color13": "#666666",  # Disabled Text
            "icon_style": "Dark",
            "color_mode": "Dark Mode",
        }
    )


def __customMode__(dashboard: QtWidgets.QMainWindow, random_clicked=False):
    """
    Set default values for Custom Mode

    :param dashboard: FISSURE Dashboard
    :type dashboard: QtWidgets.QMainWindow
    """
    # Random Clicked in the Menu
    if random_clicked == True:
        dashboard.window.actionLight_Mode.setChecked(False)
        dashboard.window.actionDark_Mode.setChecked(False)
        dashboard.window.actionCustom_Mode.setChecked(True)

        r = lambda: random.randint(0,255)
        if random.randint(0,1) == 0:
            random_icon_style = "Light"
        else:
            random_icon_style = "Dark"
        dashboard.backend.settings.update(
            {
                "color1": '#%02X%02X%02X' % (r(),r(),r()),  # Background
                "color2": '#%02X%02X%02X' % (r(),r(),r()),  # Frame Background
                "color3": '#%02X%02X%02X' % (r(),r(),r()),  # Label Background
                "color4": '#%02X%02X%02X' % (r(),r(),r()),  # Label Text
                "color5": '#%02X%02X%02X' % (r(),r(),r()),  # Text Edit Background
                "color6": '#%02X%02X%02X' % (r(),r(),r()),  # Button Gradient 1
                "color7": '#%02X%02X%02X' % (r(),r(),r()),  # Button Gradient 2
                "color8": '#%02X%02X%02X' % (r(),r(),r()),  # Disabled Gradient 1
                "color9": '#%02X%02X%02X' % (r(),r(),r()),  # Disabled Gradient 2
                "color10": '#%02X%02X%02X' % (r(),r(),r()),  # Hover Gradient 1
                "color11": '#%02X%02X%02X' % (r(),r(),r()),  # Hover Gradient 2
                "color12": '#%02X%02X%02X' % (r(),r(),r()),  # Button Text
                "color13": '#%02X%02X%02X' % (r(),r(),r()),  # Disabled Text
                "icon_style": random_icon_style,
                "color_mode": "Custom Mode",
            }
        )
        return 0

    # Custom Clicked in the Menu
    else:
        # Open the Custom Color Dialog
        custom_color_dlg = CustomColor(parent=dashboard)
        custom_color_dlg.show()
        custom_color_dlg.exec_()

        # Apply Clicked
        get_value = custom_color_dlg.return_value
        if get_value == "1":
            dashboard.window.actionLight_Mode.setChecked(False)
            dashboard.window.actionDark_Mode.setChecked(False)
            dashboard.window.actionCustom_Mode.setChecked(True)
            return 0
        else:
            return -1


def __updateSettings__(stylesheet: str, settings: dict) -> str:
    """
    Update the stylesheet with values from the settings dictionary

    :param stylesheet: FISSURE Stylesheet
    :type stylesheet: str
    :param settings: FISSURE Settings
    :type settings: dict
    :return: updated stylesheet
    :rtype: str
    """
    icon_style: str = settings.get("icon_style")
    if icon_style is None:
        icon_style = "light mode"

    # Colors
    stylesheet = re.sub(r"@color1\b", settings.get("color1"), stylesheet)
    stylesheet = re.sub(r"@color2\b", settings.get("color2"), stylesheet)
    stylesheet = re.sub(r"@color3\b", settings.get("color3"), stylesheet)
    stylesheet = re.sub(r"@color4\b", settings.get("color4"), stylesheet)
    stylesheet = re.sub(r"@color5\b", settings.get("color5"), stylesheet)
    stylesheet = re.sub(r"@color6\b", settings.get("color6"), stylesheet)
    stylesheet = re.sub(r"@color7\b", settings.get("color7"), stylesheet)
    stylesheet = re.sub(r"@color8\b", settings.get("color8"), stylesheet)
    stylesheet = re.sub(r"@color9\b", settings.get("color9"), stylesheet)
    stylesheet = re.sub(r"@color10\b", settings.get("color10"), stylesheet)
    stylesheet = re.sub(r"@color11\b", settings.get("color11"), stylesheet)
    stylesheet = re.sub(r"@color12\b", settings.get("color12"), stylesheet)
    stylesheet = re.sub(r"@color13\b", settings.get("color13"), stylesheet)

    # Dark Widgets
    if icon_style.lower() == "dark":
        stylesheet = re.sub(r"@unchecked_enabled\b", "dark-unchecked.png", stylesheet)
        stylesheet = re.sub(r"@checked_enabled\b", "dark-checked.png", stylesheet)
        stylesheet = re.sub(r"@checked_disabled\b", "dark-checked-disabled.png", stylesheet)
        stylesheet = re.sub(r"@unchecked_disabled\b", "dark-unchecked-disabled.png", stylesheet)
        stylesheet = re.sub(r"@down_arrow_enabled\b", "dark-down-arrow.png", stylesheet)
        stylesheet = re.sub(r"@down_arrow_disabled\b", "dark-down-arrow-disabled.png", stylesheet)
        stylesheet = re.sub(r"@up_arrow_enabled\b", "dark-up-arrow.png", stylesheet)
        stylesheet = re.sub(r"@up_arrow_disabled\b", "dark-up-arrow-disabled.png", stylesheet)
        stylesheet = re.sub(r"@radio_unchecked_enabled\b", "radio-unchecked.png", stylesheet)
        stylesheet = re.sub(r"@radio_checked_enabled\b", "radio-checked.png", stylesheet)
    
    # Light Widgets
    else:
        stylesheet = re.sub(r"@unchecked_enabled\b", "light-unchecked.png", stylesheet)
        stylesheet = re.sub(r"@checked_enabled\b", "light-checked.png", stylesheet)
        stylesheet = re.sub(r"@checked_disabled\b", "light-checked-disabled.png", stylesheet)
        stylesheet = re.sub(r"@unchecked_disabled\b", "light-unchecked-disabled.png", stylesheet)
        stylesheet = re.sub(r"@down_arrow_enabled\b", "light-down-arrow.png", stylesheet)
        stylesheet = re.sub(r"@down_arrow_disabled\b", "light-down-arrow-disabled.png", stylesheet)
        stylesheet = re.sub(r"@up_arrow_enabled\b", "light-up-arrow.png", stylesheet)
        stylesheet = re.sub(r"@up_arrow_disabled\b", "light-up-arrow-disabled.png", stylesheet)
        stylesheet = re.sub(r"@radio_unchecked_enabled\b", "light-radio.png", stylesheet)
        stylesheet = re.sub(r"@radio_checked_enabled\b", "light-radio-checked.png", stylesheet)
    
    # Icon Directory
    stylesheet = stylesheet.replace("@icon_path", os.path.join(fissure.utils.UI_DIR, "Icons"))

    return stylesheet


@QtCore.pyqtSlot(QtWidgets.QMainWindow, str)
def setStyleSheet(dashboard: QtWidgets.QMainWindow, mode: str = "light"):
    """
    Set the Dashboard StyleSheet

    :param dashboard: FISSURE Dashboard Window
    :type dashboard: QtWidgets.QMainWindow
    :param mode: color mode, defaults to "light"
    :type mode: str, optional
    """
    stylesheet = None
    if mode.lower() == "random":
        get_mode = "custom"
    else:
        get_mode = mode.lower()
    with open(os.path.join(fissure.utils.UI_DIR, "Style_Sheets", f"{get_mode.lower()}.css"), "r") as css_file:
        stylesheet = str(css_file.read())

    # Set Defaults?
    if mode.lower() == "light":
        __lightMode__(dashboard)
    elif mode.lower() == "dark":
        __darkMode__(dashboard)
    elif mode.lower() == "custom":
        # Prevent Check
        dashboard.window.actionCustom_Mode.blockSignals(True)
        dashboard.window.actionCustom_Mode.setChecked(False)
        dashboard.window.actionCustom_Mode.blockSignals(False)
        ret = __customMode__(dashboard)
        
        # Cancel Clicked
        if ret == -1:
            return
    elif mode.lower() == "random":
        __customMode__(dashboard, random_clicked=True)

    stylesheet = __updateSettings__(stylesheet, dashboard.backend.settings)

    # Fix Dragon OS Padding
    if (dashboard.backend.os_info == "DragonOS Focal") or (dashboard.backend.os_info == "DragonOS FocalX"):
        stylesheet = stylesheet.replace("@menu_hover_padding", "0px")
    else:
        stylesheet = stylesheet.replace("@menu_hover_padding", "2px")

    # Set Style Sheet
    dashboard.setStyleSheet(stylesheet)
    dashboard.menuBar().setStyleSheet(stylesheet)
    dashboard.centralWidget().setStyleSheet(stylesheet)

    # Refresh Custom Widgets
    refreshCustomWidgets(dashboard)


def refreshCustomWidgets(dashboard: QtWidgets.QMainWindow):
    """
    Reloads the custom widgets for the new stylesheet settings.
    """
    if dashboard.ui.stackedWidget3_iq.currentIndex() == 0:
        IQDataTabSlots._slotIQ_TabClicked(dashboard, "pushButton1_iq_tab_record")
    elif dashboard.ui.stackedWidget3_iq.currentIndex() == 1:
        IQDataTabSlots._slotIQ_TabClicked(dashboard, "pushButton1_iq_tab_playback")
    elif dashboard.ui.stackedWidget3_iq.currentIndex() == 2:
        IQDataTabSlots._slotIQ_TabClicked(dashboard, "pushButton1_iq_tab_inspection")
    elif dashboard.ui.stackedWidget3_iq.currentIndex() == 3:
        IQDataTabSlots._slotIQ_TabClicked(dashboard, "pushButton1_iq_tab_crop")
    elif dashboard.ui.stackedWidget3_iq.currentIndex() == 4:
        IQDataTabSlots._slotIQ_TabClicked(dashboard, "pushButton1_iq_tab_convert")
    elif dashboard.ui.stackedWidget3_iq.currentIndex() == 5:
        IQDataTabSlots._slotIQ_TabClicked(dashboard, "pushButton1_iq_tab_append")
    elif dashboard.ui.stackedWidget3_iq.currentIndex() == 6:
        IQDataTabSlots._slotIQ_TabClicked(dashboard, "pushButton1_iq_tab_transfer")
    elif dashboard.ui.stackedWidget3_iq.currentIndex() == 7:
        IQDataTabSlots._slotIQ_TabClicked(dashboard, "pushButton1_iq_tab_timeslot")
    elif dashboard.ui.stackedWidget3_iq.currentIndex() == 8:
        IQDataTabSlots._slotIQ_TabClicked(dashboard, "pushButton1_iq_tab_overlap")
    elif dashboard.ui.stackedWidget3_iq.currentIndex() == 9:
        IQDataTabSlots._slotIQ_TabClicked(dashboard, "pushButton1_iq_tab_resample")
    elif dashboard.ui.stackedWidget3_iq.currentIndex() == 10:
        IQDataTabSlots._slotIQ_TabClicked(dashboard, "pushButton1_iq_tab_ofdm")
    elif dashboard.ui.stackedWidget3_iq.currentIndex() == 11:
        IQDataTabSlots._slotIQ_TabClicked(dashboard, "pushButton1_iq_tab_normalize")
    elif dashboard.ui.stackedWidget3_iq.currentIndex() == 12:
        IQDataTabSlots._slotIQ_TabClicked(dashboard, "pushButton1_iq_tab_strip")
    elif dashboard.ui.stackedWidget3_iq.currentIndex() == 13:
        IQDataTabSlots._slotIQ_TabClicked(dashboard, "pushButton1_iq_tab_split")
    elif dashboard.ui.stackedWidget3_iq.currentIndex() == 14:
        IQDataTabSlots._slotIQ_TabClicked(dashboard, "pushButton1_iq_tab_ook")

    dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])
    dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
    dashboard.iq_matplotlib_widget.draw()
    dashboard.mpl_toolbar.setStyleSheet("color:" + dashboard.backend.settings['color4'])

    TSITabSlots._slotTSI_RefreshPlotClicked(dashboard)


@QtCore.pyqtSlot()
def openUserManual():
    os.system(f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'index.html')}")


def _slotMenuOptionsClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the Options dialog for the current tab."""
    dlg = fissure.Dashboard.UI_Components.Qt5.OptionsDialog(
        dashboard,
        opening_tab=dashboard.ui.tabWidget.tabText(dashboard.ui.tabWidget.currentIndex()),
        settings_dictionary=dashboard.backend.settings,
    )
    dlg.show()
    dlg.exec_()

    # OK Clicked  # Update how options get saved/read
    # get_value = dlg.return_value  # No longer needed, async messages sent on accept()
    # if len(get_value) > 0:
        # dashboard.backend.settings = dlg.settings_dictionary

        # # Update Settings Across Components
        # msg = {
        # MessageFields.IDENTIFIER: Identifiers.DASHBOARD,
        # MessageFields.MESSAGE_NAME: "Update FISSURE Settings"
        # }
        # self.hiprfisr_socket.send_msg(MessageTypes.COMMANDS, **msg)


@QtCore.pyqtSlot()
def _slotMenuUHD_FindDevicesClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a message box and copies the results of "uhd_find_devices" """
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "uhd_find_devices"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "uhd_find_devices"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "uhd_find_devices"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuHackrfInfoClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a message box and copies the results of "hackrf_info" """
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "hackrf_info"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "hackrf_info"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "hackrf_info"', shell=True)

@QtCore.pyqtSlot()
def _slotMenuLsusbClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a message box and copies the results of "lsusb" """
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "lsusb"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "lsusb"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "lsusb"', shell=True)

@QtCore.pyqtSlot()
def _slotMenuIwconfigClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a message box and copies the results of "iwconfig" """
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "iwconfig"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "iwconfig"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "iwconfig"', shell=True)

@QtCore.pyqtSlot()
def _slotMenuLoadConfigurationClicked(dashboard: QtWidgets.QMainWindow):
    """Replaces the fissure_config.yaml with another YAML file. The dashboard reloads itself with the new settings. Should it inform the other components? TODO"""
    # Look for a YAML File
    directory = fissure.utils.USER_CONFIGS_DIR
    fname = QtWidgets.QFileDialog.getOpenFileName(
        None, "Select Configuration File...", directory, filter="Configuration Files (*.yaml);;All Files (*.*)"
    )[0]

    # If a Valid File
    if fname != "":
        # Load Settings from YAML File
        yaml_config_file = open(fname)
        dashboard.backend.settings = yaml.load(yaml_config_file, yaml.FullLoader)
        yaml_config_file.close()

        # Dump Dictionary to File
        stream = open(os.path.join(fissure.utils.YAML_DIR, "YAML", "fissure_config.yaml"), "w")
        yaml.dump(dashboard.backend.settings, stream, default_flow_style=False, indent=5)

        # Update Logging
        dashboard.backend.updateLoggingLevels(
            dashboard.backend.settings["console_logging_level"], dashboard.backend.settings["file_logging_level"]
        )

        # # Update Settings Across Components
        # msg = {
        #         MessageFields.IDENTIFIER: Identifiers.DASHBOARD,
        #         MessageFields.MESSAGE_NAME: "Update FISSURE Settings"
        # }
        # self.hiprfisr_socket.send_msg(MessageTypes.COMMANDS, **msg)

        # Update Hardware
        # self.configureTSI_Hardware()
        # self.configurePD_Hardware()
        # self.configureAttackHardware()
        # self.configureIQ_Hardware()
        # self.configureArchiveHardware()


@QtCore.pyqtSlot()
def _slotMenuSaveConfigurationClicked(dashboard: QtWidgets.QMainWindow):
    """Saves a new formatted YAML file with all the system configuration variables and values."""
    # Select a Filepath
    directory = fissure.utils.USER_CONFIGS_DIR

    # This Method Allows ".yaml" to be Added to the End of the Name
    dialog = QtWidgets.QFileDialog()
    dialog.setDirectory(directory)
    dialog.setFilter(dialog.filter() | QtCore.QDir.Hidden)
    dialog.setDefaultSuffix("yaml")
    dialog.setAcceptMode(QtWidgets.QFileDialog.AcceptSave)
    dialog.setNameFilters(["Configuration Files (*.yaml)"])
    if dialog.exec_() == QtWidgets.QDialog.Accepted:
        file_name = str(dialog.selectedFiles()[0])
    else:
        file_name = ""

    # Valid file
    if file_name:
        # Dump Dictionary to File
        stream = open(file_name, "w")
        yaml.dump(dashboard.backend.settings, stream, default_flow_style=False, indent=5)


@QtCore.pyqtSlot()
def _slotMenuIwlistScanClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the 'iwlist scan' command in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "sudo iwlist scan"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "sudo iwlist scan"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "sudo iwlist scan"', shell=True)

@QtCore.pyqtSlot()
def _slotMenuKismetClicked(dashboard: QtWidgets.QMainWindow):
    """Opens Kismet for viewing wireless networks."""
    # Run Kismet
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        command_text = "gnome-terminal -- kismet &"
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        command_text = "qterminal -e kismet &"
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        command_text = 'lxterminal -e kismet &'
    proc = subprocess.Popen(command_text, shell=True)


@QtCore.pyqtSlot()
def _slotMenuQSpectrumAnalyzerClicked(dashboard: QtWidgets.QMainWindow):
    """Opens QSpectrumAnalyzer for viewing RF signals."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "qspectrumanalyzer"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "qspectrumanalyzer"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "qspectrumanalyzer"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuGQRX_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens GQRX for viewing RF signals."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "gqrx"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "gqrx"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "gqrx"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuDump1090_Clicked(dashboard: QtWidgets.QMainWindow):
    """Launches Dump1090 for RTL2832U devices."""
    # Run Dump1090
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    dump1090_directory = os.path.expanduser("~/Installed_by_FISSURE/dump1090/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- "
            + expect_script_filepath
            + ' "./dump1090 --interactive --net --freq 1090000000 --net-http-port 8081"',
            cwd=dump1090_directory,
            shell=True,
        )    
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e "
            + expect_script_filepath
            + ' "./dump1090 --interactive --net --freq 1090000000 --net-http-port 8081"',
            cwd=dump1090_directory,
            shell=True,
        )    
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' 
            + expect_script_filepath 
            + ' "./dump1090 --interactive --net --freq 1090000000 --net-http-port 8081"', 
            cwd=dump1090_directory, 
            shell=True
        )
    subprocess.run(["xdg-open", "http://127.0.0.1:8081"])


@QtCore.pyqtSlot()
def _slotMenuLimeSuite_Clicked(dashboard: QtWidgets.QMainWindow):
    """Launches LimeSuiteGUI for the LimeSDR."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "LimeSuiteGUI"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "LimeSuiteGUI"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "LimeSuiteGUI"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuMonitorModeToolClicked(dashboard: QtWidgets.QMainWindow):
    """Launches the CLI Tool for quickly changing wireless interface configurations."""
    # Run Monitor Mode Tool
    monitor_mode_tool_directory = os.path.join(fissure.utils.TOOLS_DIR, "Monitor_Mode_Tool")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- python3 monitor_mode_tool.py", cwd=monitor_mode_tool_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e python3 monitor_mode_tool.py", cwd=monitor_mode_tool_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen("lxterminal -e python3 monitor_mode_tool.py", cwd=monitor_mode_tool_directory, shell=True)


@QtCore.pyqtSlot()
def _slotMenuLoadBladeRF_FPGA_Clicked(dashboard: QtWidgets.QMainWindow):
    """Loads the FPGA image for bladeRF. Sometimes required after plugging in."""
    # Select FPGA Image File (.rbf)
    dialog = QtWidgets.QFileDialog(dashboard)
    directory = "/usr/share/Nuand/bladeRF"  # Default Directory
    dialog.setDirectory(directory)
    dialog.setNameFilters(["FPGA Image (*.rbf)"])
    get_file = None
    if dialog.exec_():
        for d in dialog.selectedFiles():
            get_file = d

    # Issue Load Command
    if get_file != None:
        try:
            if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
                command_text = "gnome-terminal -- bladeRF-cli -l " + str(get_file) + " &"
            elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
                command_text = "qterminal -e bladeRF-cli -l " + str(get_file) + " &"
            elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
                command_text = 'lxterminal -e bladeRF-cli -l ' + str(get_file) + ' &'
            proc = subprocess.Popen(command_text, shell=True)
        except:
            dashboard.errorMessage("Error Loading FPGA Image")


@QtCore.pyqtSlot()
def _slotMenuGSM_UplinkDownlinkClicked(dashboard: QtWidgets.QMainWindow):
    """Opens GRC with standalone flow graph."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "gsm_uplink_downlink.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuJ2497_DemodMethod1Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens GRC with standalone flow graph."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "j2497_demod_method1.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuWifiRxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens GRC with standalone flow graph."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "wifi_rx.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuWifiTxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens GRC with standalone flow graph."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "wifi_tx.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuRdsRxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens GRC with standalone flow graph."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "rds_rx.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuRdsTxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens GRC with standalone flow graph."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "rds_tx.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuRdsRx2Clicked(dashboard: QtWidgets.QMainWindow):
    """Open gr-rds rds_rx.grc GUI for RTL2832U."""
    # # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        rds_filepath = os.path.join(fissure.utils.FISSURE_ROOT, "Custom_Blocks", "maint-3.8", "gr-rds", "examples")
        rds_command = """grcc \\\"""" + rds_filepath + """rds_rx.grc\\\" -o \\\"""" + rds_filepath + """\\\" -r"""
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "' + rds_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        if dashboard.backend.os_info == "DragonOS Focal" or dashboard.backend.os_info == "DragonOS FocalX":
            proc = subprocess.Popen(
                "qterminal -e "
                + expect_script_filepath
                + ' "grcc /usr/src/gr-rds/examples/rds_rx.grc -o /usr/src/gr-rds/examples/ -r "',
                shell=True,
            )
        else:
            rds_command = "grcc " + os.path.dirname(os.path.realpath(__file__)) + "/Custom_Blocks/maint-3.10/gr-rds/examples/rds_rx.grc -o " + os.path.dirname(os.path.realpath(__file__)) + "/Custom_Blocks/maint-3.10/gr-rds/examples/ -r"
            proc = subprocess.Popen('qterminal -e ' + expect_script_filepath + ' "' + rds_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        rds_command = "grcc " + os.path.dirname(os.path.realpath(__file__)) + "/Custom_Blocks/maint-3.10/gr-rds/examples/rds_rx.grc -o " + os.path.dirname(os.path.realpath(__file__)) + "/Custom_Blocks/maint-3.10/gr-rds/examples/ -r"
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + rds_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuSrsLTE_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens the terminals with locations for manually running srsLTE programs."""
    # Two Terminals
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        srsLTE_dir = os.path.expanduser("~/Installed_by_FISSURE/srsRAN/srsepc")
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "sudo srsepc ~/.config/srsran/epc.conf"',
            cwd=srsLTE_dir,
            shell=True,
        )
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "sudo srsenb ~/.config/srsran/enb.conf"',
            cwd=srsLTE_dir,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        if dashboard.backend.os_info == "DragonOS Focal" or dashboard.backend.os_info == "DragonOS FocalX":
            srsLTE_dir = "/usr/src/srsRAN/srsepc"
            proc = subprocess.Popen(
                "qterminal -e " + expect_script_filepath + ' "sudo srsepc ~/.config/srsran/epc.conf"',
                cwd=srsLTE_dir,
                shell=True,
            )
            proc = subprocess.Popen(
                "qterminal -e " + expect_script_filepath + ' "sudo srsenb ~/.config/srsran/enb.conf"',
                cwd=srsLTE_dir,
                shell=True,
            )
        else:
            srsLTE_dir = os.path.expanduser("~/Installed_by_FISSURE/srsRAN/srsepc")
            proc = subprocess.Popen('qterminal -e ' + expect_script_filepath + ' "sudo srsepc ~/.config/srsran/epc.conf"', cwd=srsLTE_dir, shell=True)
            proc = subprocess.Popen('qterminal -e ' + expect_script_filepath + ' "sudo srsenb ~/.config/srsran/enb.conf"', cwd=srsLTE_dir, shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        srsLTE_dir = os.path.expanduser("~/Installed_by_FISSURE/srsRAN/srsepc")
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "sudo srsepc ~/.config/srsran/epc.conf"', cwd=srsLTE_dir, shell=True)
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "sudo srsenb ~/.config/srsran/enb.conf"', cwd=srsLTE_dir, shell=True)
   
    # # Two Tabs
    # proc = subprocess.Popen('gnome-terminal --window --working-directory="' + srsLTE_dir + '" ' + \
    # '--tab --working-directory="' + srsLTE_dir + '" ', \
    # cwd=srsLTE_dir, shell=True)


@QtCore.pyqtSlot()
def _slotMenuPaintTxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens GRC with standalone flow graph."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "paint_tx.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuX10_TxRxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "x10_tx_rx.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuWifiRelayClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "wifi_relay.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuWiresharkClicked(dashboard: QtWidgets.QMainWindow):
    """Opens Wireshark."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "wireshark"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "wireshark"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "wireshark"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuBluetoothctlClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with bluetoothctl."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "bluetoothctl"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "bluetoothctl"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "bluetoothctl"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuNoiseSourceClicked(dashboard: QtWidgets.QMainWindow):
    """Opens GRC with standalone flow graph."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "noise_source.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuLessonOpenBTS_Clicked():
    """Opens the html file in a browser."""
    os.system(f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'Lessons', 'HTML', 'Lesson1_OpenBTS.html')}")


@QtCore.pyqtSlot()
def _slotMenuV2VerifierClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the V2Verifier GUI for DSRC testing."""
    # Issue the Command
    command_text = "sudo python3 main.py local dsrc -g"
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    v2verifier_dir = os.path.join(fissure.utils.TOOLS_DIR, "v2verifier-master")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + command_text + '"', shell=True, cwd=v2verifier_dir
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "' + command_text + '"', shell=True, cwd=v2verifier_dir
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "' + command_text + '"', shell=True, cwd=v2verifier_dir
        )


@QtCore.pyqtSlot()
def _slotMenuV2VerifierWifiTxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the V2Verifier wifi_tx flow graph."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "v2verifier_wifi_tx.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuV2VerifierWifiRxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the V2Verifier wifi_rx flow graph."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "v2verifier_wifi_rx.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuFALCON_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens FALCON for LTE monitoring."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "FalconGUI"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        if dashboard.backend.os_info == "DragonOS Focal" or dashboard.backend.os_info == "DragonOS FocalX":
            proc = subprocess.Popen(
                "qterminal -e " + expect_script_filepath + ' "/usr/src/falcon/build/src/gui/FalconGUI"', shell=True
            )
        else:
            proc = subprocess.Popen('qterminal -e ' + expect_script_filepath + ' "FalconGUI"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "FalconGUI"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuCyberChefClicked():
    """Opens CyberChef in a browser"""
    os.system("xdg-open https://gchq.github.io/CyberChef/")


@QtCore.pyqtSlot()
def _slotMenuESP8266BeaconSpammerClicked():
    """Opens ESP8266 Beacon Spammer for Wifi in Arduino IDE."""
    # Open Arduino IDE
    ibf_directory = os.path.expanduser("~/Installed_by_FISSURE/Esp8266_listen_trigger/")
    proc = subprocess.Popen("sudo arduino " + ibf_directory + "Esp8266_listen_trigger.ino &", shell=True)


@QtCore.pyqtSlot()
def _slotMenuESP32BLE_BeaconSpamClicked():
    """Opens ESP32 Beacon Spammer for BLE in Arduino IDE."""
    # Open Arduino IDE
    ibf_directory = os.path.expanduser("~/Installed_by_FISSURE/Esp8266_listen_trigger/ESP32-BLEBeaconSpam/")
    proc = subprocess.Popen("sudo arduino " + ibf_directory + "ESP32-BLEBeaconSpam.ino &", shell=True)


@QtCore.pyqtSlot()
def _slotMenuMinicomClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a minicom in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "sudo minicom"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "sudo minicom"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "sudo minicom"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuPuttyClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a PuTTY in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "sudo putty"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "sudo putty"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "sudo putty"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuOpenHAB_Clicked():
    """Opens a PuTTY in a terminal."""
    # Open a browser to openHAB
    os.system("xdg-open http://127.0.0.1:8080")


@QtCore.pyqtSlot()
def _slotMenuStart_openHAB_ServiceClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a PuTTY in a terminal."""
    # Issue the Command
    command_text = "sudo /bin/systemctl start openhab.service"
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "' + command_text + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + command_text + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + command_text + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuStop_openHAB_ServiceClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a PuTTY in a terminal."""
    # Stop openHAB Service
    command_text = "sudo /bin/systemctl stop openhab.service"
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "' + command_text + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + command_text + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + command_text + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuIEEE_802_15_4_transceiver_OQPSK_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(
        fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "ieee_802_15_4_transceiver_OQPSK.grc"
    )
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuRtlZwave908_Clicked(dashboard: QtWidgets.QMainWindow):
    """Runs rtl_sdr and rtl_zwave at 908.42 MHz."""
    # Run rtl_sdr and rtl_zwave
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    rtl_zwave_directory = os.path.expanduser("~/Installed_by_FISSURE/rtl-zwave-master/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "rtl_sdr -f 908.42e6 -s 2048000 -g 25 - | ./rtl_zwave"',
            cwd=rtl_zwave_directory,
            shell=True,
        )    
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "rtl_sdr -f 908.42e6 -s 2048000 -g 25 - | ./rtl_zwave"',
            cwd=rtl_zwave_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "rtl_sdr -f 908.42e6 -s 2048000 -g 25 - | ./rtl_zwave"',
            cwd=rtl_zwave_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuRtlZwave916_Clicked(dashboard: QtWidgets.QMainWindow):
    """Runs rtl_sdr and rtl_zwave at 916 MHz."""
    # Run rtl_sdr and rtl_zwave
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    rtl_zwave_directory = os.path.expanduser("~/Installed_by_FISSURE/rtl-zwave-master/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "rtl_sdr -f 916e6 -s 2048000 -g 25 - | ./rtl_zwave"',
            cwd=rtl_zwave_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "rtl_sdr -f 916e6 -s 2048000 -g 25 - | ./rtl_zwave"',
            cwd=rtl_zwave_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "rtl_sdr -f 916e6 -s 2048000 -g 25 - | ./rtl_zwave"', 
            cwd=rtl_zwave_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuWavingZ_908_Clicked(dashboard: QtWidgets.QMainWindow):
    """Runs rtl_sdr and wave-in at 908.42 MHz."""
    # Run rtl_sdr and waving-z
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    rtl_zwave_directory = os.path.expanduser("~/Installed_by_FISSURE/waving-z/build/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- "
            + expect_script_filepath
            + ' "rtl_sdr -f 908420000 -s 2000000 -g 25  - | ./wave-in -u"',
            cwd=rtl_zwave_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "rtl_sdr -f 908420000 -s 2000000 -g 25  - | ./wave-in -u"',
            cwd=rtl_zwave_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "rtl_sdr -f 908420000 -s 2000000 -g 25  - | ./wave-in -u"', 
            cwd=rtl_zwave_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuWavingZ_916_Clicked(dashboard: QtWidgets.QMainWindow):
    """Runs rtl_sdr and wave-in at 916 MHz."""
    # Run rtl_sdr and waving-z
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    rtl_zwave_directory = os.path.expanduser("~/Installed_by_FISSURE/waving-z/build/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- "
            + expect_script_filepath
            + ' "rtl_sdr -f 916000000 -s 2000000 -g 25  - | ./wave-in -u"',
            cwd=rtl_zwave_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "rtl_sdr -f 916000000 -s 2000000 -g 25  - | ./wave-in -u"',
            cwd=rtl_zwave_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "rtl_sdr -f 916000000 -s 2000000 -g 25  - | ./wave-in -u"', 
            cwd=rtl_zwave_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuStandaloneTpmsRxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "tpms_rx.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuStandaloneTpmsTxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "tpms_tx.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuStandaloneZwaveTxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "zwave_tx.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuStandaloneZwaveRxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "zwave_rx.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot(QtWidgets.QMainWindow)
def _slotMenuFileExitClicked(dashboard: QtWidgets.QMainWindow):
    """Exits FISSURE"""
    # Close the window, which will trigger the closeEvent. Same as hitting the 'X'.
    dashboard.close()


@QtCore.pyqtSlot()
def _slotMenuLimeUtilUpdateClicked(dashboard: QtWidgets.QMainWindow):
    """Runs 'LimeUtil --update' to fix Gateware version mismatch issues."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "LimeUtil --update"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "LimeUtil --update"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "LimeUtil --update"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuBaudlineClicked(dashboard: QtWidgets.QMainWindow):
    """Opens baudline - the time-frequency browser designed for scientific visualization of the spectral domain."""
    # Issue the Command
    baudline_command = os.path.expanduser("~/Installed_by_FISSURE/baudline_1.08_linux_x86_64/baudline")
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + baudline_command + '"', shell=True
        )        
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + baudline_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + baudline_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuURH_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens Universal Radio Hacker."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "urh"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "urh"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "urh"', shell=True)


@QtCore.pyqtSlot()
def _slotMenu4G_IMSI_CatcherClicked(dashboard: QtWidgets.QMainWindow):
    """Runs 'start_sniffing.py' to sniff for towers, mimic a tower, and print IMSIs for phones joining the network."""
    # Open the Band Chooser Dialog
    new_label_text = "Choose 4G Band"
    new_items = [
        "2",
        "3",
        "4",
        "5",
        "7",
        "12",
        "13",
        "14",
        "17",
        "20",
        "25",
        "26",
        "29",
        "30",
        "40",
        "41",
        "46",
        "48",
        "66",
        "71",
    ]
    chooser_dlg = fissure.Dashboard.UI_Components.Qt5.MiscChooser(
        parent=dashboard, label_text=new_label_text, chooser_items=new_items
    )
    chooser_dlg.show()
    chooser_dlg.exec_()

    # Run the Script
    get_value = chooser_dlg.return_value
    if len(get_value) > 0:
        script_location = os.path.join(fissure.utils.TOOLS_DIR, "YAML", "IMSI-Catcher_4G", "start_sniffing.py")
        cell_search_binary_location = os.path.expanduser("~/Installed_by_FISSURE/srsRAN/build/lib/examples/cell_search")
        if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
            command_text = (
                'gnome-terminal -- python3 "'
                + script_location
                + '" -b '
                + get_value
                + " "
                + cell_search_binary_location
                + " &"
            )
        elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
            if dashboard.backend.os_info == "DragonOS Focal" or dashboard.backend.os_info == "DragonOS FocalX":
                cell_search_binary_location = "/usr/src/srsRAN/build/lib/examples/cell_search"
            command_text = (
                'qterminal -e python3 "'
                + script_location
                + '" -b '
                + get_value
                + " "
                + cell_search_binary_location
                + " &"
            )
        elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
            command_text = ('lxterminal -e python3 ' 
                + script_location 
                + 'start_sniffing.py -b ' 
                + get_value + ' ' 
                + cell_search_binary_location 
                + ' &'
            )
        proc = subprocess.Popen(command_text, cwd=script_location, shell=True)


@QtCore.pyqtSlot()
def _slotMenuInspectrumClicked(dashboard: QtWidgets.QMainWindow):
    """Opens Inspectrum."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "inspectrum"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "inspectrum"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "inspectrum"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuOpenCPN_Clicked(dashboard: QtWidgets.QMainWindow):
    """Launches OpenCPN."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "opencpn"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "opencpn"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "opencpn"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuProtocolSpreadsheetClicked():
    """Opens the Protocols_and_More.xlsx spreadsheet."""
    # Issue the Command
    spreadsheet_filepath = os.path.join(fissure.utils.FISSURE_ROOT, "docs", "Help", "Protocols_and_More.xlsx")
    command_text = 'libreoffice "' + spreadsheet_filepath + '" &'
    proc = subprocess.Popen(command_text, shell=True)


@QtCore.pyqtSlot()
def _slotMenuGrgsm_scannerClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with the grgsm_scanner command from gr-gsm for scanning GSM bands."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    # ~ command_text = 'gnome-terminal -- /bin/bash -c "grgsm_scanner -b PCS1900 -g 70 && echo "Done" && read"'  # bash and read keep the terminal open after running
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        command_text = (
            "gnome-terminal -- " + expect_script_filepath + ' "grgsm_scanner -b PCS1900 -g 70"'
        )  # let the user choose band, hardware, gain
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        command_text = (
            "qterminal -e " + expect_script_filepath + ' "grgsm_scanner -b PCS1900 -g 70"'
        )  # let the user choose band, hardware, gain
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        command_text = 'lxterminal -e ' + expect_script_filepath + ' "grgsm_scanner -b PCS1900 -g 70"'  # let the user choose band, hardware, gain


@QtCore.pyqtSlot()
def _slotMenuKalibrateClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with the kal command for calibrating RTL-SDRs and HackRF."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    kalibrate_directory = os.path.expanduser("~/Installed_by_FISSURE/kalibrate-rtl/src/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "./kal -h"', cwd=kalibrate_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "./kal -h"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "./kal -h"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuTowerSearchClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal for searching for eNodeB information using the srsRAN cell search binary."""
    # Open LTe Band List
    lte_directory = os.path.join(fissure.utils.TOOLS_DIR, "LTE_Tower_Search")
    proc = subprocess.Popen("gedit lte_bands.txt &", cwd=lte_directory, shell=True)

    # Issue the Command
    cell_search_binary_location = os.path.expanduser("~/Installed_by_FISSURE/srsRAN/build/lib/examples/cell_search")
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- "
            + expect_script_filepath
            + ' "python3 tower_search_part1.py '
            + cell_search_binary_location
            + ' [2,4]"',
            cwd=lte_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e "
            + expect_script_filepath
            + ' "python3 tower_search_part1.py '
            + cell_search_binary_location
            + ' [2,4]"',
            cwd=lte_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath 
            + ' "python3 tower_search_part1.py ' 
            + cell_search_binary_location 
            + ' [2,4]"',
            cwd=lte_directory,
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuTowerSearchPart2Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal for finding the LTE MCC/MNC and TAC values for a dictionary result provided by Tower Search Part 1."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    lte_dir = os.path.join(fissure.utils.TOOLS_DIR, "LTE_Tower_Search")
    output_example = """\\\"{\'MHz\': \'2125.0\', \'EARFCN\': \'2100\', \'PHYID\': \'276\', \'PRB\': \'50\', \'ports\': \'4\', \'PSS power\': \'-28.9 dBm\'}\\\" """
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "python3 tower_search_part2.py ' + output_example + '"',
            cwd=lte_dir,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "python3 tower_search_part2.py ' + output_example + '"',
            cwd=lte_dir,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath 
            + ' "python3 tower_search_part2.py ' 
            + output_example 
            + '"', 
            cwd=lte_dir, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuRetrogramRtlSdrClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with an example command for retrogram-rtlsdr which scans frequencies for RTL devices."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    retrogram_directory = os.path.expanduser("~/Installed_by_FISSURE/retrogram-rtlsdr-master")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "./retrogram-rtlsdr --rate 2e6 --freq 100e6 --step 1e5"',
            cwd=retrogram_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "./retrogram-rtlsdr --rate 2e6 --freq 100e6 --step 1e5"',
            cwd=retrogram_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath 
            + ' "./retrogram-rtlsdr --rate 2e6 --freq 100e6 --step 1e5"',
            cwd=retrogram_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuRTLSDR_AirbandClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with an example command for RTLSDR-Airband. Needs a configuration file."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    airband_directory = os.path.expanduser("~/Installed_by_FISSURE/RTLSDR-Airband")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "rtl_airband -h"', cwd=airband_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "rtl_airband -h"', cwd=airband_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "rtl_airband -h"', cwd=airband_directory, shell=True)


@QtCore.pyqtSlot()
def _slotMenuRadioReferenceDatabaseClicked():
    """Opens a browser to radioreference.com."""
    os.system("xdg-open https://www.radioreference.com/apps/db/")


@QtCore.pyqtSlot()
def _slotMenuSpektrumClicked(dashboard: QtWidgets.QMainWindow):
    """Launches Spektrum for RTL devices."""
    # Issue the Command
    spektrum_filepath = os.path.expanduser("~/Installed_by_FISSURE/spektrum/spektrum")
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + spektrum_filepath + '"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + spektrum_filepath + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + spektrum_filepath + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuRTL_TestClicked(dashboard: QtWidgets.QMainWindow):
    """Runs rtl_test command to detect hardware."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "rtl_test -t"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "rtl_test -t"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "rtl_test -t"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuSDR_TrunkClicked(dashboard: QtWidgets.QMainWindow):
    """Launches SDRTrunk."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        sdr_trunk_filepath = os.path.expanduser(
            "~/Installed_by_FISSURE/sdr-trunk-linux-x86_64-v0.5.0-alpha6/bin/sdr-trunk"
        )
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + sdr_trunk_filepath + '"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        if dashboard.backend.os_info == "DragonOS Focal" or dashboard.backend.os_info == "DragonOS FocalX":
            sdr_trunk_filepath = "/usr/src/sdr-trunk-linux-x86_64-v0.6.0-alpha6/bin/sdr-trunk"
            proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + sdr_trunk_filepath + '"', shell=True)
        else:
            sdr_trunk_filepath = os.path.expanduser("~/Installed_by_FISSURE/sdr-trunk-linux-x86_64-v0.5.0-alpha6/bin/sdr-trunk")
            proc = subprocess.Popen('qterminal -e ' + expect_script_filepath + ' "' + sdr_trunk_filepath + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        sdr_trunk_filepath = os.path.expanduser("~/Installed_by_FISSURE/sdr-trunk-linux-x86_64-v0.5.0-alpha6/bin/sdr-trunk")
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + sdr_trunk_filepath + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuAudacityClicked(dashboard: QtWidgets.QMainWindow):
    """Launches Audacity."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "audacity"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "audacity"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "audacity"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuSignalIdentificationGuideClicked():
    """Opens the Signal Identification Guide website in a browser."""
    os.system("xdg-open https://www.sigidwiki.com/wiki/Signal_Identification_Guide")


@QtCore.pyqtSlot()
def _slotMenuSondeHubRadiosondeTrackerClicked():
    """Opens the SondeHub Radiosonde Tracker website in a browser."""
    os.system("xdg-open https://tracker.sondehub.org/")


@QtCore.pyqtSlot()
def _slotMenuCellmapperClicked():
    """Opens cellmapper.net website in a browser."""
    os.system("xdg-open https://cellmapper.net/")


@QtCore.pyqtSlot()
def _slotMenuAirLinkClicked():
    """Opens Ubiquiti airLink tool in a browser. Great for line of sight mapping between two points."""
    os.system("xdg-open https://link.ui.com/")


@QtCore.pyqtSlot()
def _slotMenuFCC_ID_LookupClicked():
    """Opens fccid.io in a browser."""
    os.system("xdg-open https://fccid.io/")


@QtCore.pyqtSlot()
def _slotMenuStandaloneMorseGenClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "MorseGen.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuProxmark3_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with the command for controlling the Proxmark3."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    proxmark3_directory = os.path.expanduser("~/Installed_by_FISSURE/proxmark3/client/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "sudo ./proxmark3 /dev/ttyACM0"',
            cwd=proxmark3_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "sudo ./proxmark3 /dev/ttyACM0"',
            cwd=proxmark3_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "sudo ./proxmark3 /dev/ttyACM0"', cwd=proxmark3_directory, shell=True)


@QtCore.pyqtSlot()
def _slotMenuProxmark3_CheatsheetClicked():
    """Opens a Proxmark3 cheat sheet in a browser."""
    os.system("xdg-open https://scund00r.com/all/rfid/2018/06/05/proxmark-cheatsheet.html")


@QtCore.pyqtSlot()
def _slotMenuEarthNullschoolClicked():
    """Opens Earth Nullschool in a browser."""
    os.system("xdg-open https://earth.nullschool.net/")


@QtCore.pyqtSlot()
def _slotMenuCUSF_LandingPredictorClicked():
    """Opens CUSF Landing Predictor in a browser."""
    os.system("xdg-open http://predict.habhub.org/")


@QtCore.pyqtSlot()
def _slotMenuFlightAwareClicked():
    """Opens the FlightAware live map in a browser."""
    os.system("xdg-open https://flightaware.com/live/map")


@QtCore.pyqtSlot()
def _slotMenuRadiosondeAutoRxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with the command for starting radiosonde_auto_rx."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    radiosonde_directory = os.path.expanduser("~/Installed_by_FISSURE/radiosonde_auto_rx/auto_rx/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "python3 auto_rx.py"',
            cwd=radiosonde_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "python3 auto_rx.py"', cwd=radiosonde_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "python3 auto_rx.py"', cwd=radiosonde_directory, shell=True)


@QtCore.pyqtSlot()
def _slotMenuRadiosondeAutoRxConfigClicked():
    """Opens the radiosonde_auto_rx configuration file."""
    # Open the File
    config_directory = os.path.expanduser("~/Installed_by_FISSURE/radiosonde_auto_rx/auto_rx/station.cfg")
    os.system("gedit " + config_directory + " &")


@QtCore.pyqtSlot()
def _slotMenuSQ6KXY_RadiosondeTrackerClicked():
    """Opens the SQ6KXY Radiosonde Tracker in a browser."""
    os.system("xdg-open https://radiosondy.info/")


@QtCore.pyqtSlot()
def _slotMenuSdrGlutClicked(dashboard: QtWidgets.QMainWindow):
    """Opens SdrGlut in a new terminal."""
    # Issue the Command
    try:
        sdr_glut_directory = os.path.expanduser("~/Installed_by_FISSURE/SdrGlut/")
        expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
        if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
            proc = subprocess.Popen(
                "gnome-terminal -- " + expect_script_filepath + ' "./sdrglut.x"', shell=True, cwd=sdr_glut_directory
            )
        elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
            proc = subprocess.Popen(
                "qterminal -e " + expect_script_filepath + ' "./sdrglut.x"', shell=True, cwd=sdr_glut_directory
            )    
        elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
            proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "./sdrglut.x"', shell=True, cwd=sdr_glut_directory)
    except:
        dashboard.logger.error("Error accessing SdrGlut folder. Check FISSURE installer for details.")


@QtCore.pyqtSlot()
def _slotMenuUS_FrequencyAllocationsClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the US Frequency Allocations wall chart."""
    # Open the File
    us_freq_allocations_filepath = os.path.join(fissure.utils.TOOLS_DIR, "january_2016_spectrum_wall_chart.pdf")
    if (
        dashboard.backend.os_info == "DragonOS Focal" or
        dashboard.backend.os_info == "DragonOS FocalX" or
        dashboard.backend.os_info == "Kali" or
        dashboard.backend.os_info == "Raspberry Pi OS"
    ):
        os.system('open "' + us_freq_allocations_filepath + '" &')
    else:
        os.system('evince "' + us_freq_allocations_filepath + '" &')


@QtCore.pyqtSlot()
def _slotMenuCyberChefRecipesClicked():
    """Opens the cyberchef-recipes github page."""
    os.system("xdg-open https://github.com/mattnotmax/cyberchef-recipes")


@QtCore.pyqtSlot()
def _slotMenuRehexClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the Reverse Engineers' Hex Editor (rehex)."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "rehex"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "rehex"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "rehex"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuZEPASSD_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with the command for running ZEPASSD."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    zepassd_directory = os.path.expanduser("~/Installed_by_FISSURE/zepassd/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- "
            + expect_script_filepath
            + ' "./zepassd --tx-port A:A --rx-port A:A --tx-gain 87 --rx-gain 85 -p 20 foobar"',
            cwd=zepassd_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e "
            + expect_script_filepath
            + ' "./zepassd --tx-port A:A --rx-port A:A --tx-gain 87 --rx-gain 85 -p 20 foobar"',
            cwd=zepassd_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' 
            + expect_script_filepath 
            + ' "./zepassd --tx-port A:A --rx-port A:A --tx-gain 87 --rx-gain 85 -p 20 foobar"', 
            cwd=zepassd_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuIridiumExtractorClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with a command for recording Iridium bits with iridium-extractor."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    iridium_directory = os.path.join(fissure.utils.FISSURE_ROOT, "Custom_Blocks", "maint-3.8", "gr-iridium-maint-3.8")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- "
            + expect_script_filepath
            + ' "iridium-extractor -D 4 examples/hackrf.conf | grep A:OK > ~/output.bits"',
            cwd=iridium_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e "
            + expect_script_filepath
            + ' "iridium-extractor -D 4 examples/hackrf.conf | grep A:OK > ~/output.bits"',
            cwd=iridium_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' 
            + expect_script_filepath 
            + ' "iridium-extractor -D 4 examples/hackrf.conf | grep A:OK > ~/output.bits"', 
            cwd=iridium_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuIridiumParserClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with the command to parse the bits created by iridium-extractor.py and prepare it for stats-voc.py to allow audio playback."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    iridium_directory = os.path.join(fissure.utils.FISSURE_ROOT, "Custom_Blocks", "maint-3.8", "gr-iridium-maint-3.8")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- "
            + expect_script_filepath
            + ' "python2 iridium-parser.py -p ~/output.bits > ~/output.parsed"',
            cwd=iridium_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e "
            + expect_script_filepath
            + ' "python2 iridium-parser.py -p ~/output.bits > ~/output.parsed"',
            cwd=iridium_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath 
            + ' "python2 iridium-parser.py -p ~/output.bits > ~/output.parsed"', 
            cwd=iridium_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuStatsVocClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with the command to play the audio from the parsed Iridium files. Left-click and right-click on the red dots in each row."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    iridium_toolkit_directory = os.path.expanduser("~/Installed_by_FISSURE/iridium-toolkit/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- "
            + expect_script_filepath
            + ' "export PATH=$PATH:'
            + iridium_toolkit_directory
            + ' && ./stats-voc.py ~/output.parsed"',
            cwd=iridium_toolkit_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e "
            + expect_script_filepath
            + ' "export PATH=$PATH:'
            + iridium_toolkit_directory
            + ' && ./stats-voc.py ~/output.parsed"',
            cwd=iridium_toolkit_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' 
            + expect_script_filepath 
            + ' "export PATH=$PATH:' 
            + iridium_toolkit_directory 
            + ' && ./stats-voc.py ~/output.parsed"', 
            cwd=iridium_toolkit_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuIridiumLiveClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal for running the iridium-extractor/iridium-parser and piping the output to udp-for-il.py (localhost). Runs IridiumLive and opens a browser to 127.0.0.1:7777."""
    # Issue the IridiumLive Command
    iridiumlive_directory = os.path.expanduser("~/Installed_by_FISSURE/linux-x64/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen('gnome-terminal -- "./IridiumLive" &', cwd=iridiumlive_directory, shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen('qterminal -e "./IridiumLive" &', cwd=iridiumlive_directory, shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e "./IridiumLive" &', cwd=iridiumlive_directory, shell=True)

    # Open the Browser
    os.system("xdg-open http://127.0.0.1:7777/")

    # Issue the Command for Extractor and Parser
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    iridium_directory = os.path.join(fissure.utils.FISSURE_ROOT, "Custom_Blocks", "maint-3.8", "gr-iridium-maint-3.8")
    tools_filepath = os.path.join(fissure.utils.TOOLS_DIR)
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- "
            + expect_script_filepath
            + ' "iridium-extractor --offline --multi-frame '
            + iridium_directory
            + "examples/hackrf.conf | ~/Installed_by_FISSURE/iridium-toolkit/iridium-parser.py -p /dev/stdin /dev/stdout | python2 "
            + tools_filepath
            + 'IridiumLive/udp-for-il.py"',
            cwd=iridium_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e "
            + expect_script_filepath
            + ' "iridium-extractor --offline --multi-frame '
            + iridium_directory
            + "examples/hackrf.conf | ~/Installed_by_FISSURE/iridium-toolkit/iridium-parser.py -p /dev/stdin /dev/stdout | python2 "
            + tools_filepath
            + 'IridiumLive/udp-for-il.py"',
            cwd=iridium_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath 
            + ' "iridium-extractor --offline --multi-frame ' 
            + iridium_directory 
            + 'examples/hackrf.conf | ~/Installed_by_FISSURE/iridium-toolkit/iridium-parser.py -p /dev/stdin /dev/stdout | python2 ' 
            + tools_filepath 
            + 'IridiumLive/udp-for-il.py"', 
            cwd=iridium_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuNETATTACK2_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal and launches NETATTACK2."""
    # Issue the Command
    netattack2_directory = os.path.expanduser("~/Installed_by_FISSURE/netattack2/")
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "sudo python2 netattack2.py"',
            shell=True,
            cwd=netattack2_directory,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "sudo python2 netattack2.py"',
            shell=True,
            cwd=netattack2_directory,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "sudo python2 netattack2.py"', 
            shell=True, 
            cwd=netattack2_directory
        )


@QtCore.pyqtSlot()
def _slotMenuWifiteClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal and launches Wifite."""
    # Issue the Command
    expect_script_filepath = os.path.join(
        fissure.utils.TOOLS_DIR, "expect_script"
    )  # Expect is needed because Wifite closes on completion
    wifite2_directory = os.path.expanduser("~/Installed_by_FISSURE/wifite2/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "sudo ./Wifite.py"', cwd=wifite2_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "sudo wifite"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "sudo wifite"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuRtl_433_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal and launches rtl_433."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "rtl_433"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "rtl_433"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "rtl_433"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuRouterSploitClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal and launches RouterSploit."""
    # Issue the Command
    routersploit_directory = os.path.expanduser("~/Installed_by_FISSURE/routersploit/")
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "python3 rsf.py"', shell=True, cwd=routersploit_directory
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "python3 rsf.py"', shell=True, cwd=routersploit_directory
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "python3 rsf.py"', shell=True, cwd=routersploit_directory
        )


@QtCore.pyqtSlot()
def _slotMenuExploitDatabaseClicked():
    """Opens ExploitDB in a browser."""
    # Open the Browser
    os.system("xdg-open https://www.exploit-db.com/")


@QtCore.pyqtSlot()
def _slotMenuMetasploitClicked(dashboard: QtWidgets.QMainWindow):
    """Opens msfconsole in a new terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "msfconsole"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "msfconsole"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "msfconsole"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuMonitor_rtl433_Clicked(dashboard: QtWidgets.QMainWindow):
    """Runs monitor_rtl433 and opens a browser to view data."""
    # Issue the Command
    monitor_rtl433_directory = os.path.expanduser("~/Installed_by_FISSURE/monitor_rtl433/")
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "sudo python3 -m monitor_rtl433"',
            shell=True,
            cwd=monitor_rtl433_directory,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "sudo python3 -m monitor_rtl433"',
            shell=True,
            cwd=monitor_rtl433_directory,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "sudo python3 -m monitor_rtl433"', 
            shell=True,
            cwd=monitor_rtl433_directory,
        )

    # Open the Browser
    os.system("xdg-open http://127.0.0.1:5000/")


@QtCore.pyqtSlot()
def _slotMenuWiGLE_Clicked():
    """Opens wigle.net in a browser."""
    # Open the Browser
    os.system("xdg-open https://www.wigle.net/")


@QtCore.pyqtSlot()
def _slotMenuScan_SSID_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal for scanning SSIDs while in managed mode using scan-ssid."""
    # Guess the Wireless Interface Name
    get_interface = "interface"

    # Get the Text
    proc = subprocess.Popen(
        "iwconfig &",
        shell=True,
        stdout=subprocess.PIPE,
    )
    output = proc.communicate()[0].decode()

    # Pull the Interfaces
    lines = output.split("\n")
    get_interface = ""
    wifi_interfaces = []
    for n in range(0, len(lines)):
        if "ESSID" in lines[n]:
            wifi_interfaces.append(lines[n].split(" ", 1)[0])

    # Found an Interface
    if len(wifi_interfaces) > 0:

        # Update the Edit Box
        get_interface = wifi_interfaces[0]

    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "scan-ssid -p ' + get_interface + '"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "scan-ssid -p ' + get_interface + '"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "scan-ssid -p ' + get_interface + '"', shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuPySimReadClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal in the pySim directory for using pySim-read.py."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    pysim_directory = os.path.expanduser("~/Installed_by_FISSURE/pysim/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "./pySim-read.py -p 0"', cwd=pysim_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "./pySim-read.py -p 0"', cwd=pysim_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "./pySim-read.py -p 0"', cwd=pysim_directory, shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuPySimProgClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal in the pySim directory for using pySim-prog.py."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    pysim_directory = os.path.expanduser("~/Installed_by_FISSURE/pysim/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- "
            + expect_script_filepath
            + ' "./pySim-prog.py -p 0 -x 310 -y 070 -n test1 -t sysmoUSIM-SJS1 -i 901700000023688 -s 8988211000000236888 -o 1B0A4D434B184DE7BA88147E725C5AAD -k 0B7BBF089FD188EA0C64FEE245EB03E7 -a 12100237"',
            cwd=pysim_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e "
            + expect_script_filepath
            + ' "./pySim-prog.py -p 0 -x 310 -y 070 -n test1 -t sysmoUSIM-SJS1 -i 901700000023688 -s 8988211000000236888 -o 1B0A4D434B184DE7BA88147E725C5AAD -k 0B7BBF089FD188EA0C64FEE245EB03E7 -a 12100237"',
            cwd=pysim_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' 
            + expect_script_filepath 
            + ' "./pySim-prog.py -p 0 -x 310 -y 070 -n test1 -t sysmoUSIM-SJS1 -i 901700000023688 -s 8988211000000236888 -o 1B0A4D434B184DE7BA88147E725C5AAD -k 0B7BBF089FD188EA0C64FEE245EB03E7 -a 12100237"', 
            cwd=pysim_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuLessonLuaDissectorsClicked():
    """Opens the html file in a browser."""
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'Lessons', 'HTML', 'Lesson2_LuaDissectors.html')}"
    )


@QtCore.pyqtSlot()
def _slotMenuMinimodemRxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal and populates it with the minimodem --rx command."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "minimodem --rx 110"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "minimodem --rx 110"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "minimodem --rx 110"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuMinimodemTxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal and populates it with the minimodem --tx command."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    transmit_text = """\\\"This is a test message!\\\" """
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "printf ' + transmit_text + ' | minimodem --tx 110"',
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "printf ' + transmit_text + ' | minimodem --tx 110"',
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "printf ' + transmit_text + ' | minimodem --tx 110"', 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuWSJTX_Clicked(dashboard: QtWidgets.QMainWindow):
    """Issues the wsjtx command."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "wsjtx"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "wsjtx"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "wsjtx"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuWSPRnetMapClicked():
    """Opens the WSPRnet Map in the browser."""
    # Open the Browser
    os.system("xdg-open https://www.wsprnet.org/drupal/wsprnet/map")


@QtCore.pyqtSlot()
def _slotMenuAntennaTestRxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "antenna_test_rx.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuAntennaTestTxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "antenna_test_tx.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuLessonSound_eXchangeClicked():
    """Opens the html file in a browser."""
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'Lessons', 'HTML', 'Lesson3_Sound_eXchange.html')}"
    )


@QtCore.pyqtSlot()
def _slotMenuVLC_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens VLC."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "vlc"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "vlc"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "vlc"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuZigbeeOpenSnifferClicked(dashboard: QtWidgets.QMainWindow):
    """Opens ZigBee Open Sniffer Web GUI"""
    # Issue the Command
    open_sniffer_cmd = "python2 " + os.path.expanduser("~/Installed_by_FISSURE/OpenSniffer-0.1/ZigBee_GUI.py")
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "vlc"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + open_sniffer_cmd + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + open_sniffer_cmd + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuSimpleScreenRecorderClicked(dashboard: QtWidgets.QMainWindow):
    """Opens SimpleScreenRecorder."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "simplescreenrecorder"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "simplescreenrecorder"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "simplescreenrecorder"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuPixieDustListClicked():
    """Opens a list of devices vulnerable to Pixie Dust (Wifite)."""
    os.system(
        "xdg-open https://docs.google.com/spreadsheets/d/1tSlbqVQ59kGn8hgmwcPTHUECQ3o9YhXR91A_p7Nnj5Y/edit#gid=2048815923"
    )


@QtCore.pyqtSlot()
def _slotMenuAudioRecordClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with the sox record command loaded."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "rec test.wav trim 0 0:10"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "rec test.wav trim 0 0:10"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "rec test.wav trim 0 0:10"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuESP_BoardClicked():
    """Opens the html file in a browser."""
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'Lessons', 'HTML', 'Lesson4_ESP_Boards.html')}"
    )


@QtCore.pyqtSlot()
def _slotMenuGoogleEarthProClicked(dashboard: QtWidgets.QMainWindow):
    """Opens Google Earth Pro."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "google-earth-pro"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "google-earth-pro"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "google-earth-pro"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuGrAirModesClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with an example command for using gr-air-modes."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "modes_rx -s osmocom -K aircrafts.kml"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "modes_rx -s osmocom -K aircrafts.kml"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "modes_rx -s osmocom -K aircrafts.kml"', shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuESP8266_DeautherInoClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the .ino file in the Arduino IDE."""
    # Issue the Command
    deauther_directory = os.path.expanduser("~/Installed_by_FISSURE/esp8266_deauther-2/esp8266_deauther/")
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    deauther_cmd = "sudo arduino " + deauther_directory + "esp8266_deauther.ino"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "' + deauther_cmd + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + deauther_cmd + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + deauther_cmd + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuESP8266_DeautherWebInterfaceClicked():
    """Opens a browser to the Deauther web interface. Need to connect to its wireless network."""
    os.system("xdg-open 192.168.4.1")


@QtCore.pyqtSlot()
def _slotMenuESP8266_DeautherCredentialsClicked():
    """Opens a text file with the credentials for joining the deauther's network."""
    # Open the File
    credential_directory = os.path.join(fissure.utils.TOOLS_DIR, "ESP8266_Deauther_v2", "credentials.txt")
    os.system('gedit "' + credential_directory + '" &')


@QtCore.pyqtSlot()
def _slotMenuLowEarthVisualizationClicked():
    """Opens the LeoLabs visualization page."""
    os.system("xdg-open https://platform.leolabs.space/visualization")


@QtCore.pyqtSlot()
def _slotMenuLeoLabsCatalogClicked():
    """Opens the LeoLabs catalog page."""
    os.system("xdg-open https://platform.leolabs.space/catalog")


@QtCore.pyqtSlot()
def _slotMenuCgpsClicked(dashboard: QtWidgets.QMainWindow):
    """Runs the cgps command in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "cgps"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "cgps"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "cgps"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuGpsdecodeClicked(dashboard: QtWidgets.QMainWindow):
    """Decodes the output of gpscat in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "sudo gpscat /dev/ttyACM0 | gpsdecode"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "sudo gpscat /dev/ttyACM0 | gpsdecode"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "sudo gpscat /dev/ttyACM0 | gpsdecode"', shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuGpsmonClicked(dashboard: QtWidgets.QMainWindow):
    """Runs the gpsmon command in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "gpsmon"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "gpsmon"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "gpsmon"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuXgpsClicked(dashboard: QtWidgets.QMainWindow):
    """Runs the xgps command in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "xgps"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "xgps"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "xgps"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuXgpsspeedClicked(dashboard: QtWidgets.QMainWindow):
    """Runs the xgsspeed command in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "xgpsspeed"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "xgpsspeed"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "xgpsspeed"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuVikingClicked(dashboard: QtWidgets.QMainWindow):
    """Opens Viking tool. May need to link ports to track GPS: "sudo ln -s /dev/ttyACM0 /dev/ttyUSB0" """
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "viking"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "viking"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "viking"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuPyGPSClientClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the PyGPSClient program."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "sudo python3 -m pygpsclient"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "sudo python3 -m pygpsclient"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "sudo python3 -m pygpsclient"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuRadioStationLocator():
    """Opens the Radio Station Locator in a browser."""
    os.system("xdg-open https://radio-locator.com/cgi-bin/locate")


@QtCore.pyqtSlot()
def _slotMenuLiveATCnetClicked():
    """Opens LiveATC.net in a browser"""
    os.system("xdg-open https://www.liveatc.net/")


@QtCore.pyqtSlot()
def _slotMenuFlightradar24_Clicked():
    """Opens Flightradar24 in a browser."""
    os.system("xdg-open https://www.flightradar24.com/")


@QtCore.pyqtSlot()
def _slotMenuFlightStatsClicked():
    """Opens FlightStats in a browser."""
    os.system("xdg-open http://www.flightstats.com/")


@QtCore.pyqtSlot()
def _slotMenuPlaneFinderClicked():
    """Opens Plane Finder in a browser."""
    os.system("xdg-open https://planefinder.net/")


@QtCore.pyqtSlot()
def _slotMenuUS_CountyOverlaysClicked():
    """Opens the FCC U.S. County Overlay for Google Earth (KML) in a browser."""
    os.system("xdg-open https://www.fcc.gov/media/radio/us-county-overlays-kml")


@QtCore.pyqtSlot()
def _slotMenuAM_QueryClicked():
    """Opens the FCC AM Query in a browser."""
    os.system("xdg-open https://www.fcc.gov/media/radio/am-query")


@QtCore.pyqtSlot()
def _slotMenuFM_QueryClicked():
    """Opens the FCC FM Query in a browser."""
    os.system("xdg-open https://www.fcc.gov/media/radio/fm-query")


@QtCore.pyqtSlot()
def _slotMenuRadioGardenClicked():
    """Opens Radio Garden in a browser."""
    os.system("xdg-open http://radio.garden/")


@QtCore.pyqtSlot()
def _slotMenuDiffcheckerClicked():
    """Opens Diffchecker in a browser."""
    os.system("xdg-open https://www.diffchecker.com/")


@QtCore.pyqtSlot()
def _slotMenuEveryTimeZoneClicked():
    """Opens Every Time Zone in a browser."""
    os.system("xdg-open https://everytimezone.com/")


@QtCore.pyqtSlot()
def _slotMenuCloudConvertClicked():
    """Opens CloudConvert in a browser."""
    os.system("xdg-open https://cloudconvert.com/")


@QtCore.pyqtSlot()
def _slotMenuRoundup_ofSDRsClicked():
    """Opens Roundup of SDRs in a browser."""
    os.system("xdg-open https://www.rtl-sdr.com/roundup-software-defined-radios/")


@QtCore.pyqtSlot()
def _slotMenuList_ofSDRsClicked():
    """Opens List of SDRs in a browser."""
    os.system("xdg-open https://en.wikipedia.org/wiki/List_of_software-defined_radios")


@QtCore.pyqtSlot()
def _slotMenuAcarsDemoClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "acars_demo.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuGpredictClicked(dashboard: QtWidgets.QMainWindow):
    """Opens Gpredict."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "gpredict"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "gpredict"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "gpredict"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuTechInfoDepotClicked():
    """Opens TechInfoDepot in a browser."""
    os.system("xdg-open http://en.techinfodepot.shoutwiki.com/wiki/Main_Page")


@QtCore.pyqtSlot()
def _slotMenuWikiDeviClicked():
    """Opens WikiDevi (TechInfoDepot) in a browser."""
    os.system("xdg-open http://en.techinfodepot.shoutwiki.com/wiki/Main_Page/WikiDevi")


@QtCore.pyqtSlot()
def _slotMenuApt3000_Clicked():
    """Opens APT3000 in a browser."""
    os.system("xdg-open https://jthatch.com/APT3000/APT3000.html")


@QtCore.pyqtSlot()
def _slotMenuFSPL_CalculatorClicked():
    """Opens Free Space Path Loss Calculator in a browser."""
    os.system("xdg-open https://www.pasternack.com/t-calculator-fspl.aspx")


@QtCore.pyqtSlot()
def _slotMenuHabhubTrackerClicked():
    """Opens habhub tracker in a browser."""
    os.system("xdg-open https://tracker.habhub.org/")


@QtCore.pyqtSlot()
def _slotMenuFoxtrotGPS_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens the FoxtrotGPS program."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "foxtrotgps"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "foxtrotgps"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "foxtrotgps"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuGoogleMapsAPRS_Clicked():
    """Opens Google Maps APRS in a browser."""
    os.system("xdg-open https://aprs.fi/")


@QtCore.pyqtSlot()
def _slotMenuAPRSmultimon_ngClicked(dashboard: QtWidgets.QMainWindow):
    """Places the command to view raw APRS data from an RTL device in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- "
            + expect_script_filepath
            + ' "rtl_fm -f 144.390M -s 22050|multimon-ng -t raw -a AFSK1200 -f alpha -A /dev/stdin"',
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e "
            + expect_script_filepath
            + ' "rtl_fm -f 144.390M -s 22050|multimon-ng -t raw -a AFSK1200 -f alpha -A /dev/stdin"',
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' 
            + expect_script_filepath 
            + ' "rtl_fm -f 144.390M -s 22050|multimon-ng -t raw -a AFSK1200 -f alpha -A /dev/stdin"', 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuLTE_CellScannerClicked(dashboard: QtWidgets.QMainWindow):
    """Opens an example command for LTE-Cell-Scanner in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "CellSearch --freq-start 884e6 --freq-end 886e6"',
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "CellSearch --freq-start 884e6 --freq-end 886e6"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "CellSearch --freq-start 884e6 --freq-end 886e6"', shell=True
        )


@QtCore.pyqtSlot()
def _slotMenu_esriSatelliteMapClicked():
    """Opens esri Satellite Map in a browser."""
    os.system("xdg-open https://maps.esri.com/rc/sat2/index.html")


@QtCore.pyqtSlot()
def _slotMenuLessonRadiosondeTrackingClicked():
    """Opens the html file in a browser."""
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'Lessons', 'HTML', 'Lesson5_Radiosonde_Tracking.html')}"
    )


@QtCore.pyqtSlot()
def _slotMenuBtrxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens an example command for using btrx (gr-bluetooth)."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "btrx -f 2402M -r 4M -g 40 -a hackrf"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "btrx -f 2402M -r 4M -g 40 -a hackrf"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "btrx -f 2402M -r 4M -g 40 -a hackrf"', shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuBleDumpTriggered(dashboard: QtWidgets.QMainWindow):
    """Opens an example command for using ble_dump and creates a fifo for Wireshark."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    ble_dump_directory = os.path.join(fissure.utils.TOOLS_DIR, "ble_dump-master")
    proc = subprocess.Popen("mkfifo /tmp/fifo1", shell=True)
    proc = subprocess.call("wireshark -S -k -i /tmp/fifo1 &", shell=True)
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "sudo python2 ble_dump.py -s 4000000 -o /tmp/fifo1"',
            cwd=ble_dump_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "sudo python2 ble_dump.py -s 4000000 -o /tmp/fifo1"',
            cwd=ble_dump_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -q ' + expect_script_filepath + ' "sudo python2 ble_dump.py -s 4000000 -o /tmp/fifo1"', 
            cwd=ble_dump_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuFlashESP32_BoardClicked(dashboard: QtWidgets.QMainWindow):
    """Flashes the ESP32 board with the BrakTooth Sniffer."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    esp32_sniffer_directory = os.path.expanduser("~/Installed_by_FISSURE/esp32_bluetooth_classic_sniffer/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "sudo ./firmware.py flash /dev/ttyUSB0"',
            cwd=esp32_sniffer_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "sudo ./firmware.py flash /dev/ttyUSB0"',
            cwd=esp32_sniffer_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "sudo ./firmware.py flash /dev/ttyUSB0"', 
            cwd=esp32_sniffer_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuBT_SnifferBREDR_Clicked(dashboard: QtWidgets.QMainWindow):
    """Runs the Bluetooth Classic Sniffer in slave role."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    esp32_sniffer_directory = os.path.expanduser("~/Installed_by_FISSURE/esp32_bluetooth_classic_sniffer/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- "
            + expect_script_filepath
            + ' "sudo ./BTSnifferBREDR.py --port=/dev/ttyUSB0 --live-terminal --live-wireshark"',
            cwd=esp32_sniffer_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e "
            + expect_script_filepath
            + ' "sudo ./BTSnifferBREDR.py --port=/dev/ttyUSB0 --live-terminal --live-wireshark"',
            cwd=esp32_sniffer_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' 
            + expect_script_filepath 
            + ' "sudo ./BTSnifferBREDR.py --port=/dev/ttyUSB0 --live-terminal --live-wireshark"', 
            cwd=esp32_sniffer_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuHcitoolScanClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the hcitool scan command in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "hcitool scan"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "hcitool scan"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "hcitool scan"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuSdptoolBrowseClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the sdptool browse command in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "sdptool browse 00:80:98:24:15:6D"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "sdptool browse 00:80:98:24:15:6D"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "sdptool browse 00:80:98:24:15:6D"', shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuHcitoolInqClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the hcitool inq command in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "hcitool inq"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "hcitool inq"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "hcitool inq"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuDeviceClassListClicked():
    """Opens "Bluetooth - Class of Device List" in a browser."""
    os.system("xdg-open http://domoticx.com/bluetooth-class-of-device-lijst-cod/")


@QtCore.pyqtSlot()
def _slotMenuBtclassifyClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the btsclassify.py command in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    btclassify_directory = os.path.join(fissure.utils.TOOLS_DIR, "btclassify-master")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "python2 btclassify.py 38010c 0x5a020c 240404"',
            cwd=btclassify_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "python2 btclassify.py 38010c 0x5a020c 240404"',
            cwd=btclassify_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "python2 btclassify.py 38010c 0x5a020c 240404"', 
            cwd=btclassify_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuL2pingClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the l2ping command in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "sudo l2ping 00:80:98:24:15:6D"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "sudo l2ping 00:80:98:24:15:6D"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "sudo l2ping 00:80:98:24:15:6D"', shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuBtscannerClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the btscanner program."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "sudo btscanner"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "sudo btscanner"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "sudo btscanner"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuHcidumpClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the hcidump command in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "sudo hcidump -Xt"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "sudo hcidump -Xt"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "sudo hcidump -Xt"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuLessonRFID_Clicked():
    """Opens the html file in a browser."""
    os.system(f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'Lessons', 'HTML', 'Lesson6_RFID.html')}")


@QtCore.pyqtSlot()
def _slotMenuStandaloneFM_RadioCaptureClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "FM_Radio_Capture.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuProtocolCSV_Clicked():
    """Opens a CSV with RF protocols sorted by frequency."""
    # Issue the Command
    csv_filepath = os.path.join(fissure.utils.FISSURE_ROOT, "docs", "Help", "protocols_by_frequency.csv")
    command_text = 'libreoffice "' + csv_filepath + '" &'
    proc = subprocess.Popen(command_text, shell=True)


@QtCore.pyqtSlot()
def _slotMenuUHD_ImageLoaderClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal and displays the uhd_image_loader command for the USRP X3x0."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    uhd_command = """\\\"/usr/bin/uhd_image_loader\\\" --args=\\\"type=x300,addr=192.168.40.2\\\" """
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "' + uhd_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + uhd_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + uhd_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuTinyWowClicked():
    """Opens TinyWow in a browser."""
    os.system("xdg-open https://tinywow.com/")


@QtCore.pyqtSlot()
def _slotMenuGrPaintConverterClicked(dashboard: QtWidgets.QMainWindow):
    """Converts text into a raw file formatted for gr-paint."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    spectrum_painter_directory = os.path.expanduser("~/Installed_by_FISSURE/spectrum_painter/")
    converter_command = "convert -pointsize 30 -fill black label:hello hello.png && convert -flip hello.png hello.png && python3 -m spectrum_painter.img2iqstream hello.png --samplerate 8000000 --format hackrf > hello.raw"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + converter_command + '"',
            cwd=spectrum_painter_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "' + converter_command + '"',
            cwd=spectrum_painter_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "' + converter_command + '"', 
            cwd=spectrum_painter_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuNrsc5_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens the nrsc5 command (for rtl devices) in a terminal. Press 0,1,2,3 once running to switch programs."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    nrsc_command = "nrsc5 94.9 0 -g 40"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "' + nrsc_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + nrsc_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + nrsc_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuStandaloneHd_tx_usrpClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "hd_tx_usrp.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuAntennaComparisonClicked():
    """Opens the AntennaComparison spreadsheet."""
    # Issue the Command
    spreadsheet_filepath = os.path.join(fissure.utils.FISSURE_ROOT, "docs", "Help", "AntennaComparison.ods")
    command_text = 'libreoffice "' + spreadsheet_filepath + '" &'
    proc = subprocess.Popen(command_text, shell=True)


@QtCore.pyqtSlot()
def _slotMenu2022_2026_TechnicianPoolClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the 2022-2026 Technician Pool pdf."""
    # Open the File
    pdf_location = os.path.join(
        fissure.utils.TOOLS_DIR, "Ham Radio Exam", "2022-2026 Technician Pool Released Jan17 Revised.pdf"
    )
    if (
        dashboard.backend.os_info == "DragonOS Focal" or
        dashboard.backend.os_info == "DragonOS FocalX" or
        dashboard.backend.os_info == "Kali" or
        dashboard.backend.os_info == "Raspberry Pi OS"
    ):
        os.system('open "' + pdf_location + '" &')
    else:
        os.system('evince "' + pdf_location + '" &')


@QtCore.pyqtSlot()
def _slotMenuLicenseSearchClicked():
    """Opens a browser to the license search for the Universal Licensing System."""
    # Open a Browser
    os.system("xdg-open https://wireless2.fcc.gov/UlsApp/UlsSearch/searchLicense.jsp")


@QtCore.pyqtSlot()
def _slotMenuAnkiClicked(dashboard: QtWidgets.QMainWindow):
    """Opens Anki for reviewing flashcards."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "anki"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "anki"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "anki"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuAnkiDecksClicked():
    """Opens a browser to download amateur radio Anki decks."""
    # Open a Browser
    os.system("xdg-open https://ankiweb.net/shared/decks/amateur%20radio")


@QtCore.pyqtSlot()
def _slotMenuWavelengthCalculatorClicked():
    """Opens a browser to a frequency to wavelength calculator."""
    # Open a Browser
    os.system("xdg-open https://www.ahsystems.com/EMC-formulas-equations/frequency-wavelength-calculator.php")


@QtCore.pyqtSlot()
def _slotMenuAntennaSearchClicked():
    """Opens a browser to AntennaSearch."""
    # Open a Browser
    os.system("xdg-open https://www.antennasearch.com/")


@QtCore.pyqtSlot()
def _slotMenuCommandClassSpecificationClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the Z-Wave Application Command Class Specification (SDS13781)."""
    # Open the File
    pdf_location = os.path.join(fissure.utils.TOOLS_DIR, "SDS13781-Z-Wave-Application-Command-Class-Specification.pdf")
    if (
        dashboard.backend.os_info == "DragonOS Focal" or
        dashboard.backend.os_info == "DragonOS FocalX" or
        dashboard.backend.os_info == "Kali" or
        dashboard.backend.os_info == "Raspberry Pi OS"
    ):
        os.system('open "' + pdf_location + '" &')
    else:
        os.system('evince "' + pdf_location + '" &')


@QtCore.pyqtSlot()
def _slotMenuCommandClassListClicked():
    """Opens the Z-Wave Command Class List."""
    # Issue the Command
    xlsx_filepath = os.path.join(fissure.utils.TOOLS_DIR, "SDS13548-List-of-defined-Z-Wave-Command-Classes.xlsx")
    command_text = 'libreoffice "' + xlsx_filepath + '" &'
    proc = subprocess.Popen(command_text, shell=True)


@QtCore.pyqtSlot()
def _slotMenuSCADACoreRF_LineOfSightClicked():
    """Opens the SCADACore RF Line-of-Sight plot tool in a browser."""
    # Open a Browser
    os.system("xdg-open https://www.scadacore.com/tools/rf-path/rf-line-of-sight/")


@QtCore.pyqtSlot()
def _slotMenuOnlineHexConverterClicked():
    """Opens the SCADACore Online Hex Converter in a browser."""
    # Open a Browser
    os.system("xdg-open https://www.scadacore.com/tools/programming-calculators/online-hex-converter/")


@QtCore.pyqtSlot()
def _slotMenuExamLocationsClicked():
    """Opens the ARRL page with instructions on how to register and find Amateur Radio License exam locations."""
    # Open a Browser
    os.system("xdg-open http://www.arrl.org/find-an-amateur-radio-license-exam-session")


@QtCore.pyqtSlot()
def _slotMenuEchoLinkLinkStatusClicked():
    """Opens the online search for EchoLink links in a browser. Must register your call sign and provide proof of license to use EchoLink."""
    # Open a Browser
    os.system("xdg-open https://www.echolink.org/links.jsp")


@QtCore.pyqtSlot()
def _slotMenuSolarHamClicked():
    """Opens the SolarHam in a browser."""
    # Open a Browser
    os.system("xdg-open https://www.solarham.net/")


@QtCore.pyqtSlot()
def _slotMenuBlessHexEditorClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the Bless hex editor."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "bless"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "bless"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "bless"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuTrackjackerClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with an example trackerjacker command."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    trackerjacker_command = "sudo trackerjacker -i wlan1337 --map --map-file ~/wifi_map.yaml"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + trackerjacker_command + '"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "' + trackerjacker_command + '"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + trackerjacker_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuSanitizedIEEE_OUI_DataClicked():
    """Open a browser to download updated OUI lists."""
    # Open a Browser
    os.system("xdg-open https://linuxnet.ca/ieee/oui/")


@QtCore.pyqtSlot()
def _slotMenuMarineTrafficClicked():
    """Opens MarineTraffic map in a browser."""
    # Open a Browser
    os.system("xdg-open https://www.marinetraffic.com/")


@QtCore.pyqtSlot()
def _slotMenuVesselFinderClicked():
    """Opens VesselFinder map in a browser."""
    # Open a Browser
    os.system("xdg-open https://www.vesselfinder.com/")


@QtCore.pyqtSlot()
def _slotMenuBoatnerdClicked():
    """Opens Boatnerd map in a browser."""
    # Open a Browser
    os.system("xdg-open https://ais.boatnerd.com/")


@QtCore.pyqtSlot()
def _slotMenuCruiseMapperClicked():
    """Opens CruiseMapper map in a browser."""
    # Open a Browser
    os.system("xdg-open https://www.cruisemapper.com/")


@QtCore.pyqtSlot()
def _slotMenuLessonDataTypesClicked():
    """Opens the html file in a browser."""
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'Lessons', 'HTML', 'Lesson7_Data_Types.html')}"
    )


@QtCore.pyqtSlot()
def _slotMenuLessonCustomGNU_RadioBlocksClicked():
    """Opens the html file in a browser."""
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'Lessons', 'HTML', 'Lesson8_Custom_GNU_Radio_Blocks.html')}"
    )


@QtCore.pyqtSlot()
def _slotMenuADSB_ExchangeClicked():
    """Opens ADS-B Exchange in a browser."""
    # Open a Browser
    os.system("xdg-open https://globe.adsbexchange.com/")


@QtCore.pyqtSlot()
def _slotMenuStandaloneClapperPlusTransmitClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "Clapper_Plus_Transmit.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuStandaloneGarageDoorTransmitClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "Garage_Door_Transmit.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuStandaloneGarageDoorCycleClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "Garage_Door_Cycle.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuLessonTPMS_Clicked():
    """Opens the html file in a browser."""
    os.system(f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'Lessons', 'HTML', 'Lesson9_TPMS.html')}")


@QtCore.pyqtSlot()
def _slotMenuHowToFileClicked():
    """Opens RadioQTH page on how to file for a call sign in a browser."""
    # Open a Browser
    os.system("xdg-open http://www.radioqth.net/howtofile/")


@QtCore.pyqtSlot()
def _slotMenuRadioQTH_Clicked():
    """Opens RadioQTH page for finding available call signs in a browser."""
    # Open a Browser
    os.system("xdg-open http://www.radioqth.net/vanity/available")


@QtCore.pyqtSlot()
def _slotMenuAE7Q_Clicked():
    """Opens AE7Q for finding available call signs in a browser."""
    # Open a Browser
    os.system("xdg-open https://www.ae7q.com/query/")


@QtCore.pyqtSlot()
def _slotMenuAirgeddonClicked(dashboard: QtWidgets.QMainWindow):
    """Opens airgeddon in a terminal."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    airgeddon_directory = os.path.expanduser("~/Installed_by_FISSURE/airgeddon/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "sudo bash airgeddon.sh"',
            cwd=airgeddon_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "sudo bash airgeddon.sh"', cwd=airgeddon_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "sudo bash airgeddon.sh"', cwd=airgeddon_directory, shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuWhoisherePyClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with whoishere.py command."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    whoishere_command = "sudo python2 whoishere.py"
    whoishere_dir = os.path.join(fissure.utils.TOOLS_DIR, "whoishere.py-master")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + whoishere_command + '"',
            cwd=whoishere_dir,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "' + whoishere_command + '"', cwd=whoishere_dir, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "' + whoishere_command + '"', cwd=whoishere_dir, shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuWhoishereConfClicked():
    """Opens the whoishere.conf file."""
    # Open the File
    config_directory = os.path.join(fissure.utils.TOOLS_DIR, "whoishere.py-master", "whoishere.conf")
    os.system('gedit "' + config_directory + '" &')


@QtCore.pyqtSlot()
def _slotMenuHydraClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with the Hydra command for brute-forcing SSH."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    password_list = os.path.join(fissure.utils.TOOLS_DIR, "Credentials", "top-20-common-SSH-passwords.txt")
    hydra_command = 'hydra -l root -P "' + password_list + '" ssh://192.168.1.1 -t 4'
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "' + hydra_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + hydra_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + hydra_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuSecListsClicked():
    """Opens the SecLists GitHub page for usernames, passwords, and other data."""
    # Open a Browser
    os.system("xdg-open https://github.com/danielmiessler/SecLists")


@QtCore.pyqtSlot()
def _slotMenu_ssh_loginClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with the Metasploit ssh_login command for brute-forcing SSH."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    password_list = os.path.join(fissure.utils.TOOLS_DIR, "Credentials", "root_userpass.txt")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        msf_command = """msfconsole -x \\\"use auxiliary/scanner/ssh/ssh_login; set RHOSTS 192.168.1.1; set USERPASS_FILE """ + password_list + """; run\\\" """
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "' + msf_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        msf_command = """msfconsole -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS 192.168.1.1; set USERPASS_FILE """ + password_list + """; run" """
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + msf_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        msf_command = """msfconsole -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS 192.168.1.1; set USERPASS_FILE """ + password_list + """; run" """
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + msf_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuMetasploitWordlistsClicked():
    """Opens the Metasploit Wordlists GitHub page for usernames, passwords, and other data."""
    # Open a Browser
    os.system("xdg-open https://github.com/rapid7/metasploit-framework/tree/master/data/wordlists")


@QtCore.pyqtSlot()
def _slotMenuOpenSSH_UsernameEnumerationClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the command for a script used to enumerate SSH usernames for OpenSSH versions <7.2."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    username_list = "multiplesources-users-fabian-fingerle.de.txt"
    script_command = "python3 OpenSSH7-2_Username_Enumeration.py 192.168.1.1 -U " + username_list + " --factor 10"
    script_dir = os.path.join(fissure.utils.TOOLS_DIR, "Credentials")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + script_command + '"', cwd=script_dir, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "' + script_command + '"', cwd=script_dir, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "' + script_command + '"', cwd=script_dir, shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuLessonHamRadioExamsClicked():
    """Opens the html file in a browser."""
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'Lessons', 'HTML', 'Lesson10_Ham_Radio_Exams.html')}"
    )


@QtCore.pyqtSlot()
def _slotMenu2019_2023_GeneralPoolClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the 2019-2023 General Class Question Pool pdf."""
    # Open the File
    pdf_location = os.path.join(fissure.utils.TOOLS_DIR, "Ham Radio Exam", "2019-2023GeneralClassQuestionPool.pdf")
    if (
        dashboard.backend.os_info == "DragonOS Focal" or
        dashboard.backend.os_info == "DragonOS FocalX" or
        dashboard.backend.os_info == "Kali" or
        dashboard.backend.os_info == "Raspberry Pi OS"
    ):
        os.system('open "' + pdf_location + '" &')
    else:
        os.system('evince "' + pdf_location + '" &')


@QtCore.pyqtSlot()
def _slotMenuGitHubFISSURE_Clicked():
    """Opens the FISSURE GitHub page."""
    # Open a Browser
    os.system("xdg-open https://github.com/ainfosec/fissure")


@QtCore.pyqtSlot()
def _slotMenuGitHub_cpoore1_Clicked():
    """Opens the cpoore1 GitHub page."""
    # Open a Browser
    os.system("xdg-open https://github.com/cpoore1")


@QtCore.pyqtSlot()
def _slotMenuGitHub_ainfosecClicked():
    """Opens the ainfosec GitHub page."""
    # Open a Browser
    os.system("xdg-open https://github.com/ainfosec")


@QtCore.pyqtSlot()
def _slotMenuLessonWiFiToolsClicked():
    """Opens the html file in a browser."""
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'Lessons', 'HTML', 'Lesson11_WiFi_Tools.html')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpPySDR_orgClicked():
    """Opens PySDR.org in a browser."""
    # Open a Browser
    os.system("xdg-open https://pysdr.org/")


@QtCore.pyqtSlot()
def _slotMenuNrsc5_GuiClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the nrsc5-gui for decoding HD radio signals."""
    # Issue the Command
    nrsc5_gui_filepath = os.path.expanduser("~/Installed_by_FISSURE/nrsc5-gui/")
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "./nrsc5_gui.py"', shell=True, cwd=nrsc5_gui_filepath
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "./nrsc5_gui.py"', shell=True, cwd=nrsc5_gui_filepath
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "./nrsc5_gui.py"', shell=True, cwd=nrsc5_gui_filepath
        )


@QtCore.pyqtSlot()
def _slotMenuStandaloneJ2497_ModHackRF_Direct_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "j2497_mod_hackrfdirect.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuStandaloneJ2497_fl2kClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "j2497_mod_fl2k.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuStandaloneJ2497_ModClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "j2497_mod.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuEnscribeClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with an example command for enscribe."""
    # Open a Terminal
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    enscribe_command = "enscribe -oversample -lf=5 -hf=70 -color=yb -wav input.jpg output.wav"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + enscribe_command + '"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + enscribe_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + enscribe_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuOpenWeatherClicked():
    """Opens the Open-weather website in a browser."""
    # Open a Browser
    os.system("xdg-open https://open-weather.community/")


@QtCore.pyqtSlot()
def _slotMenuLTE_ciphercheckClicked(dashboard):
    """Asks for config values and then runs LTE-ciphercheck."""
    # Open the Band Chooser Dialog
    dl_earfcn, done1 = QtWidgets.QInputDialog().getText(dashboard, "Enter target DL_EARFCN", "dl_earfcn (blank=default)")
    apn, done2 = QtWidgets.QInputDialog().getText(dashboard, "Enter target APN", "apn (blank=default)")
    imei, done3 = QtWidgets.QInputDialog().getText(dashboard, "Enter target IMEI", "imei (blank=default)")
    if done1 and done2 and done3:
        # Rewrite the Config File
        with open(os.path.expanduser("~/Installed_by_FISSURE/LTE-ciphercheck/srsue/ciphercheck.conf"), "r") as conf:
            data = conf.readlines()
            if len(dl_earfcn) > 0:
                data[37] = "dl_earfcn = {}\n".format(dl_earfcn)
            if len(imei) > 0:
                data[122] = "imei = {}\n".format(imei)
            if len(apn) > 0:
                data[158] = "apn = {}\n".format(apn)
            with open(os.path.expanduser("~/Installed_by_FISSURE/LTE-ciphercheck/srsue/ciphercheck.conf"), "w") as conf:
                conf.writelines(data)

        # Open a Terminal
        expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
        srsue_location = os.path.expanduser("~/Installed_by_FISSURE/LTE-ciphercheck/build/srsue/src")
        config_file_location = os.path.expanduser("~/Installed_by_FISSURE/LTE-ciphercheck/srsue/ciphercheck.conf")
        command_text = "sudo ./srsue " + config_file_location
        if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
            proc = subprocess.Popen(
                "gnome-terminal -- " + expect_script_filepath + ' "' + command_text + '"',
                cwd=srsue_location,
                shell=True,
            )
        elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
            proc = subprocess.Popen(
                "qterminal -e " + expect_script_filepath + ' "' + command_text + '"', cwd=srsue_location, shell=True
            )
        elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
            proc = subprocess.Popen(
                'lxterminal -e ' + expect_script_filepath + ' "' + command_text + '"', cwd=srsue_location, shell=True
            )


@QtCore.pyqtSlot()
def _slotMenuElectromagneticRadiationSpectrumClicked():
    """Opens the unihedron Electromagnetic Radiation Spectrum Poster in a browser."""
    # Open a Browser
    os.system("xdg-open http://www.unihedron.com/projects/spectrum/downloads/full_spectrum.jpg")


@QtCore.pyqtSlot()
def _slotMenuIIO_OscilloscopeClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the IIO Oscilloscope for Analog Devices products (PlutoSDR)."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "osc"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "osc"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "osc"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuHelpDiscordClicked():
    """Opens a browser to the FISSURE Discord server."""
    # Open a Browser
    os.system("xdg-open https://discord.gg/JZDs5sgxcG")


@QtCore.pyqtSlot()
def _slotMenuLessonSDR_WithHackRF_Clicked():
    """Opens a browser to the Great Scott Gadgets lessons page."""
    # Open a Browser
    os.system("xdg-open https://greatscottgadgets.com/sdr/")


@QtCore.pyqtSlot()
def _slotMenuLessonGNU_RadioTutorialsClicked():
    """Opens a browser to the GNU Radio tutorials page."""
    # Open a Browser
    os.system("xdg-open https://wiki.gnuradio.org/index.php/Tutorials")


@QtCore.pyqtSlot()
def _slotMenuSigDiggerClicked(dashboard: QtWidgets.QMainWindow):
    """Opens SigDigger from the menu."""
    # Issue the Command
    try:
        expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
        if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
            if any(keyword == dashboard.backend.os_info for keyword in fissure.utils.OS_3_10_KEYWORDS):
                sigdigger_location = os.path.expanduser("~/Installed_by_FISSURE/blsd-dir/SigDigger/")
                proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "./SigDigger"', shell=True, cwd=sigdigger_location)
            else:
                proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "SigDigger"', shell=True)
        elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
            proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "SigDigger"', shell=True)
        elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
            if any(keyword == dashboard.backend.os_info for keyword in fissure.utils.OS_3_10_KEYWORDS):
                sigdigger_location = os.path.expanduser("~/Installed_by_FISSURE/blsd-dir/SigDigger/")
                proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "./SigDigger"', shell=True, cwd=sigdigger_location)
            else:
                proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "SigDigger"', shell=True)
    except:
        dashboard.logger.error("Error accessing SigDigger location.")


@QtCore.pyqtSlot()
def _slotMenuHam2monClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with the ham2mon command. Refer to its readme for controls."""
    # Open a Terminal
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    ham2mon_directory = os.path.expanduser("~/Installed_by_FISSURE/ham2mon/apps/")
    ham2mon_cmd = 'python3 ham2mon.py -a "uhd" -n 8 -d 0 -f 146E6 -r 4E6 -g 30 -s -60 -v 0 -t 10'
    # proc = subprocess.Popen('gnome-terminal --maximize --window --working-directory="' + ham2mon_directory + \
    #    '" -- ' + ham2mon_cmd, cwd=ham2mon_directory, shell=True)
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + ham2mon_cmd + '"', cwd=ham2mon_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "' + ham2mon_cmd + '"', cwd=ham2mon_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "' + ham2mon_cmd + '"', cwd=ham2mon_directory, shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuLessonProgrammingSDRsClicked():
    """Opens the Bastian Bloessl tutorial from ACM WiSec2021 Conference."""
    # Open a Browser
    os.system("xdg-open https://www.youtube.com/watch?v=WqAqPEXZs-Q&t=16870s")


@QtCore.pyqtSlot()
def _slotMenuLessonLearnSDR_Clicked():
    """Opens the Harvey Mudd College tutorials."""
    # Open a Browser
    os.system("xdg-open https://gallicchio.github.io/learnSDR/")


@QtCore.pyqtSlot()
def _slotMenuQSSTV_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens QSSTV from the menu."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "qsstv"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "qsstv"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "qsstv"', shell=True)


@QtCore.pyqtSlot()
def _slotMenu_m17_demodClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with an example m17-demod command."""
    # Open a Terminal
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    m17_demod_cmd = "nc -l -u -p 7355 | m17-demod -l -d | play -q -b 16 -r 8000 -c1 -t s16 -"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "' + m17_demod_cmd + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + m17_demod_cmd + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + m17_demod_cmd + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuMultimon_ngClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with an example multimon-ng command for POCSAG. Works with Narrow FM in Gqrx and UDP output."""
    # Open a Terminal
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    multimon_ng_cmd = "nc -l -u -p 7355 | sox -t raw -esigned-integer -b 16 -r 48000 - -esigned-integer -b 16 -r 22050 -t raw - | multimon-ng -t raw -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -f alpha -"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + multimon_ng_cmd + '"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + multimon_ng_cmd + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + multimon_ng_cmd + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuFldigiClicked(dashboard: QtWidgets.QMainWindow):
    """Opens Fldigi from the menu."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "fldigi"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "fldigi"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "fldigi"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuStandaloneFrequencyTranslatingClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "frequency_translating.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuTriqOrgClicked():
    """Opens triq.org in a browser."""
    # Open a Browser
    os.system("xdg-open https://triq.org/")


@QtCore.pyqtSlot()
def _slotMenuPyFDA_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens pyFDA from the menu."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "pyfdax"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "pyfdax"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "pyfdax"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuMorseCodeTranslatorClicked():
    """Opens morsecode.world in a browser."""
    # Open a Browser
    os.system("xdg-open https://morsecode.world/international/translator.html")


@QtCore.pyqtSlot()
def _slotMenuPSK_ReporterClicked():
    """Opens PSK Reporter in a browser."""
    # Open a Browser
    os.system("xdg-open https://pskreporter.info/pskmap.html")


@QtCore.pyqtSlot()
def _slotMenuAmateurSatelliteDatabaseClicked():
    """Opens Amateur Satellite Database in a browser."""
    # Open a Browser
    os.system("xdg-open https://amsat.org/amateur-satellite-index")


@QtCore.pyqtSlot()
def _slotMenuCryptiiClicked():
    """Opens cryptii.com in a browser."""
    # Open a Browser
    os.system("xdg-open https://cryptii.com/")


@QtCore.pyqtSlot()
def _slotMenuLessonCreatingBootableUSBsClicked():
    """Opens the html file in a browser."""
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'Lessons', 'HTML', 'Lesson12_Creating_Bootable_USBs.html')}"
    )


@QtCore.pyqtSlot()
def _slotMenuDireWolfClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with an example Dire Wolf command."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    dire_wolf_command = "direwolf -r 48000 udp:7355  # GQRX: Narrow FM, UDP port 7355"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + dire_wolf_command + '"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + dire_wolf_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + dire_wolf_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuMeldClicked(dashboard: QtWidgets.QMainWindow):
    """Launches Meld for diff'ing files and folders."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "meld"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "meld"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "meld"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuHfpropagationClicked():
    """Opens hfpropagation.com in a browser."""
    # Open a Browser
    os.system("xdg-open https://hfpropagation.com/")


@QtCore.pyqtSlot()
def _slotMenuWaveDromClicked():
    """Opens WaveDrom editor in a browser."""
    # Open a Browser
    os.system("xdg-open https://wavedrom.com/editor.html")


@QtCore.pyqtSlot()
def _slotMenuPacketDiagramClicked(dashboard: QtWidgets.QMainWindow):
    """Provides example command for packetdiag."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    sample_diagram = os.path.join(fissure.utils.TOOLS_DIR, "simple.diag")
    packetdiag_command = "packetdiag " + sample_diagram + " -o ~/simple.png  # Edit /FISSURE/Tools/simple.diag"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + packetdiag_command + '"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + packetdiag_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + packetdiag_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuHamClockTriggered(dashboard: QtWidgets.QMainWindow):
    """Launches HamClock."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "hamclock"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "hamclock"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "hamclock"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuICE9_BluetoothSnifferClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with an example command for using the ICE9 Bluetooth Sniffer for HackRF."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    ice9_directory = os.path.expanduser("~/Installed_by_FISSURE/ice9-bluetooth-sniffer/build/")
    ice9_command = "./ice9-bluetooth -l -c 2427 -C 20 -w ~/ble.pcap"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + ice9_command + '"', cwd=ice9_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        if dashboard.backend.os_info == "DragonOS Focal" or dashboard.backend.os_info == "DragonOS FocalX":
            ice9_directory = '/usr/src/ice9-bluetooth-sniffer/build/'
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "' + ice9_command + '"', cwd=ice9_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "' + ice9_command + '"', cwd=ice9_directory, shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuStandalone_pocsagtxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "pocsagtx.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenu_dump978_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with an example dump978 command."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    dump978_directory = os.path.expanduser("~/Installed_by_FISSURE/dump978/")
    dump978_command = "rtl_sdr -f 978000000 -s 2083334 -g 48 - | ./dump978 | ./uat2text"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + dump978_command + '"',
            cwd=dump978_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "' + dump978_command + '"', cwd=dump978_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "' + dump978_command + '"', cwd=dump978_directory, shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuIQEngineClicked():
    """Opens IQEngine in a browser."""
    # Open a Browser
    os.system("xdg-open https://iqengine.org/")


@QtCore.pyqtSlot()
def _slotMenu_rfidpicsClicked():
    """Opens rfidpics in a browser."""
    # Open a Browser
    os.system("xdg-open https://doegox.github.io/rfidpics/")


@QtCore.pyqtSlot()
def _slotMenu_acars_adsbexchangeClicked():
    """Opens acars.adsbexchange in a browser."""
    # Open a Browser
    os.system("xdg-open https://acars.adsbexchange.com/")


@QtCore.pyqtSlot()
def _slotMenuAirframesClicked():
    """Opens Airframes in a browser."""
    # Open a Browser
    os.system("xdg-open https://app.airframes.io/flights")


@QtCore.pyqtSlot()
def _slotMenu_htopClicked(dashboard: QtWidgets.QMainWindow):
    """Launches htop in the tree view."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    htop_command = "htop -t"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "' + htop_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + htop_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + htop_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenu_WSPR_RocksClicked():
    """Opens WSPR Rocks! in a browser."""
    # Open a Browser
    os.system("xdg-open http://wspr.rocks/")


@QtCore.pyqtSlot()
def _slotMenu_wttr_inClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with text for a curl to wttr.in."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    wttr_in_command = "curl wttr.in?3"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + wttr_in_command + '"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + wttr_in_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + wttr_in_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuQtDesignerDashboardUiClicked(dashboard: QtWidgets.QMainWindow):
    """Opens dashboard.ui in QtDesigner."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    ui_directory = os.path.join(fissure.utils.UI_DIR)
    dashboard_ui_command = "designer dashboard.ui"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + dashboard_ui_command + '"',
            cwd=ui_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "' + dashboard_ui_command + '"', cwd=ui_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "' + dashboard_ui_command + '"', cwd=ui_directory, shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuFissureDashboardUiClicked(dashboard: QtWidgets.QMainWindow):
    """
    Opens FissureDashboard.ui in QtDesigner.
    """
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    ui_directory = os.path.join(fissure.utils.UI_DIR)
    dashboard_ui_command = "designer FissureDashboard.ui"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + dashboard_ui_command + '"',
            cwd=ui_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "' + dashboard_ui_command + '"', cwd=ui_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "' + dashboard_ui_command + '"', cwd=ui_directory, shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuQtDesignerOptionsUiClicked(dashboard: QtWidgets.QMainWindow):
    """Opens options.ui in QtDesigner."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    ui_directory = os.path.join(fissure.utils.UI_DIR)
    options_ui_command = "designer options.ui"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + options_ui_command + '"',
            cwd=ui_directory,
            shell=True,
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "' + options_ui_command + '"', cwd=ui_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "' + options_ui_command + '"', 
            cwd=ui_directory, 
            shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuGripClicked(dashboard: QtWidgets.QMainWindow):
    """Provides an example grip command to convert Markdown to HTML."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    grip_directory = os.path.join(fissure.utils.FISSURE_ROOT, "docs", "Lessons", "Markdown")
    grip_command = "grip Lesson1_OpenBTS.md --export ../HTML/Lesson1_OpenBTS.html"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + grip_command + '"', cwd=grip_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "' + grip_command + '"', cwd=grip_directory, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "' + grip_command + '"', cwd=grip_directory, shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuArduinoClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with the Arduino IDE command."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    arduino_command = "arduino"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + arduino_command + '"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + arduino_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + arduino_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenu_guidusClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with the guidus command for editing USBs."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    guidus_command = "sudo guidus"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "' + guidus_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + guidus_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + guidus_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuSystembackClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with the Systemback command for creating system images."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    systemback_command = "sudo systemback"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + systemback_command + '"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + systemback_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + systemback_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuOpenWebRX_Clicked(dashboard: QtWidgets.QMainWindow):
    """Starts the openwebrx service and opens a browser to localhost:8083."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    openwebrx_command = "sudo openwebrx"
    os.system("xdg-open http://127.0.0.1:8073")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + openwebrx_command + '"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + openwebrx_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + openwebrx_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuTuneInExplorerClicked():
    """Opens TuneIn Explorer in a browser."""
    # Open a Browser
    os.system("xdg-open https://tunein.com/explorer/")


@QtCore.pyqtSlot()
def _slotMenuYouTubeClicked():
    """Opens FISSURE Videos YouTube playlist in a browser."""
    # Open a Browser
    os.system("xdg-open https://www.youtube.com/playlist?list=PLs4a-ctXntfjpmc_hrvI0ngj4ZOe_5xm_")


@QtCore.pyqtSlot()
def _slotMenuGpickClicked(dashboard: QtWidgets.QMainWindow):
    """Launches Gpick."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "gpick"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "gpick"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "gpick"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuLessonComplexToRealClicked():
    """Opens complextoreal.com tutorials on digital communications engineering in a browser."""
    # Open a Browser
    os.system("xdg-open http://complextoreal.com/tutorials/")


@QtCore.pyqtSlot()
def _slotMenuSolveCryptoWithForceClicked():
    """Opens scwf.dima.ninja in a browser."""
    # Open a Browser
    os.system("xdg-open https://scwf.dima.ninja/")


@QtCore.pyqtSlot()
def _slotMenuCrackStationClicked():
    """Opens crackstation.net in a browser."""
    # Open a Browser
    os.system("xdg-open https://crackstation.net/")


@QtCore.pyqtSlot()
def _slotMenuGHexClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the GHex editor."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "ghex"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "ghex"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "ghex"', shell=True)


@QtCore.pyqtSlot()
def _slotMenu_qFlipperClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with the command to run qFlipper."""
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    qFlipper_dir = os.path.expanduser("~/Installed_by_FISSURE/qFlipper/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        qFlipper_command = "sudo ./qFlipper*"
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + qFlipper_command + '"', cwd=qFlipper_dir, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        qFlipper_command = "sudo .//qFlipper*"
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "' + qFlipper_command + '"', cwd=qFlipper_dir, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        qFlipper_command = "sudo ./qFlipper*"
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "' + qFlipper_command + '"', cwd=qFlipper_dir, shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuAIVDM_AIVDO_DecodingClicked():
    """Opens AIVDM AIVDO Decoding in a browser."""
    # Open a Browser
    os.system("xdg-open https://gpsd.gitlab.io/gpsd/AIVDM.html")


@QtCore.pyqtSlot()
def _slotMenuAIS_VDM_VDO_DecoderClicked():
    """Opens AIS VDM VDO Decoder in a browser."""
    # Open a Browser
    os.system("xdg-open https://www.maritec.co.za/aisvdmvdodecoding")


@QtCore.pyqtSlot()
def _slotMenuAIS_OnlineDecoderClicked():
    """Opens AIS Online Decoder in a browser."""
    # Open a Browser
    os.system("xdg-open https://www.aggsoft.com/ais-decoder.htm")


@QtCore.pyqtSlot()
def _slotMenu_pyaisGitHubClicked():
    """Opens pyais GitHub in a browser."""
    # Open a Browser
    os.system("xdg-open https://github.com/M0r13n/pyais")


@QtCore.pyqtSlot()
def _slotMenuStandaloneAiS_TX_Clicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "AiS_TX.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuStandalone_ais_rx_demodClicked(dashboard: QtWidgets.QMainWindow):
    """Opens the standalone flow graph in GNU Radio Companion."""
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "ais_rx_demod.grc")
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString + " &")


@QtCore.pyqtSlot()
def _slotMenuADSB_TowersClicked():
    """Opens towers.stratux.me in a browser."""
    # Open a Browser
    os.system("xdg-open http://towers.stratux.me/")


@QtCore.pyqtSlot()
def _slotMenuHelpRequirementsClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'installation.html#requirements')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpCloningClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'installation.html#cloning')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpInstallerClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'installation.html#installer')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpUninstallingClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'installation.html#uninstalling')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpUsageClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'installation.html#usage')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpKnownConflictsClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'installation.html#known-conflicts')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpThirdPartySoftwareClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'installation.html#third-party-software')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpThirdPartySoftwareVersionsClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'installation.html#third-party-software-versions')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpHardwareSupportedClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'hardware.html#supported')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpHardwareConfiguringClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'hardware.html#configuring')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpHardwareLimeSDR_Clicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'hardware.html#limesdr-notes')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpHardwareNewUSRPX310_Clicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'hardware.html#new-usrp-x310')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpHardwareUpdatingHackRFClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'hardware.html#updating-hackrf-firmware')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpHardwareGNU_RadioHardwareClicked():
    """Opens the GNU Radio Hardware wiki page in a browser."""
    # Open a Browser
    os.system("xdg-open https://wiki.gnuradio.org/index.php/Hardware")


@QtCore.pyqtSlot()
def _slotMenuHelpComponentsCommunicationsClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'components.html#communications')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpComponentsLibraryClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'components.html#library')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpComponentsFileStructureClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'components.html#file-structure')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpComponentsSupportedProtocolsClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'components.html#supported-protocols')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpComponentsDashboardClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'components.html#dashboard')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpComponentsTSI_Clicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'components.html#target-signal-identification')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpComponentsPD_Clicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'components.html#protocol-discovery')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpComponentsFGE_Clicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'components.html#flow-graph-script-executor')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpComponentsHIPRFISR_Clicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'components.html#hiprfisr')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationHardwareButtonsClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#hardware-buttons')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationNetworkingConfigurationClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#networking-configuration')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationLessonsClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#lessons')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationStandaloneFlowGraphsClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#standalone-flow-graphs')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationToolsClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#tools')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationOptionsClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#options')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationViewClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#view')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationAutomationClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#automation-tab')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationTSI_Clicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#tsi-tab')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationPD_Clicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#pd-tab')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationAttackClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#attack-tab')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationIQ_DataClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#iq-data-tab')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationArchiveClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#archive-tab')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationPacketCrafterClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#packet-crafter-tab')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationLibraryClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#library-tab')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationLogClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#log-tab')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpOperationStatusBarClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'operation.html#status-bar')}"
    )


@QtCore.pyqtSlot()
def _slotMenuAPRS_TrackDirectClicked():
    """Opens the APRS Track Direct map in a browser."""
    # Open a Browser
    os.system("xdg-open http://lora.ham-radio-op.net/")


@QtCore.pyqtSlot()
def _slotMenuHelpDevelopmentAddingCustomOptionsClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'development.html#adding-custom-options')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpDevelopmentBuiltWithClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'development.html#built-with')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpDevelopmentUploadingFlowGraphsClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'development.html#attack-flow-graphs')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpDevelopmentUploadingPythonScriptsClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'development.html#attack-python-scripts')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpDevelopmentInspectionFlowGraphsClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'development.html#inspection-flow-graphs')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpDevelopmentModifyingDashboardClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'development.html#modifying-dashboard')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpAboutClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'about.html')}"
    )


@QtCore.pyqtSlot()
def _slotMenuHelpCreditsClicked():
    """Opens the FISSURE documentation in a browser."""
    # Open a Browser
    os.system(
        f"xdg-open {os.path.join(fissure.utils.FISSURE_ROOT, 'docs', 'RTD', '_build', 'html', 'pages', 'about.html#credits')}"
    )


@QtCore.pyqtSlot()
def _slotMenuOpenRailwayMapClicked():
    """Opens OpenRailwayMap in a browser."""
    # Open a Browser
    os.system("xdg-open https://www.openrailwaymap.org/")


@QtCore.pyqtSlot()
def _slotMenuOrbitalElementConverterClicked():
    """Opens orbital element converter in a browser."""
    # Open a Browser
    os.system("xdg-open http://orbitsimulator.com/formulas/OrbitalElements.html")


@QtCore.pyqtSlot()
def _slotMenuSatelliteLinkBudgetClicked():
    """
    Opens satellite link budget calculator in a browser.
    """
    # Open a Browser
    os.system("xdg-open https://www.satsig.net/linkbugt.htm")


@QtCore.pyqtSlot()
def _slotMenuWebSDR_Clicked():
    """
    Opens WebSDR in a browser.
    """
    # Open a Browser
    os.system("xdg-open http://websdr.org/")


@QtCore.pyqtSlot()
def _slotMenuCemaxecuterYouTubeClicked():
    """
    Opens cemaexecuter YouTube videos in a browser.
    """
    # Open a Browser
    os.system("xdg-open https://www.youtube.com/@cemaxecuter7783/videos")


@QtCore.pyqtSlot()
def _slotMenuIcemanYouTubeClicked():
    """
    Opens Iceman YouTube videos in a browser.
    """
    # Open a Browser
    os.system("xdg-open https://www.youtube.com/@iceman1001/videos")


@QtCore.pyqtSlot()
def _slotMenuGPSJAM_Clicked():
    """
    Opens GPSJAM in a browser.
    """
    # Open a Browser
    os.system("xdg-open https://gpsjam.org/")


@QtCore.pyqtSlot()
def _slotMenuHF_PropagationMapClicked():
    """
    Opens HF Propagation Map in a browser.
    """
    # Open a Browser
    os.system("xdg-open https://hf.dxview.org/")


@QtCore.pyqtSlot()
def _slotMenuHAMRS_Clicked(dashboard: QtWidgets.QMainWindow):
    """
    Opens a terminal to the HAMRS location.
    """
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    hamrs_dir = os.path.expanduser("~/Installed_by_FISSURE/HAMRS/")
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        hamrs_command = "./hamrs*"
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + hamrs_command + '"', cwd=hamrs_dir, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        hamrs_command = ".//hamrs*"
        proc = subprocess.Popen(
            "qterminal -e " + expect_script_filepath + ' "' + hamrs_command + '"', cwd=hamrs_dir, shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        hamrs_command = "./hamrs*"
        proc = subprocess.Popen(
            'lxterminal -e ' + expect_script_filepath + ' "' + hamrs_command + '"', cwd=hamrs_dir, shell=True
        )


@QtCore.pyqtSlot()
def _slotMenuMLAT_FeederMapClicked():
    """
    Opens MLAT Feeder Map in a browser.
    """
    # Open a Browser
    os.system("xdg-open https://map.adsbexchange.com/mlat-map/")


@QtCore.pyqtSlot()
def _slotMenuHelpFISSURE_ChallengeClicked():
    """
    Opens the FISSURE Challenge page in a browser.
    """
    # Open a Browser
    os.system("xdg-open https://fissure.ainfosec.com/")


@QtCore.pyqtSlot()
def _slotMenuBinwalkClicked(dashboard: QtWidgets.QMainWindow):
    """
    Opens a terminal with an example binwalk command.
    """
    # Issue the Command
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    binwalk_command = "binwalk -h"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + binwalk_command + '"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + binwalk_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + binwalk_command + '"', shell=True)


@QtCore.pyqtSlot()
def _slotMenuN2YO_Clicked():
    """
    Opens N2YO in a browser.
    """
    # Open a Browser
    os.system("xdg-open https://www.n2yo.com/")


@QtCore.pyqtSlot()
def _slotMenuFindSatellitesClicked():
    """
    Opens Find Satellites in a browser.
    """
    # Open a Browser
    os.system("xdg-open https://www.find-satellites.com/")


@QtCore.pyqtSlot()
def _slotMenuAGSatTrackClicked():
    """
    Opens AGSatTrack in a browser.
    """
    # Open a Browser
    os.system("xdg-open https://agsattrack.com/")


@QtCore.pyqtSlot()
def _slotMenuCelestrakClicked():
    """
    Opens Celestrak in a browser.
    """
    # Open a Browser
    os.system("xdg-open https://celestrak.org/")


@QtCore.pyqtSlot()
def _slotMenuSpotTheStationClicked():
    """
    Opens Spot The Station in a browser.
    """
    # Open a Browser
    os.system("xdg-open https://spotthestation.nasa.gov/")


@QtCore.pyqtSlot()
def _slotMenuLessonHideoOkawaraClicked():
    """
    Opens Hideo Okawara's Mixed Signal Lecture Series (Tom Verbeure) in a browser.
    """
    # Open a Browser
    os.system("xdg-open https://tomverbeure.github.io/2024/01/06/Hideo-Okawara-Mixed-Signal-Lecture-Series.html")


@QtCore.pyqtSlot()
def _slotMenuStandaloneTeslaChargePortClicked(dashboard: QtWidgets.QMainWindow):
    """
    Opens the standalone flow graph in GNU Radio Companion.
    """
    # Open the Flow Graph in GNU Radio Companion
    filepath = os.path.join(
        fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Standalone Flow Graphs", "tesla_charge_port_remote_ook_synthesizer.grc"
    )
    osCommandString = 'gnuradio-companion "' + filepath + '" &'
    os.system(osCommandString)


@QtCore.pyqtSlot()
def _slotMenuRememberConfigurationClicked(dashboard: QtWidgets.QMainWindow):
    """
    Updates fissure_config.yaml and default.yaml remember_configuration field. Currently checks default.yaml on startup.
    """
    # Load the YAML
    get_settings = fissure.utils.load_yaml(fissure.utils.FISSURE_CONFIG_FILE)
    get_settings_default = fissure.utils.load_yaml(fissure.utils.FISSURE_CONFIG_DEFAULT)
    
    # Remember
    if dashboard.window.actionRemember_Configuration.isChecked():
        # Change the Value
        get_settings["remember_configuration"] = True
        get_settings_default["remember_configuration"] = True

        # Save the YAML
        fissure.utils.save_yaml(fissure.utils.FISSURE_CONFIG_FILE, get_settings)
        fissure.utils.save_yaml(fissure.utils.FISSURE_CONFIG_DEFAULT, get_settings_default)

    # Forget
    else:
        # Change the Value
        get_settings["remember_configuration"] = False
        get_settings_default["remember_configuration"] = False

        # Save the YAML
        fissure.utils.save_yaml(fissure.utils.FISSURE_CONFIG_FILE, get_settings)
        fissure.utils.save_yaml(fissure.utils.FISSURE_CONFIG_DEFAULT, get_settings_default)


@QtCore.pyqtSlot()
def _slotMenuWlColorPickerClicked():
    """
    Opens wl-color-picker.
    """
    # Launch wl-color-picker
    wl_color_picker_dir = os.path.expanduser("~/Installed_by_FISSURE/wl-color-picker/")
    proc = subprocess.Popen("./wl-color-picker.sh &", shell=True, cwd=wl_color_picker_dir)


@QtCore.pyqtSlot()
def _slotMenuTpmsRxClicked(dashboard: QtWidgets.QMainWindow):
    """Opens a terminal with the tpms_rx command."""
    # Launch tpms_rx
    expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
    #tpms_command = "tpms_rx --source rtlsdr --if-rate 400000 --tuned-frequency 315000000"
    tpms_command = "sudo tpms_rx --source hackrf --if-rate 400000 --tuned-frequency 315000000"
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc = subprocess.Popen(
            "gnome-terminal -- " + expect_script_filepath + ' "' + tpms_command + '"', shell=True
        )
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + tpms_command + '"', shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + tpms_command + '"', shell=True)

