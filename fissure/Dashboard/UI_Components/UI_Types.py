from PyQt5 import uic

import fissure.utils
import os

uic.properties.logger.setLevel("INFO")
uic.uiparser.logger.setLevel("INFO")


class UI_Types:
    Dashboard, _ = uic.loadUiType(os.path.join(fissure.utils.UI_DIR, "dashboard.ui"))
    Options, _ = uic.loadUiType(os.path.join(fissure.utils.UI_DIR, "options.ui"))
    Node_Select, _ = uic.loadUiType(os.path.join(fissure.utils.UI_DIR, "node_select.ui"))
    Node_Configure, _ = uic.loadUiType(os.path.join(fissure.utils.UI_DIR, "node_configure.ui"))
    Status, _ = uic.loadUiType(os.path.join(fissure.utils.UI_DIR, "status.ui"))
    Chooser, _ = uic.loadUiType(os.path.join(fissure.utils.UI_DIR, "chooser.ui"))
    New_SOI, _ = uic.loadUiType(os.path.join(fissure.utils.UI_DIR, "new_soi.ui"))
    SigMF, _ = uic.loadUiType(os.path.join(fissure.utils.UI_DIR, "sigmf.ui"))
    CustomColor, _ = uic.loadUiType(os.path.join(fissure.utils.UI_DIR, "custom_color.ui"))
    JointPlot, _ = uic.loadUiType(os.path.join(fissure.utils.UI_DIR, "joint_plot.ui"))
    Trim, _ = uic.loadUiType(os.path.join(fissure.utils.UI_DIR, "trim.ui"))
    Triggers, _ = uic.loadUiType(os.path.join(fissure.utils.UI_DIR, "triggers.ui"))
    DetectorSelection, _ = uic.loadUiType(os.path.join(fissure.utils.UI_DIR, "detector_selection.ui"))
    Demod, _ = uic.loadUiType(os.path.join(fissure.utils.UI_DIR, "demod.ui"))
    Features, _ = uic.loadUiType(os.path.join(fissure.utils.UI_DIR, "features.ui"))
    DownloadMapPack, _ = uic.loadUiType(os.path.join(fissure.utils.UI_DIR, "download_map_pack.ui"))

