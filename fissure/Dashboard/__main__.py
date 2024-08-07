# from fissure.Dashboard.Backend import DashboardBackend
from fissure.Dashboard.Frontend import Dashboard
from PyQt5 import QtWidgets
from PyQt5 import QtCore

import asyncio
import fissure.utils
import qasync
import sys


def run():
    fissure.utils.init_logging()
    # Handle high resolution displays:
    if hasattr(QtCore.Qt, 'AA_EnableHighDpiScaling'):
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)
    if hasattr(QtCore.Qt, 'AA_UseHighDpiPixmaps'):
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps, True)

    app = QtWidgets.QApplication(sys.argv)

    eventLoop: asyncio.AbstractEventLoop = qasync.QEventLoop(app)
    asyncio.set_event_loop(eventLoop)

    gui = Dashboard()
    gui.show()

    with eventLoop:
        eventLoop.run_forever()


if __name__ == "__main__":
    rc = 0
    # try:
    run()
    # except Exception:
        # rc = 1

    sys.exit(rc)
