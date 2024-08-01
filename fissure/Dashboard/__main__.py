# from fissure.Dashboard.Backend import DashboardBackend
from fissure.Dashboard.Frontend import Dashboard
from PyQt5 import QtWidgets

import asyncio
import fissure.utils
import qasync
import sys


def run():
    fissure.utils.init_logging()

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
