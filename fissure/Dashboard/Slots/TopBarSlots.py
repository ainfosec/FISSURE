from ..UI_Components import NodeSelectDialog
from ..UI_Components import NodeConfigureDialog
from PyQt5 import QtCore, QtWidgets

import time
import os
import fissure.utils
import subprocess
import qasync
import asyncio
import sys
import signal

# top_buttons[node_idx].setStyleSheet("color: rgb(0,0,0); border: 2px solid darkGray; border-radius: 10px; border-style: outset; border-color: " + dashboard.backend.settings['color3'] + "; background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,stop: 0 #ffb477, stop: 1 #db8d4e); min-width: 80px;")
# top_buttons[n].setStyleSheet("")


@QtCore.pyqtSlot(QtCore.QObject)
def demoClicked(dashboard: QtCore.QObject):
    """ 
    Stops demo mode.
    """
    # Set the Flag
    dashboard.logger.info("Stop Demo Mode")
    dashboard.stop_demo_flag = True
    dashboard.ui.pushButton_demo.setText("Stopping...")


@qasync.asyncSlot(QtCore.QObject)
async def _slotLaunchLocalNodeClicked(dashboard: QtCore.QObject):
    """
    Launch or stop a local sensor node from the Dashboard top bar.
    """
    proc = getattr(dashboard, "local_sensor_node_process", None)

    # Stop local node
    if proc is not None and proc.poll() is None:
        await stopLocalSensorNode(dashboard, remove_from_hiprfisr=True)
        return

    # Launch local node
    sensor_node_path = os.path.join(
        fissure.utils.SENSOR_NODE_DIR,
        "SensorNode.py"
    )

    dashboard.local_sensor_node_process = subprocess.Popen(
        [
            sys.executable,
            sensor_node_path,
            "--local",
        ],
        start_new_session=True,
    )

    dashboard.logger.info("Launching local sensor node, please wait...")
    dashboard.new_local_connection = True

    dashboard.ui.label_top_launch_local_node_title.setText("Stop Local Node")
    dashboard.ui.label_top_launch_local_node_subtitle.setText("Terminate the local sensor node")
    dashboard.ui.frame_top_launch_local_node.setEnabled(True)


async def stopLocalSensorNode(dashboard: QtCore.QObject, remove_from_hiprfisr: bool = True):
    """
    Stop the local sensor node process and optionally remove it from HIPRFISR.
    """
    proc = getattr(dashboard, "local_sensor_node_process", None)

    if proc is not None and proc.poll() is None:
        dashboard.logger.info("Stopping local sensor node...")

        try:
            # Kill the whole local-node process group if it was launched with start_new_session=True.
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except Exception as e:
            dashboard.logger.warning(f"Failed to terminate local sensor node process group: {e}")
            proc.terminate()

        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            dashboard.logger.warning("Local sensor node did not stop cleanly. Killing it.")

            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception as e:
                dashboard.logger.warning(f"Failed to kill local sensor node process group: {e}")
                proc.kill()

            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                dashboard.logger.error("Local sensor node still did not exit after SIGKILL.")

    dashboard.local_sensor_node_process = None

    if remove_from_hiprfisr:
        try:
            uuid_file = os.path.expanduser("~/.fissure/local_sensor_node_uuid.uuid")

            with open(uuid_file, "r") as f:
                node_uid = f.read().strip()

            if node_uid:
                await dashboard.backend.removeNode(node_uid=node_uid)

                selected_uid = getattr(dashboard, "selected_node_uid", "") or ""
                selected_settings = getattr(dashboard, "selected_node_settings", {}) or {}
                sensor_settings = selected_settings.get("Sensor Node", {}) or {}

                selected_is_removed_node = (
                    selected_uid == node_uid
                    or selected_uid.endswith(node_uid)
                    or node_uid.endswith(selected_uid)
                    or selected_uid in node_uid
                    or node_uid in selected_uid
                )

                selected_is_local = (
                    str(sensor_settings.get("local_remote", "")).strip().lower() == "local"
                    or str(sensor_settings.get("node_ip_address", "")).strip().lower() == "ipc"
                    or str(getattr(dashboard, "selected_node_ip", "") or "").strip().lower() == "ipc"
                )

                if selected_is_removed_node:
                    clearSelectedNode(dashboard)

        except FileNotFoundError:
            dashboard.logger.warning("Local sensor node UUID file not found.")
        except Exception as e:
            dashboard.logger.error(f"Failed to remove local node from HIPRFISR: {e}")

    dashboard.ui.label_top_launch_local_node_title.setText("Launch Local Node")
    dashboard.ui.label_top_launch_local_node_subtitle.setText("Start a local sensor node")
    dashboard.ui.frame_top_launch_local_node.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSelectNodeClicked(dashboard: QtCore.QObject):
    dashboard.openPopUp("NodeSelectDialog", NodeSelectDialog)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotConfigureNodeClicked(dashboard: QtCore.QObject):
    if not getattr(dashboard, "selected_node_uid", None):
        return

    dashboard.openPopUp("NodeConfigureDialog", NodeConfigureDialog)


def _refresh_frame_style(frame):
    frame.style().unpolish(frame)
    frame.style().polish(frame)
    frame.update()


def _topFramePressed(frame: QtWidgets.QFrame, event: QtCore.QEvent):
    if event.button() != QtCore.Qt.LeftButton:
        return

    frame.setProperty("pressed", True)
    _refresh_frame_style(frame)


def _topFrameReleased(dashboard, frame: QtWidgets.QFrame, event: QtCore.QEvent, callback):
    if event.button() != QtCore.Qt.LeftButton:
        return

    frame.setProperty("pressed", False)
    _refresh_frame_style(frame)

    if not frame.rect().contains(event.pos()):
        return

    result = callback(dashboard)

    if asyncio.iscoroutine(result):
        asyncio.create_task(result)


def clearSelectedNode(dashboard: QtCore.QObject):
    """
    Clear the currently selected sensor node in the Dashboard UI.

    This is the central selected-node cleanup path. It clears the top-bar
    selected-node state, resets the selected-node card, and then refreshes
    hardware-dependent widgets through configureSelectedNodeHardware().

    TSI Fixed stacked-widget behavior is intentionally not handled directly
    here. It is owned by:

        configureSelectedNodeHardware()
            -> configureTSI_Hardware()
                -> TSITabSlots.update_tsi_fixed_detector_node_gate()
    """
    dashboard.selected_node_uid = ""
    dashboard.selected_node_ip = ""
    dashboard.selected_node_settings = {}

    # Show "No Node Selected" page in the top-bar selected-node card.
    dashboard.ui.stackedWidget_top_configure_node.setCurrentIndex(0)

    # Reset selected-node card styling.
    frame = dashboard.ui.frame_top_configure_node
    frame.setProperty("selected", "false")
    frame.setProperty("connected", "false")
    frame.setProperty("pressed", "false")
    frame.style().unpolish(frame)
    frame.style().polish(frame)
    frame.update()

    # Refresh all selected-node-dependent hardware widgets.
    # This includes the TSI Fixed no-node stacked-widget gate through
    # configureTSI_Hardware().
    try:
        dashboard.configureSelectedNodeHardware()
    except Exception as e:
        dashboard.logger.debug(
            f"Could not refresh selected-node hardware after clearing selected node: {e}"
        )