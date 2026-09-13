#! /usr/bin/env python3
"""Live Video Stream Operation

Serves a local V4L2 camera as an H.264 RTSP stream.

The RTSP server listens on the Sensor Node, so viewers connect to the node
instead of the node pushing video to a configured destination. The shared media
factory allows multiple clients, such as the FISSURE Dashboard and WinTAK, to
view the same camera feed simultaneously.
"""

import asyncio
import logging
import os
import sys
from typing import Any, Callable, Union


PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FISSURE_REPO_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))

for path in (FISSURE_REPO_ROOT, PLUGIN_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from fissure.utils.plugins.operations import Operation


def _to_int(value: Any, default: int) -> int:
    try:
        if value is None:
            return int(default)
        return int(float(value))
    except Exception:
        return int(default)


def _to_str(value: Any, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, value))


class OperationMain(Operation):
    """Serve a Sensor Node camera through RTSP."""

    def __init__(
        self,
        rtsp_port: int = 8554,
        device: str = "/dev/video0",
        source_format: str = "YUY2",
        width: int = 640,
        height: int = 480,
        fps: int = 30,
        bitrate_kbps: int = 750,
        operation_id: str = "",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        alert_callback: Union[Callable, None] = None,
        tak_cot_callback: Union[Callable, None] = None,
        status_callback: Union[Callable, None] = None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            alert_callback=alert_callback,
            tak_cot_callback=tak_cot_callback,
            status_callback=status_callback,
        )

        self.rtsp_port = _clamp(_to_int(rtsp_port, 8554), 1, 65535)
        self.device = _to_str(device, "/dev/video0")
        self.source_format = _to_str(source_format, "YUY2").upper()
        self.width = _clamp(_to_int(width, 640), 160, 3840)
        self.height = _clamp(_to_int(height, 480), 120, 2160)
        self.fps = _clamp(_to_int(fps, 30), 1, 120)
        self.bitrate_kbps = _clamp(_to_int(bitrate_kbps, 750), 64, 20000)
        self.operation_id = _to_str(operation_id, "")

        if self.source_format not in {"YUY2", "MJPG"}:
            raise ValueError("source_format must be YUY2 or MJPG")

        self.rtsp_path = "/fissure"

        self._Gst = None
        self._GstRtspServer = None
        self._GLib = None

        self._server = None
        self._factory = None
        self._mounts = None
        self._main_loop = None
        self._main_loop_task = None
        self._source_id = 0

    async def setup(self) -> bool:
        """Verify RTSP bindings, media devices, and required GStreamer elements."""
        try:
            import gi

            gi.require_version("Gst", "1.0")
            gi.require_version("GstRtspServer", "1.0")

            from gi.repository import Gst, GstRtspServer, GLib
        except Exception as exc:
            self.logger.error(
                "GStreamer RTSP Python bindings are not available: %s",
                exc,
            )
            self.logger.error(
                "Install gir1.2-gst-rtsp-server-1.0 on the Sensor Node."
            )
            return False

        self._Gst = Gst
        self._GstRtspServer = GstRtspServer
        self._GLib = GLib

        self._Gst.init(None)

        required_elements = [
            "v4l2src",
            "videoconvert",
            "x264enc",
            "rtph264pay",
            "autoaudiosrc",
            "audioconvert",
            "audioresample",
            "avenc_aac",
            "aacparse",
            "rtpmp4gpay",
        ]

        if self.source_format == "MJPG":
            required_elements.append("jpegdec")

        for element in required_elements:
            if self._Gst.ElementFactory.find(element) is None:
                self.logger.error(
                    "Missing GStreamer element: %s",
                    element,
                )
                return False

        if not os.path.exists(self.device):
            self.logger.error(
                "Video device does not exist: %s",
                self.device,
            )
            return False

        return True

    def _pipeline_description(self) -> str:
        if self.source_format == "MJPG":
            video_source = (
                f"v4l2src device={self.device} ! "
                f"image/jpeg,width={self.width},height={self.height},"
                f"framerate={self.fps}/1 ! "
                "jpegdec ! "
            )
        else:
            video_source = (
                f"v4l2src device={self.device} ! "
                f"video/x-raw,format=YUY2,width={self.width},"
                f"height={self.height},framerate={self.fps}/1 ! "
            )

        return (
            "( "
            f"{video_source}"
            "videoconvert ! "
            "video/x-raw,format=I420 ! "
            "x264enc "
            "tune=zerolatency "
            "speed-preset=ultrafast "
            f"bitrate={self.bitrate_kbps} "
            f"key-int-max={self.fps} "
            "bframes=0 ! "
            "video/x-h264,profile=main ! "
            "rtph264pay "
            "name=pay0 "
            "pt=96 "
            "config-interval=1 "
            "autoaudiosrc ! "
            "audioconvert ! "
            "audioresample ! "
            "audio/x-raw,rate=48000,channels=2 ! "
            "avenc_aac bitrate=64000 ! "
            "aacparse ! "
            "audio/mpeg,mpegversion=4,stream-format=raw ! "
            "rtpmp4gpay "
            "name=pay1 "
            "pt=97 "
            ")"
        )

    async def _stop_server(self) -> None:
        """Stop the RTSP server and disconnect any active viewers."""
        if self._mounts is not None:
            try:
                self._mounts.remove_factory(
                    self.rtsp_path
                )
            except Exception:
                self.logger.exception(
                    "Failed to remove RTSP media factory."
                )

        if (
            self._server is not None
            and self._GstRtspServer is not None
        ):
            try:
                self._server.client_filter(
                    lambda server, client: (
                        self._GstRtspServer.RTSPFilterResult.REMOVE
                    )
                )
            except Exception:
                self.logger.exception(
                    "Failed to disconnect RTSP clients."
                )

        if (
            self._source_id
            and self._GLib is not None
        ):
            try:
                self._GLib.source_remove(
                    self._source_id
                )
            except Exception:
                pass

        if self._main_loop is not None:
            try:
                self._main_loop.quit()
            except Exception:
                self.logger.exception(
                    "Failed to stop RTSP GLib main loop."
                )

        if self._main_loop_task is not None:
            try:
                await asyncio.wait_for(
                    asyncio.shield(
                        self._main_loop_task
                    ),
                    timeout=2.0,
                )
            except asyncio.TimeoutError:
                self.logger.warning(
                    "Timed out waiting for RTSP GLib main loop to stop."
                )
            except Exception:
                self.logger.exception(
                    "RTSP GLib main loop exited with an error."
                )

        self._source_id = 0
        self._main_loop_task = None
        self._main_loop = None
        self._mounts = None
        self._factory = None
        self._server = None

    async def run(self) -> None:
        """Run the RTSP server until the operation is stopped."""
        if (
            self._GstRtspServer is None
            or self._GLib is None
        ):
            raise RuntimeError(
                "RTSP server dependencies were not initialized."
            )

        self._main_loop = self._GLib.MainLoop()

        self._server = self._GstRtspServer.RTSPServer()
        self._server.set_service(str(self.rtsp_port))

        self._factory = self._GstRtspServer.RTSPMediaFactory()
        self._factory.set_shared(True)
        self._factory.set_stop_on_disconnect(True)
        self._factory.set_launch(
            self._pipeline_description()
        )

        self._mounts = self._server.get_mount_points()
        self._mounts.add_factory(
            self.rtsp_path,
            self._factory,
        )

        self._source_id = self._server.attach(None)
        if not self._source_id:
            raise RuntimeError(
                f"Unable to start RTSP server on port {self.rtsp_port}."
            )

        self.logger.info(
            "Starting video RTSP stream: "
            f"device={self.device}, "
            f"format={self.source_format}, "
            f"size={self.width}x{self.height}, "
            f"fps={self.fps}, "
            f"bitrate={self.bitrate_kbps} kbps, "
            f"url=rtsp://<sensor-node-ip>:{self.rtsp_port}{self.rtsp_path}"
        )

        # Python 3.8 compatible replacement for asyncio.to_thread().
        loop = asyncio.get_running_loop()
        self._main_loop_task = loop.run_in_executor(
            None,
            self._main_loop.run,
        )

        # Give the GLib loop a moment to begin servicing RTSP before the
        # connection is advertised to TAK clients.
        await asyncio.sleep(0.1)

        # Advertise the stream through the existing TAK callback path.
        # Do not make TAK availability a requirement for local RTSP streaming.
        if self.node_uid:
            try:
                await self.tak_cot_callback(
                    {
                        "msg_type": "video",
                        "uid": f"FISSURE-VIDEO-{self.node_uid}",
                        "node_uid": self.node_uid,
                        "data": {
                            "protocol": "rtsp",
                            "port": self.rtsp_port,
                            "path": self.rtsp_path,
                        },
                    }
                )
                self.logger.info(
                    "Video RTSP stream advertisement submitted to TAK."
                )
            except Exception as exc:
                self.logger.warning(
                    "Unable to advertise video RTSP stream to TAK: %s",
                    exc,
                )

        try:
            while not self._stop:
                if self._main_loop_task.done():
                    exc = self._main_loop_task.exception()
                    if exc is not None:
                        raise exc
                    raise RuntimeError(
                        "RTSP GLib main loop exited unexpectedly."
                    )

                await asyncio.sleep(0.1)
        finally:
            await self._stop_server()

    async def teardown(self) -> None:
        await self._stop_server()


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test

    run_test(
        OperationMain,
        {
            "rtsp_port": 8554,
            "device": "/dev/video0",
            "source_format": "YUY2",
            "width": 640,
            "height": 480,
            "fps": 30,
            "bitrate_kbps": 750,
        },
        {},
    )
