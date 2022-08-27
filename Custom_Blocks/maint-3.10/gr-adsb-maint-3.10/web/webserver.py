#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2016-2019 Matt Hostetter.
#
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
#

from gevent import monkey
monkey.patch_all()

import time
from flask import Flask, request
from flask_socketio import SocketIO
from threading import Thread
import zmq.green as zmq

import pmt

HTTP_ADDRESS ="127.0.0.1"
HTTP_PORT = 5000

ZMQ_ADDRESS = "127.0.0.1"
ZMQ_PORT = 5001

app = Flask(__name__, static_url_path="")
app.config["SECRET_KEY"] = "secret!"
socketio = SocketIO(app)


def zmq_thread():
    # Establish ZMQ context and socket
    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.setsockopt(zmq.SUBSCRIBE, b"")
    socket.connect("tcp://{:s}:{:d}".format(ZMQ_ADDRESS, ZMQ_PORT))

    while True:
        # Receive decoded ADS-B message from the decoder over ZMQ
        pdu_bin = socket.recv()
        pdu = pmt.deserialize_str(pdu_bin)
        plane = pmt.to_python(pmt.car(pdu))

        socketio.emit("updatePlane", plane)


@app.route("/")
def index():
    return app.send_static_file("index.html")


@socketio.on("connect")
def connect():
    print("Client connected", request.sid)


@socketio.on("disconnect")
def disconnect():
    print("Client disconnected", request.sid)


if __name__ == "__main__":
    thread = Thread(target=zmq_thread)
    thread.daemon = True
    thread.start()

    socketio.run(app, host=HTTP_ADDRESS, port=HTTP_PORT, debug=True, use_reloader=False)
