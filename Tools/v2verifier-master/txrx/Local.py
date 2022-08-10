import os
import yaml
from threading import Lock, Thread
from socket import socket
from txrx.Receiver import Receiver
from cv2x.c_v2x_receiver import CV2XReceiver
from vehicle.LocalVehicle import LocalVehicle
from gui.GUI import GUI
import tkinter as tk


def run_local(with_gui=False, tech="dsrc", cohda=False):

    with open("init.yml", "r") as confFile:
        config = yaml.load(confFile, Loader=yaml.FullLoader)

        if os.geteuid() != 0:
            print("Error - you must be root! Try running with sudo")
            exit(1)

        if with_gui:
            root = tk.Tk()
            gui = GUI(root)
            gui.run_gui_receiver()
            print("GUI Initialized...")

            s2 = socket()
            s2.connect(('127.0.0.1', 6666))

            lock = Lock()

            if tech == "cv2x":
                if cohda:
                    receiver = CV2XReceiver(with_gui=True, cohda=True)
                else:
                    receiver = CV2XReceiver(with_gui=True)
            else:
                receiver = Receiver(gui_enabled=True)

            listener = Thread(target=receiver.run_receiver, args=(s2, lock,))
            listener.start()
            print("Listener running...")

            lv = LocalVehicle(config["localConfig"]["tracefile"])

            local = Thread(target=lv.start, args=(s2, lock,))
            local.start()

            root.mainloop()

        else:
            if tech == "cv2x":
                if cohda:
                    receiver = CV2XReceiver(with_gui=False, cohda=True)
                else:
                    receiver = CV2XReceiver(with_gui=False)
            else:
                receiver = Receiver(gui_enabled=False)

            listener = Thread(target=receiver.run_receiver)
            listener.start()
            print("Listener running...")
