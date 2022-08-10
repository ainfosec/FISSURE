from txrx import Utility
import json
import time


def send_to_gui(msg, s, lock):

    bsm = msg.split(",")

    decoded_data = {'id': bsm[0],
                    'x': bsm[1],
                    'y': bsm[2],
                    'heading': bsm[3],
                    'speed': bsm[4],
                    'sig': True,
                    'elapsed': 0,
                    'recent': True,
                    'receiver': True,
                    'reputation': 1000}

    vehicle_data_json = json.dumps(decoded_data)

    with lock:
        s.send(vehicle_data_json.encode())


class LocalVehicle:
    
    def __init__(self, local_trace_file):
        self.trace_file = local_trace_file
        
    def start(self, s, lock):

        with open(self.trace_file, "r") as coordinates_file:
            coordinates = coordinates_file.readlines()

        if len(coordinates) < 3:
            raise Exception("Coordinates file must have more than three entries!")

        for i in range(0, len(coordinates) - 2):
            bsm = "99," + coordinates[i].replace("\n", "") + "," + \
                  Utility.calculate_heading(coordinates[i], coordinates[i + 1]) + "," + \
                  str(Utility.calc_speed(coordinates[i], coordinates[i + 1]))
            send_to_gui(bsm, s, lock)
            time.sleep(0.1)
