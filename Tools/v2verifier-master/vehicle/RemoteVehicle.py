import subprocess
import time
from txrx import Utility, WavePacketBuilder


def send_payload_to_gnuradio(message_payload):
    loader = subprocess.Popen(("echo", "-n", "-e", message_payload), stdout=subprocess.PIPE)
    sender = subprocess.check_output(("nc", "-w0", "-u", "localhost", "52001"), stdin=loader.stdout)


class RemoteVehicle:

    def __init__(self, coordinate_file_path, vehicle_id):
        self.coordinates_file_path = coordinate_file_path
        self.vehicle_id = vehicle_id
        self.key_path = "keys/" + str(self.vehicle_id) + "/p256.key"

    # Send stream of payloads to GNURadio (wifi_tx.py)
    def start(self):

        with open(self.coordinates_file_path, "r") as coordinates_file:
            coordinate_list = coordinates_file.readlines()

        if len(coordinate_list) < 3:
            raise Exception("Your file must have at least 3 pairs of coordinates")

        for i in range(0, len(coordinate_list) - 2):

            heading = Utility.calculate_heading(coordinate_list[i], coordinate_list[i + 1])
            speed = Utility.calc_speed(coordinate_list[i], coordinate_list[i + 1])

            bsm_text = str(self.vehicle_id) + "," + coordinate_list[i].replace("\n", "") + "," + heading + "," + \
                str(round(speed, 2)) + "\n"
            bsm_payload = WavePacketBuilder.get_wsm_payload(bsm_text, self.key_path)
            bsm_payload = Utility.inject_time(bsm_payload)
            print("Sending message: ", bsm_text)
            send_payload_to_gnuradio(bsm_payload)

            time.sleep(0.1)
