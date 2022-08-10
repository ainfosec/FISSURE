from txrx.Receiver import Receiver
import socket


class CV2XReceiver(Receiver):
    
    def __init__(self, with_gui=False, cohda=False):
        super().__init__(gui_enabled=with_gui)
        self.cohda = cohda

    def listen_for_wsms(self, gui_socket, gui_socket_lock):

        print("Listening on port 4444 for C-V2X WSMs")

        if self.cohda:
            # use IPv6 on the Ethernet interface to get messages from Cohda MK6c OBU
            listener = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            listener.bind(("fe80::ca89:f53:4108:d142%enp3s0", 4444, 0, 2))
        else:
            # otherwise presume SDR and use IPv4 on localhost to get messages from srsLTE
            listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            listener.bind(('localhost', 4444))
        while True:
            wsm = listener.recv(1024)
            if self.cohda:
                self.process_packet(wsm.hex(), gui_socket, gui_socket_lock)
            else:
                self.process_packet(wsm.hex()[46:], gui_socket, gui_socket_lock)

    def process_packet(self, payload, s, lock):
        # print("Received BSM:", payload)
        self.parse_wsm(payload)

    def parse_wsm(self, wsm):
        # print("Input to parse_wsm:", wsm)

        # This is a temporary workaround to avoid trying to process control frames (which
        # are much shorter than data frames) as if they are BSMs.
        if len(wsm) < 150:
            return

        if self.cohda:
            self.parse_cohda_spdu(wsm)
        else:
            self.parse_16092_spdu(wsm)


    def parse_16092_spdu(self, wsm):
        # ignore the 5 WSMP header bytes
        ieee1609dot2data = wsm
        # print(ieee1609dot2data)

        bsm_length = int(ieee1609dot2data[12:14], 16)

        # extract SAE J2735 BSM
        bsm = ieee1609dot2data[14:(14 + (2 * bsm_length))]

        self.parse_sae_j2735_bsm(bsm)

        # signature is the last 64 bytes of the SPDU
        signature = ieee1609dot2data[len(ieee1609dot2data) - 65:]
        r = signature[:32]
        s = signature[32:]

    def parse_cohda_spdu(self, wsm):

        # ignore the 5 WSMP header bytes
        ieee1609dot2data = wsm
        # print(ieee1609dot2data)

        bsm_length = int(ieee1609dot2data[12:14], 16)

        # extract SAE J2735 BSM
        bsm = ieee1609dot2data[14:(14 + (2 * bsm_length))]

        self.parse_sae_j2735_bsm(bsm)

        # signature is the last 64 bytes of the SPDU
        signature = ieee1609dot2data[len(ieee1609dot2data) - 65:]
        r = signature[:32]
        s = signature[32:]

    def parse_sae_j2735_bsm(self, bsm):
        data = {}
        
        data["sender_id"] = bsm[9:16]
        data["latitude"] = bsm[20:28]
        data["longitude"] = bsm[28:36]
        data["elevation"] = bsm[36:40]
        data["speed"] = bsm[49:52]
        data["heading"] = bsm[52:56]
        
        self.report_bsm(data)



    # 3/3/21 - verified that the offsets in this portion are correct (via Wireshark compare)
    def report_bsm(self, data_dict):
        print("BSM from", data_dict["sender_id"], ": vehicle at (" +
              data_dict["latitude"] + "," +
              data_dict["longitude"] + "," +
              data_dict["elevation"] +
              ")" +
              " is moving on bearing " +
              str(data_dict["heading"]) +
              " at " +
              str(data_dict["speed"]) +
              " m/s")
