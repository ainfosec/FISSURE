from fastecdsa import ecdsa
from datetime import datetime


class Verifier:

    """
    Wrapper function for fastecdsa.ecdsa.verify()
    See library documentation for that function, inputs are identical.
    """
    def verify_signature(self, r, s, message, public_key):
        return ecdsa.verify((r, s), message, public_key)
    
    # Returns true if less than 1s elapsed between message transmission and reception
    def verify_time(self, timestamp):
        elapsed = self.calculate_elapsed_time(timestamp)
        return elapsed, elapsed < 300
    
    # calculate the number of elapsed milliseconds since the message was transmitted
    def calculate_elapsed_time(self, time_in_milliseconds):
        unpadded_time_in_milliseconds = ""
        for i in range(0, len(time_in_milliseconds)):
            if time_in_milliseconds[i] != "0":
                unpadded_time_in_milliseconds = time_in_milliseconds[i:]
                break
        unpadded_time_in_milliseconds = int(unpadded_time_in_milliseconds, 16)
        origin = datetime(2004, 1, 1, 0, 0, 0, 0)
        now = (datetime.now() - origin).total_seconds() * 1000
        return now - unpadded_time_in_milliseconds
