import sys
import time

import subprocess
import os
import signal

def main():
    # Accept Command Line Arguments
    try:
        hardware = str(sys.argv[1])
        sample_rate = str(float(sys.argv[2])*1e6)
        frequency = str(sys.argv[3])
        threshold = str(sys.argv[4])
    except:
        print("Error accepting power threshold arguments. Exiting trigger.")
        return -1

    # Choose the Flow Graph
    if "USRP B2x0" in hardware:
        filepath = os.path.dirname(os.path.realpath(__file__)) + "/Power_Threshold_USRPB2x0.py"
    else:
        return -1
        
    # Look for Text in stdout
    keyword = "Signal Found"
    
    # Start the Flow Graph
    process = subprocess.Popen(["python3", filepath, "--rx-freq-default=" + frequency, "--sample-rate-default=" + sample_rate, "--threshold-default=" + threshold], stdout=subprocess.PIPE, universal_newlines=True)
   
    # Iterate over stdout to print the output in real-time
    for line in iter(process.stdout.readline, ''):
        print(line, end='')  # Print the line without adding additional newline

        # Check if the match_text is present in the output
        if keyword in line:
            print("Match found in stdout. Exiting both programs.")
            process.terminate()
            return 0
    process.stdout.close()
    process.wait()
    
if __name__ == "__main__":
    main()
