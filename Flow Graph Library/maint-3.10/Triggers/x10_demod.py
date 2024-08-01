import sys
import time

import subprocess
import os
import signal

def main():
    # Accept Command Line Arguments
    try:
        hardware = str(sys.argv[1])
        matching_text = str(sys.argv[2])
        #matching_text = "Bits: 01100000100111110000000011111111"
    except:
        print("Error accepting X10 demod arguments. Exiting trigger.")
        return -1

    # Choose the Flow Graph
    if "USRP B2x0" in hardware:
        filepath = os.path.dirname(os.path.realpath(__file__)) + "/X10_OOK_USRPB2x0_Demod.py"
    else:
        return -1
        
    # Start the Flow Graph
    process = subprocess.Popen(["python3", filepath], stdout=subprocess.PIPE, universal_newlines=True)
   
    # Iterate over stdout to print the output in real-time
    try:
        for line in iter(process.stdout.readline, ''):
            print(line, end='')  # Print the line without adding additional newline

            # Check if the match_text is present in the output
            if matching_text in line:
                print("Match found in stdout. Exiting both programs.")
                process.terminate()
                return 0
        process.stdout.close()
        process.wait()
    finally:
        #process.terminate()
        # os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        # process.wait()
        #os.system("pkill -f " + '"' + filepath +'"')
        #print("DIED")
        pass

    
if __name__ == "__main__":
    main()
