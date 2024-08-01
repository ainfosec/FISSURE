import sys
import time

import subprocess
import os

def main():
    # Accept Command Line Arguments
    try:
        hardware = str(sys.argv[1])
        icao = str(sys.argv[2]).lower()
    except:
        print("Error accepting plane spotting arguments. Exiting trigger.")
        return -1

    # Choose the Flow Graph
    dump1090_directory = os.path.expanduser("~/Installed_by_FISSURE/dump1090/")
    if "RTL2832U" in hardware:
        #command = [dump1090_directory + "dump1090","--onlyaddr"]  # Doesn't print as well to stdout?
        command = [dump1090_directory + "dump1090"]
    else:
        return -1

    # Start the Flow Graph
    process = subprocess.Popen(command, stdout=subprocess.PIPE, universal_newlines=True)
   
    try:
        # Iterate over stdout to print the output in real-time
        for line in iter(process.stdout.readline, ''):
            print(line, end='')  # Print the line without adding additional newline

            # Check if the match_text is present in the output
            if icao in line:
                print("Match found in stdout. Exiting both programs.")
                process.terminate()
                return 0
        process.stdout.close()
        process.wait()
    finally:
        process.terminate()
        process.wait()

    
if __name__ == "__main__":
    main()
