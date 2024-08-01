import sys
import time

import subprocess
import os
import signal

def main():
    # Accept Command Line Arguments
    try:
        hardware = str(sys.argv[1])
        pci = str(sys.argv[2])
        frequency = str(float(sys.argv[3])*1e6)
    except:
        print("Error accepting cellular tower arguments. Exiting trigger.")
        return -1

    # Assemble the CellSearch Command
    cellsearch_directory = os.path.expanduser("~/Installed_by_FISSURE/LTE-Cell-Scanner/build/src/")
    if "RTL2832U" in hardware:
        command = [cellsearch_directory + "CellSearch", "--freq-start", frequency, "--freq-end", frequency]
    else:
        return -1
        
    # Loop the Command
    keyword = "cell ID: " + pci + "\n"
    match_found = False
    while match_found == False:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, universal_newlines=True)
   
        # Iterate over stdout to print the output in real-time
        for line in iter(process.stdout.readline, ''):
            print(line, end='')  # Print the line without adding additional newline

            # Check if the match_text is present in the output
            if keyword in line:
                process.terminate()
                match_found = True
                
        process.stdout.close()
        process.wait()
        
        if match_found == False:
            time.sleep(10)
        else:
            print("Match found in stdout. Exiting both programs.")
            
            
    return 0

    
if __name__ == "__main__":
    main()
