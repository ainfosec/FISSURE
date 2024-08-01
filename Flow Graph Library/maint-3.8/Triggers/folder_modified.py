import sys
import time
import os

def main():
    # Accept Command Line Arguments
    try:
        folder_modified = str(sys.argv[1])
    except:
        print("Error accepting folder modified argument. Exiting trigger.")
        return -1

    # Get the initial set of files in the folder
    initial_files = set(os.listdir(folder_modified))

    while True:
        # Wait for some time before checking again
        time.sleep(0.1)
        
        # Get the current set of files
        current_files = set(os.listdir(folder_modified))
        
        # Check for new files
        new_files = current_files - initial_files
        if new_files:
            break

    return 0

if __name__ == "__main__":
    main()
