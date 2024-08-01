import sys
import time
import os

def main():
    # Accept Command Line Arguments
    try:
        file_modified = str(sys.argv[1])
    except:
        print("Error accepting file modified argument. Exiting trigger.")
        return -1

    initial_mod_time = os.path.getmtime(file_modified)

    while True:
        new_mod_time = os.path.getmtime(file_modified)
        if new_mod_time != initial_mod_time:
            break
        time.sleep(.1)

    return 0

if __name__ == "__main__":
    main()
