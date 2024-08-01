import time
from dateutil import parser
import sys


def main():
    # Accept Command Line Arguments
    try:
        trigger_time = sys.argv[1]
        trigger_time = parser.parse(trigger_time).timestamp()
        #print(trigger_time)
    except:
        print("Error accepting trigger time argument. Exiting trigger.")
        return -1

    while time.time() < trigger_time:
        #print("in the loop")
        time.sleep(.1)
        
    #print("out")
    #time.sleep(5)
    return 0

if __name__ == "__main__":
    main()
