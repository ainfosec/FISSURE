import time
import sys
import signal


# Signal handler function
def handle_sigterm(signum, frame):
    print("Received SIGTERM signal. Cleaning up...")
    # Perform any cleanup here
    sys.exit(0)
    
def main():
    # Accept Command Line Arguments
    try:
        get_timer_seconds = float(sys.argv[1])
    except:
        print("Error accepting timer argument. Exiting trigger.")
        return -1
        
    # Register the signal handler for SIGTERM
    signal.signal(signal.SIGTERM, handle_sigterm)
        
    initial_time = time.time()

    while time.time() < initial_time + get_timer_seconds:
        #print("in the loop")
        time.sleep(.1)
        
    #print("out")
    #time.sleep(5)
    return 0

if __name__ == "__main__":
    main()
