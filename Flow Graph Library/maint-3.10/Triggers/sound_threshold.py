import time
import sys

import sounddevice as sd
import numpy as np

import threading

def detect_sound_above_threshold(indata, frames, time, status, threshold, stop_event, warmup_done):
    """
    Callback function to process audio blocks.
    """
    if not warmup_done.is_set():
        return  # Skip processing during the warm-up period
    
    # Calculate the amplitude of the audio block
    amplitude = np.linalg.norm(indata) / np.sqrt(len(indata))
    
    print(amplitude)
    
    # Check if the amplitude is above the threshold
    if amplitude > threshold:
        print("Sound detected above threshold!")
        stop_event.set()  # Set the stop event to signal the main loop to exit

def main():
    try:
        get_threshold = float(sys.argv[1])   # 0.2   # Define the threshold above which the sound is considered loud enough
        get_duration = float(sys.argv[2])    # 0.1   # Define the duration to listen to each audio snippet in seconds
        get_sample_rate = float(sys.argv[3]) # 44100 # Define the sampling rate in Hz
    except:
        print("Error accepting timer argument. Exiting trigger.")
        return -1

    print("Listening for sound...")

    # Create threading events to signal when to stop and when warm-up is done
    stop_event = threading.Event()
    warmup_done = threading.Event()

    try:
        # Use a lambda to pass the threshold and events to the callback
        callback = lambda indata, frames, time, status: detect_sound_above_threshold(indata, frames, time, status, get_threshold, stop_event, warmup_done)
        
        with sd.InputStream(callback=callback, channels=1, samplerate=get_sample_rate, blocksize=int(get_sample_rate * get_duration)):
            # Warm-up period to stabilize the audio stream
            sd.sleep(2000)  # 2 seconds warm-up
            warmup_done.set()  # Signal that the warm-up period is done
            while not stop_event.is_set():
                sd.sleep(int(get_duration * 1000))  # Sleep to allow callback to process
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)  # Exit with a non-zero status on error
    print("Exiting program.")
    sys.exit(0)  # Exit the program with code 0

if __name__ == "__main__":
    main()
