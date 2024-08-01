import sys
import time

import gpsd

def main():
    # Accept Command Line Arguments
    try:
        latitude_threshold = float(sys.argv[1]) if sys.argv[1] != "None" else None  # 42.1234567
        longitude_threshold = float(sys.argv[2]) if sys.argv[2] != "None" else None  # -76.123456
        direction = str(sys.argv[3])  # ">" or "<"
        
    except:
        print("Error accepting GPS line arguments. Exiting trigger.")
        return -1
    
    # Connect to the local gpsd
    gpsd.connect()
    
    while True:
        current_pos = get_current_position()
        if current_pos:
            print(f"Current position: {current_pos}")
            if check_crossing(current_pos, latitude_threshold, longitude_threshold, direction):
                print("Threshold crossed. Exiting.")
                break
        else:
            print("Waiting for GPS signal...")

        # Sleep for a while before the next check
        time.sleep(5)
        
def get_current_position():
    try:
        # Get GPS position
        packet = gpsd.get_current()
        if packet.mode >= 2:
            latitude = packet.lat
            longitude = packet.lon
            return (latitude, longitude)
        else:
            print("No GPS fix")
            return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def check_crossing(current_pos, lat_threshold=None, lon_threshold=None, direction=">"):
    """
    Check if the current position has crossed the specified latitude or longitude threshold.
    """
    lat_crossed = lon_crossed = False

    if lat_threshold is not None:
        if direction == ">":
            lat_crossed = current_pos[0] > lat_threshold
        elif direction == "<":
            lat_crossed = current_pos[0] < lat_threshold
        print(f"Latitude check: {current_pos[0]} {direction} {lat_threshold}: {lat_crossed}")

    if lon_threshold is not None:
        if direction == ">":
            lon_crossed = current_pos[1] > lon_threshold
        elif direction == "<":
            lon_crossed = current_pos[1] < lon_threshold
        print(f"Longitude check: {current_pos[1]} {direction} {lon_threshold}: {lon_crossed}")

    return lat_crossed or lon_crossed
    
if __name__ == "__main__":
    main()
