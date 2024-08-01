import sys
import time

import gpsd
from geopy.distance import geodesic


def main():
    # Accept Command Line Arguments
    try:
        target_lattitude = float(sys.argv[1])  # 42.1234567
        target_longitude = float(sys.argv[2])  # -76.123456
        max_distance = float(sys.argv[3])  # meters
        
    except:
        print("Error accepting GPS point arguments. Exiting trigger.")
        return -1
            
    target_pos = (target_lattitude, target_longitude)
    
    # Connect to the local gpsd
    gpsd.connect()
    
    while True:
        current_pos = get_current_position()
        if current_pos:
            print(f"Current position: {current_pos}")
            if is_within_distance(current_pos, target_pos, max_distance):
                print("Target reached. Exiting.")
                break
        else:
            print("Waiting for GPS signal...")

        # Sleep for a while before the next check
        time.sleep(5)        
        
def get_current_position():
    try:
        # Get GPS position
        packet = gpsd.get_current()
        latitude = packet.lat
        longitude = packet.lon
        return (latitude, longitude)
    except (KeyError, AttributeError):
        return None

def is_within_distance(current_pos, target_pos, max_distance):
    """
    Check if current_pos is within max_distance (in meters) from target_pos
    """
    distance = geodesic(current_pos, target_pos).meters
    print("Current distance from point: " + str(distance)) 
    return distance <= max_distance
    
if __name__ == "__main__":
    main()
