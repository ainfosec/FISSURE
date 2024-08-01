import sys
import time
import requests
from datetime import datetime

def main():
    # Accept Command Line Arguments
    try:
        sunrise_sunset = str(sys.argv[1])
        city_name = str(sys.argv[2])
        state_code = str(sys.argv[3])
        country_code = str(sys.argv[4])
    except:
        print("Error accepting sunrise/sunset arguments. Exiting trigger.")
        return -1
        
    # Retrieve Sunrise/Sunset Time
    sunrise_sunset_time = get_sunrise_sunset(sunrise_sunset, city_name, state_code, country_code)  # "20:41:14"
    sunrise_sunset_time = "14:29:14"
    compare_hours, compare_minutes, _ = sunrise_sunset_time.split(':')
    
    # Check Current Time Periodically
    while True:
        current_time = datetime.now()
        formatted_time = current_time.strftime("%H:%M:%S")
        current_hours, current_minutes, _ = formatted_time.split(':')
        
        # Compare Hours and Minutes
        if current_hours == compare_hours and current_minutes == compare_minutes:
            break

        time.sleep(10)
        
    return 0

def get_sunrise_sunset(sunrise_sunset, city_name, state_code=None, country_code=None):
    location = city_name
    if state_code:
        location += f",{state_code}"
    if country_code:
        location += f",{country_code}"

    if sunrise_sunset == "Sunrise":
        url = f"http://wttr.in/{location}?format=%S"
    else:
        url = f"http://wttr.in/{location}?format=%s"
    response = requests.get(url)
    
    if response.status_code == 200:
        sunrise_sunset_time = response.text.strip()
        return sunrise_sunset_time
    else:
        print(f"Error {response.status_code}: Could not retrieve data.")
        return None



if __name__ == "__main__":
    main()
