import sys
import time
import requests

def main():
    # Accept Command Line Arguments
    try:
        wind_threshold = int(sys.argv[1])
        city_name = str(sys.argv[2])
        state_code = str(sys.argv[3])
        country_code = str(sys.argv[4])
    except:
        print("Error accepting wind arguments. Exiting trigger.")
        return -1
        
    # Check Wind Periodically
    while wind_threshold > get_wind(city_name, state_code, country_code):
        time.sleep(10)
        
    return 0

def get_wind(city_name, state_code=None, country_code=None):
    location = city_name
    if state_code:
        location += f",{state_code}"
    if country_code:
        location += f",{country_code}"

    url = f"http://wttr.in/{location}?format=%w"
    response = requests.get(url)
    
    if response.status_code == 200:
        wind = response.text.strip()
        wind = int(wind[1:].replace("mph",""))  # Remove arrow and mph
        return wind
    else:
        print(f"Error {response.status_code}: Could not retrieve data.")
        return None



if __name__ == "__main__":
    main()
