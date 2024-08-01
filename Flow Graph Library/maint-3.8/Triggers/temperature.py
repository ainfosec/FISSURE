import sys
import time
import requests

def main():
    # Accept Command Line Arguments
    try:
        comparison = str(sys.argv[1])
        temperature = int(str(sys.argv[2]))
        city_name = str(sys.argv[3])
        state_code = str(sys.argv[4])
        country_code = str(sys.argv[5])
    except:
        print("Error accepting temperature arguments. Exiting trigger.")
        return -1
    
    current_temp = get_temperature(city_name, state_code, country_code)
    if current_temp == None:
        print("Invalid location")
        return -1
        
    if comparison == "<":
        while current_temp >= temperature:
            current_temp = get_temperature(city_name, state_code, country_code)
            time.sleep(10)
    elif comparison == ">":
        while current_temp <= temperature:
            current_temp = get_temperature(city_name, state_code, country_code)
            time.sleep(10)
    else:
        while current_temp != temperature:
            current_temp = get_temperature(city_name, state_code, country_code)
            time.sleep(10)
    return 0

def get_temperature(city_name, state_code=None, country_code=None):
    location = city_name
    if state_code:
        location += f",{state_code}"
    if country_code:
        location += f",{country_code}"

    url = f"http://wttr.in/{location}?format=%t"
    response = requests.get(url)
    
    if response.status_code == 200:
        temperature = int(response.text.strip().replace("°F",""))
        return temperature
    else:
        print(f"Error {response.status_code}: Could not retrieve data.")
        return None



if __name__ == "__main__":
    main()
