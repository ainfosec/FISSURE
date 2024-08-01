import sys
import time
import requests

def main():
    # Accept Command Line Arguments
    try:
        conditions = str(sys.argv[1])
        city_name = str(sys.argv[2])
        state_code = str(sys.argv[3])
        country_code = str(sys.argv[4])
    except:
        print("Error accepting weather arguments. Exiting trigger.")
        return -1
    
    # Build Keywords
    keywords = []    
    if conditions == "Rain":
        keywords.append("rain")
        keywords.append("drizzle")
    elif conditions == "Snow/Sleet":
        keywords.append("snow")
        keywords.append("sleet")
        keywords.append("blizzard")
        keywords.append("freezing")
        keywords.append("ice")
    elif conditions == "Clear":
        keywords.append("clear")
    elif conditions == "Cloudy/Fog":
        keywords.append("cloudy")
        keywords.append("fog")
        keywords.append("overcast")
        keywords.append("mist")
        keywords.append("thunder")
    else:
        print("Invalid weather condition.")
        return -1
        
    # Check Conditions Periodically
    while True:
        get_conditions = get_weather(city_name, state_code, country_code)
        for n in range(0,len(keywords)):
            if keywords[n] in get_conditions:
                return 0            
        time.sleep(10)

def get_weather(city_name, state_code=None, country_code=None):
    location = city_name
    if state_code:
        location += f",{state_code}"
    if country_code:
        location += f",{country_code}"

    url = f"http://wttr.in/{location}?format=%C"
    response = requests.get(url)
    
    if response.status_code == 200:
        conditions = response.text.strip().lower()
        return conditions
    else:
        print(f"Error {response.status_code}: Could not retrieve data.")
        return None



if __name__ == "__main__":
    main()
