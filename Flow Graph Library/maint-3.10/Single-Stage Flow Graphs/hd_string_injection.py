import json
import os
import subprocess
import signal
import time
import sys

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    json_filepath = '/home/user/FISSURE/Flow Graph Library/Single-Stage Flow Graphs/Attack Files/Naughty Strings/blns.json'
    artist_or_title = 'title'
    frequency_MHz = 95.1
    timeout_seconds = 35
    gain = 70
    wav1_filepath = '/home/user/FISSURE/Flow Graph Library/Single-Stage Flow Graphs/Attack Files/sample.wav'
    wav2_filepath = '/home/user/FISSURE/Flow Graph Library/Single-Stage Flow Graphs/Attack Files/sample_mono.wav'
    run_with_sudo = 'False'
    notes = "Inject naughty strings into the artist or song title in HD Radio from a JSON file. Specify 'title' or 'artist' to direct the injection process."
    arg_names = ['json_filepath','artist_or_title','frequency_MHz','gain','timeout_seconds','wav1_filepath','wav2_filepath','run_with_sudo','notes']
    arg_values = [json_filepath, artist_or_title, frequency_MHz, gain, timeout_seconds, wav1_filepath, wav2_filepath, run_with_sudo, notes]
    return (arg_names,arg_values)

# Function to inject new string each time
def run_command_with_timeout(command, timeout):
    print("String Injection Starting...")
    process = subprocess.Popen(command)                 # start the process
    time.sleep(timeout)                                 # Wait for the specified timeout (in seconds)
    print("String Injection Completed!\n")
    process.send_signal(signal.SIGTERM)
    process.terminate()
    process.kill()
    process.wait()

if __name__ == "__main__":
    
    # Default Values
    get_filepath = ''
    get_artist_or_title = ''
    get_frequency = 1000000
    get_gain = 70
    timeout_seconds = 35 


     # Accept Command Line Arguments 
    try:
        get_filepath = sys.argv[1]
        get_artist_or_title = sys.argv[2]
        get_frequency = float(sys.argv[3]) * get_frequency
        get_gain = sys.argv[4]
        get_timeout_seconds = float(sys.argv[5]) 
        get_wav1_filepath = sys.argv[6]
        get_wav2_filepath = sys.argv[7]
    except:
        pass

    # Set script path to execute
    script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'hd_tx_usrp_copy.py')         

    if len(get_filepath) > 0:
        with open(get_filepath) as json_file:  
            blns = json.load(json_file)
            for string in blns:                                                            # will loop through strings
                print("String: ", string)
                
                if len(string) == 0:
                    string='""'
                    
                arguments = ['--' + get_artist_or_title + '=' + string, '--frequency=' + str(get_frequency), '--gain=' + str(get_gain), '--wav1-filepath=' + get_wav1_filepath, '--wav2-filepath=' + get_wav2_filepath]
                command = ['python3', script_path] + arguments                                                                
                run_command_with_timeout(command, get_timeout_seconds)
                time.sleep(5)
        print("All strings have been injected!")
    else:
        print("Invalid File Selected!")
