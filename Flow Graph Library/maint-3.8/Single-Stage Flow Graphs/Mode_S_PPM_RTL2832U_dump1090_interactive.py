import os, sys, webbrowser, subprocess, time

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    frequency = '1090000000'
    serial = '0'
    run_with_sudo = 'False'
    notes = 'Runs dump1090 in interactive mode. Go to: http://127.0.0.1:8081'

    arg_names = ['frequency','serial','run_with_sudo','notes']
    arg_values = [frequency, serial, run_with_sudo, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    frequency = '1090000000'

    # Accept Command Line Arguments
    try:
        frequency = sys.argv[1]
        serial = sys.argv[2]
    except:
        pass

#################################################
    
    # Run Dump1090
    home = os.path.expanduser("~")
    dump1090_directory = home + "/Installed_by_FISSURE/dump1090/"
    print "\n\nOpening http://127.0.0.1:8081\n\n"
    time.sleep(2)
    #proc=subprocess.Popen("gnome-terminal -x ./dump1090 --interactive --net", cwd=dump1090_directory, shell=True)
    #proc=subprocess.call("./dump1090 --interactive --net --net-http-port 8081", cwd=dump1090_directory, shell=True)    
    webbrowser.open("http://127.0.0.1:8081")
    os.system("cd ~/Installed_by_FISSURE/dump1090 && ./dump1090 --freq " + frequency + " --device-index " + serial + " --interactive --net --net-http-port 8081")

