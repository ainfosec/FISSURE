import os, sys, webbrowser,subprocess, time

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    Empty = "Empty"
    notes = 'Runs dump1090 in interactive mode. Go to: http://127.0.0.1:8080'

    arg_names = ["Empty",'notes']
    arg_values = [Empty, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    Empty = "Empty"

    # Accept Command Line Arguments
    try:
        Empty = sys.argv[1]
    except:
        pass

#################################################
    
    # Run Dump1090
    home = os.path.expanduser("~")
    dump1090_directory = home + "/Installed_by_FISSURE/dump1090/"
    print "\n\nGo to: http://127.0.0.1:8080\n\n"
    time.sleep(3)
    #proc=subprocess.Popen("gnome-terminal -x ./dump1090 --interactive --net", cwd=dump1090_directory, shell=True)
    proc=subprocess.call("./dump1090 --interactive --net", cwd=dump1090_directory, shell=True)
    #webbrowser.open("http://127.0.0.1:8080")

