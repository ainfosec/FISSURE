import time
import sys

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    sleep_duration_seconds = 10
    run_with_sudo = False
    notes = 'Sleeps for a duration.'
    arg_names = ['sleep_duration_seconds', 'run_with_sudo', 'notes']
    arg_values = [sleep_duration_seconds, run_with_sudo, notes]

    return (arg_names, arg_values)


if __name__ == "__main__":

    # Default Values
    get_sleep_duration_seconds = 10.0

    # Accept Command Line Arguments
    try:
        get_sleep_duration_seconds = float(sys.argv[1])
    except:
        pass

#################################################

    # Sleep
    time.sleep(get_sleep_duration_seconds)
