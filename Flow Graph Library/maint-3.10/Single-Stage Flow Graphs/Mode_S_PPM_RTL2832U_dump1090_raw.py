import os, sys

#################################################
############ Default FISSURE Header ############
#################################################
def getArguments():
    ascii_output_filepath = '/home/laptop1/FISSURE/Sensor Nodes/Recordings/dump1090_ascii.txt'
    serial = '0'
    frequency = '1090000000'
    run_with_sudo = 'False'
    notes = 'Executes the "./dump1090 --raw > ascii_file.txt" command to save ASCII data (*8dc051daf82300020049b8c711c4) to a file.'
    arg_names = ['ascii_output_filepath','serial','frequency','run_with_sudo','notes']
    arg_values = [ascii_output_filepath, serial, frequency, run_with_sudo, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    ascii_output_filepath = '/home/laptop1/FISSURE/Sensor Nodes/Recordings/dump1090_ascii.txt'
    serial = '0'
    frequency = '1090000000'

    # Accept Command Line Arguments
    try:
        ascii_output_filepath = sys.argv[1]
        serial = sys.argv[2]
        frequency = sys.argv[3]
    except:
        pass

#################################################

    # Run Dump1090
    os.system('~/Installed_by_FISSURE/dump1090/dump1090 --device-index ' + serial + ' --freq ' + frequency + ' --raw > "' + ascii_output_filepath + '"')
