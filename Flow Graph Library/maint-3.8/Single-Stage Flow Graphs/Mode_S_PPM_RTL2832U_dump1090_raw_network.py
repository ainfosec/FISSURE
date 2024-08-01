import os, sys

#################################################
############ Default FISSURE Header ############
#################################################
def getArguments():
    ip_address = '127.0.0.1'
    port = '55555'
    serial = '0'
    frequency = '1090000000'
    run_with_sudo = 'False'
    notes = 'Executes the "./dump1090 --raw | nc 127.0.0.1 55555" command to transfer ASCII data (*8dc051daf82300020049b8c711c4) over a network.'
    arg_names = ['ip_address','port','serial','frequency','run_with_sudo','notes']
    arg_values = [ip_address, port, serial, frequency, run_with_sudo, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    ip_address = '127.0.0.1'
    port = '55555'
    serial = '0'
    frequency = '1090000000'

    # Accept Command Line Arguments
    try:
        ip_address = sys.argv[1]
        port = sys.argv[2]
        serial = sys.argv[3]
        frequency = sys.argv[4]
    except:
        pass

#################################################

    # Run Dump1090
    os.system('~/Installed_by_FISSURE/dump1090/dump1090 --device-index ' + serial + ' --freq ' + frequency + ' --raw | nc ' + ip_address + ' ' + port)
