import os, sys

#################################################
############ Default FISSURE Header ############
#################################################
def getArguments():
    sample_rate = '2083334'
    frequency = '978000000'
    gain = '48'
    serial = '0'
    run_with_sudo = 'False'
    notes = 'Executes the "rtl_sdr -d 0 -f 978000000 -s 2083334 -g 48 - | ./dump978 | ./uat2text" command to decode 978 MHz UAT messages into a readable format.'
    arg_names = ['sample_rate','frequency','gain','serial','run_with_sudo','notes']
    arg_values = [sample_rate, frequency, gain, serial, run_with_sudo, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    sample_rate = '2083334'
    frequency = '978000000'
    gain = '48'
    serial = '0'

    # Accept Command Line Arguments
    try:
        sample_rate = sys.argv[1]
        frequency = sys.argv[2]
        gain = sys.argv[3]
        serial = sys.argv[4]
    except:
        pass

#################################################

    # Run dump978 with uat2text
    os.system('cd ~/Installed_by_FISSURE/dump978 && rtl_sdr -d ' + serial + ' -f ' + frequency + ' -s ' + sample_rate + ' -g ' + gain + ' - | ./dump978 | ./uat2text')
