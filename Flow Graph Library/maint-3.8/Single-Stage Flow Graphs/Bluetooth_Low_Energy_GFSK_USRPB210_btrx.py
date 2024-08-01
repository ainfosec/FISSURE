import subprocess

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    rx_frequency = "2402M"
    sample_rate  = "4M"
    gain = 70
    notes = 'Executes the btrx command for monitoring Bluetooth at a specified frequency, gain, and sample rate via the USRP B210.'

    arg_names = ['rx_frequency','sample_rate','gain','notes']
    arg_values = [rx_frequency, sample_rate, gain, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    get_rx_frequency = "2402M"
    get_sample_rate  = "4M"
    get_gain = 70
    
    # Accept Command Line Arguments
    try:
        get_rx_frequency = sys.argv[1]
        get_sample_rate  = sys.argv[2]
        get_gain  = sys.argv[3]
    except:
        pass

#################################################
        
    # Issue Command
    command_text = "btrx -f " + str(get_rx_frequency) + " -r " + str(get_sample_rate) + " -g " + str(get_gain) + " -a b210" 
    proc=subprocess.call(command_text, shell=True)
