import subprocess

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    rx_frequency = "2402M"
    sample_rate  = "4M"
    notes = 'Executes the btrx command for monitoring Bluetooth at a specified frequency and sample rate via the HackRF.'

    arg_names = ['rx_frequency','sample_rate','notes']
    arg_values = [rx_frequency, sample_rate,notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    get_rx_frequency = "2402M"
    get_sample_rate  = "4M"
    
    # Accept Command Line Arguments
    try:
        get_rx_frequency = sys.argv[1]
        get_sample_rate  = sys.argv[2]
    except:
        pass

#################################################
        
    # Issue Command
    command_text = "btrx -f " + str(get_rx_frequency) + " -r " + str(get_sample_rate) + " -a hackrf"
    proc=subprocess.call(command_text, shell=True)
