import subprocess, os


#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    fifo_path = "/tmp/fifo1"
    sample_rate  = "4000000"
    notes = 'Runs ble_dump.py and creates a pipe to Wireshark for dumping BLE packets.'

    arg_names = ['fifo_path','sample_rate','notes']
    arg_values = [fifo_path, sample_rate, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    get_fifo_path = "/tmp/fifo1"
    get_sample_rate  = "4000000"
    
    # Accept Command Line Arguments
    try:
        get_fifo_path = sys.argv[1]
        get_sample_rate = sys.argv[2]
    except:
        pass

#################################################
        
    # Make FIFO for Wireshark
    try:
        os.system("mkfifo /tmp/fifo1")
    except:
        pass        
    
    # Open Wireshark
    #proc=subprocess.Popen("gnome-terminal -x wireshark -S -k -i " + get_fifo_path, shell=True)
    proc=subprocess.call("wireshark -S -k -i " + get_fifo_path + " &", shell=True)
    
    # Run ble_dump.py
    ble_dump_directory = os.path.dirname(os.path.realpath(__file__))
    ble_dump_directory = ble_dump_directory.rsplit("Flow Graph Library/")[0] + "Tools/ble_dump-master/"
    command_text = "sudo python " + ble_dump_directory + "ble_dump.py -s " + str(get_sample_rate) + " -o " + str(get_fifo_path)
    #proc=subprocess.Popen("gnome-terminal -x " + command_text, shell=True)    
    proc=subprocess.call(command_text, shell=True)    
    
