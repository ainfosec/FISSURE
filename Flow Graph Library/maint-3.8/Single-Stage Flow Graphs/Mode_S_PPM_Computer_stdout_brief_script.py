import os, sys

#################################################
############ Default FISSURE Header ############
#################################################
def getArguments():
    flow_graph_filepath = '/home/user/FISSURE/Flow Graph Library/Single-Stage Flow Graphs/Mode_S_PPM_Computer_stdout_brief.py'
    samp_rate = '2e6'
    iq_filepath = ''
    threshold = '0.01'
    run_with_sudo = 'False'
    notes = "Prints formatted decoded ADSB data (gr-adsb) originating from an IQ file to stdout with the brief option selected."
    arg_names = ['flow_graph_filepath','samp_rate','iq_filepath','threshold','run_with_sudo','notes']
    arg_values = [flow_graph_filepath, samp_rate, iq_filepath, threshold, run_with_sudo, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    flow_graph_filepath = ''
    samp_rate = '2e6'
    iq_filepath = ''
    threshold = '0.01'

    # Accept Command Line Arguments
    try:
        flow_graph_filepath = sys.argv[1]
        samp_rate = sys.argv[2]
        iq_filepath = sys.argv[3]
        threshold = sys.argv[4]
    except:
        pass

#################################################

    # Run the Flow Graph
    os.system('python3 "' + flow_graph_filepath + '" --samp-rate=' + samp_rate + ' --filepath="' + iq_filepath + '" --threshold=' + threshold)
