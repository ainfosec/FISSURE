import os, sys

#################################################
############ Default FISSURE Header ############
#################################################
def getArguments():
    flow_graph_filepath = '/home/user/FISSURE/Flow Graph Library/Single-Stage Flow Graphs/Mode_S_PPM_USRPB210_stdout_webserver.py'
    samp_rate = '2e6'
    freq = '1090e6'
    gain = '70'
    antenna = 'TX/RX'
    channel = 'A:A'
    serial = 'False'
    threshold = '0.01'
    ip_address = '127.0.0.1'
    port = '5001'
    run_with_sudo = 'False'
    notes = "Forwards formatted decoded ADSB data (gr-adsb) originating from an SDR (2 MS/s) to a webserver (tcp://127.0.0.1:5001) over ZMQ."
    arg_names = ['flow_graph_filepath','samp_rate','freq','gain','antenna','channel','serial','threshold','ip_address','port','run_with_sudo','notes']
    arg_values = [flow_graph_filepath, samp_rate, freq, gain, antenna, channel, serial, threshold, ip_address, port, run_with_sudo, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    flow_graph_filepath = ''
    samp_rate = '2e6'
    freq = '1090e6'
    gain = '70'
    antenna = 'TX/RX'
    channel = 'A:A'
    serial = 'False'
    threshold = '0.01'
    ip_address = '127.0.0.1'
    port = '5001'

    # Accept Command Line Arguments
    try:
        flow_graph_filepath = sys.argv[1]
        samp_rate = sys.argv[2]
        freq = sys.argv[3]
        gain = sys.argv[4]
        antenna = sys.argv[5]
        channel = sys.argv[6]
        serial = sys.argv[7]
        threshold = sys.argv[8]
        ip_address = sys.argv[9]
        port = sys.argv[10]
    except:
        pass

#################################################

    # Run the Flow Graph
    os.system('python3 "' + flow_graph_filepath + '" --samp-rate=' + samp_rate + ' --freq=' + freq + ' --gain=' + gain + ' --antenna=' + antenna + ' --channel=' + channel + ' --serial="' + serial + '" --threshold=' + threshold + ' --ip-address=' + ip_address + ' --port=' + port)
