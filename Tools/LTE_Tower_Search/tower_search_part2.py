import subprocess
import re
import os
import sys
import psutil
#import pyshark
#import argparse
#import time
from decimal import Decimal
#import signal
import ast

########################################################################
# US: 2, 4, 5, 12, 13, 14, 17, 25, 26, 29, 30, 41, 46, 48, 66, 71
# Europe: 3, 7, 20
# China, India: 3, 40, 41
# AT&T: 2, 4, 5, 12, 14, 17, 29, 30, 66
# Verizon: 2, 4, 5, 13, 46, 48, 66
# T-Mobile/Sprint: 2, 4, 5, 12, 66, 71/25, 26, 41
# All: 2, 3, 4, 5, 7, 12, 13, 14, 17, 20, 25, 26, 29, 30, 40, 41, 46, 48, 66, 71
########################################################################

def kill(proc_pid):
    process = psutil.Process(proc_pid)
    for proc in process.children(recursive=True):
        proc.kill()
    process.kill()

# # Input Arguments
# get_cell_search_binary = sys.argv[1]
# get_bands = sys.argv[2][1:-1]
# get_bands = get_bands.split(',')

# # Search One Band at a Time
# for b in get_bands:
    # print("\nScanning LTE Band #" + b)
    
    # # Run the srsRAN Binary
    # # p1 = subprocess.Popen([get_cell_search_binary, '-b', b, "-g", "70"], stdout=subprocess.PIPE)
    # # output = p1.communicate()
    # # output = str(output)
    # ####################################################################
    # output = """
    # (b'linux; GNU C++ version 7.3.0; Boost_106501; UHD_003.010.003.000-0-unknown\n\nOpening RF device...\nOpening USRP channels=1, args: type=b200,master_clock_rate=23.04e6\n-- Detected Device: B210\n-- Operating over USB 3.\n-- Initialize CODEC control...\n-- Initialize Radio control...\n-- Performing register loopback test... pass\n-- Performing register loopback test... pass\n-- Performing CODEC loopback test... pass\n-- Performing CODEC loopback test... pass\n-- Asking for clock rate 23.040000 MHz... \n-- Actually got clock rate 23.040000 MHz.\n-- Performing timer loopback test... pass\n-- Performing timer loopback test... pass\n\n\nFound 5 cells\nMHz=1935.0,EARFCN=650,PHYID=434,PRB=50,ports=4,PSS power=-28.1 dBm\nMHz=1935.2,EARFCN=652,PHYID=398,PRB=15,ports=4,PSS power=-29.8 dBm\nMHz=1972.2,EARFCN=1022,PHYID=2,PRB=50,ports=2,PSS power=-31.9 dBm\nMHz=1972.4,EARFCN=1024,PHYID=2,PRB=75,ports=2,PSS power=-33.5 dBm\nMHz=1972.5,EARFCN=1025,PHYID=434,PRB=75,ports=4,PSS power=-30.0 dBm\n\nBye\n', None)
    # """

    # ####################################################################
    
    # # Parse the Output
    # num_cells = re.search('Found (\d+) cells', output)
    # if not num_cells:
        # print("No cells found, try again.")        
    # else:
        # num_cells = num_cells.group(1)
        # search_space = output.find('Found')
        # output = output[search_space + 14:][:-19]
        # output = output.split('\n')
        
        # if num_cells == "0":
            # print("No cell towers found, please run again.")
            # sys.exit(1)
        # cells = []
        # for cell in output:
            # configs = {}
            # for variable in cell.split(","):
                # if "=" not in variable:
                    # pass
                # else:
                    # key, value = variable.split("=")
                    # configs[key] = value.lstrip()
            # cells.append(configs)
               
        # print("\nFound " + str(num_cells) + " Towers")     
        # print("################################################################################################################################")
        # print("###########################################################  TOWERS  ###########################################################")
        # print("################################################################################################################################")        
        # num_cells = int(num_cells)
        # for x in range(0,int(num_cells)):
            # print("Cell Tower #%d " % (x + 1) + str(cells[x]))
        # print("################################################################################################################################")
        # print("################################################################################################################################")
        # print("################################################################################################################################")
        # print("\n")

    # # ~ p1.terminate()
    
    # Extract the MCC, MNC, and TAC for Towers
    
    
    
########################################################################
# Input Arguments
get_cell = [arg for arg in sys.argv[1:]]
get_cell = ast.literal_eval(get_cell[0])
# ~ get_cell = json.loads('"""' + get_cell[0] + '"""')

cells = []
#cells.append({'MHz': '1952.5', 'EARFCN': '825', 'PHYID': '253', 'PRB': '75', 'ports': '2', 'PSS power': '-29.1 dB'})
#cells.append({'MHz': '2125.0', 'EARFCN': '2100', 'PHYID': '276', 'PRB': '50', 'ports': '4', 'PSS power': '-28.9 dBm'})
cells.append(get_cell)

########################################################################

num_cells = len(cells)
for n in range(0,num_cells):
    MHz = Decimal(cells[n]['MHz'])
    MHz = int(float(MHz * 1000000))
    MHz = str(MHz)
    cell_id = cells[n]['PHYID']
    no_PRBs = cells[n]['PRB']
    gain = str(80)
    earfcn = cells[n]['EARFCN']
    with open("ue.conf", "r") as conf:
        data = conf.readlines()
    data[56] = "dl_earfcn = {}\n".format(earfcn)
    with open('ue.conf', 'w') as conf:
        conf.writelines(data)

    ue = ["srsue ue.conf"]
    with open("tower_info", "w+") as f:
        execute_ue = subprocess.Popen(ue, shell=True, stdout=f)
        f.read()
    print("\nListening for tower info...")
    with open("tower_info", "r") as f:
        line = f.readline()
        while not line.startswith("Found PLMN"):
            line = f.readline()
        #print(str(line))  # Found PLMN:  Id=310410, TAC=3339
        line = line.split(',')
        mcc_mnc = str(line[0][line[0].find('Id=')+3:])
        tac = str(line[1][line[1].find('TAC=')+4:]).strip()
        #key, value = "M
        print("\nMCC/MNC: " + mcc_mnc)
        print("TAC: " + tac)            
        cells[n]['MCC_MNC']=mcc_mnc
        cells[n]['TAC']=tac
    kill(execute_ue.pid)


print("################################################################################################################################")
print("###########################################################  TOWERS  ###########################################################")
print("################################################################################################################################")        
for x in range(0,int(num_cells)):
    print("Cell Tower #%d " % (x + 1) + str(cells[x]))
print("################################################################################################################################")
print("################################################################################################################################")
print("################################################################################################################################")
print("\n")


