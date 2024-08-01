import socket
import time
import sys
#import os
from fastecdsa import ecdsa
from fastecdsa.keys import import_key
from hashlib import sha256
import subprocess
import math
from datetime import datetime
import binascii

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    vehicle_id = 0
    coordinate_filepath = ""  #"/home/someguy/FISSURE/Tools/v2verifier-master/coords/coords_1"
    key_filepath = ""         #"/home/someguy/FISSURE/Tools/v2verifier-master/keys/0/p256.key"
    interval = 0.1
    wifi_tx_udp_port = 52001
    wifi_tx_ip_address = "127.0.0.1"
    notes = 'Generates DSRC messages using a coordinate file and a key file. Messages are sent to a wifi_tx UDP port.'
    arg_names = ['vehicle_id','coordinate_filepath','key_filepath','interval','wifi_tx_udp_port','wifi_tx_ip_address','notes']
    arg_values = [vehicle_id, coordinate_filepath, key_filepath, interval, wifi_tx_udp_port, wifi_tx_ip_address, notes]

    return (arg_names,arg_values)
    


########################################################################
     
def get_wsm_payload(bsm_string, key):
    payload = get_llc_bytestring() + get_wsm_headers() + getIeee1609Dot2Data(bsm_string, key)

    return "\\x" + "\\x".join(payload[i:i + 2] for i in range(0, len(payload), 2))


def get_llc_bytestring():
    bytestring = ""

    # Logical Link Control fields

    # llc_dsap = "aa" to indicate SNAP extension in use (for protocol identification)
    bytestring += "aa"

    # llc_ssap = "aa" to indicate SNAP extension in use  (for protocol identification)
    bytestring += "aa"

    # llc_control = "03" for unacknowledged, connectionless mode
    bytestring += "03"

    # llc_org_code = "000000" as we have no assigned OUI
    bytestring += "000000"

    # llc_type = "88dc" to indicate WAVE Short Message Protocol
    bytestring += "88dc"

    return bytestring


def get_wsm_headers():
    bytestring = ""

    # WSM N-Header and T-Header fields

    # wsmp_n_subtype_opt_version = "03"
    bytestring += "03"
    # wsmp_n_tpid = "00"
    bytestring += "00"
    # wsmp_t_headerLengthAndPSID = "20"
    bytestring += "20"
    # wsmp_t_length = "00"
    bytestring += "00"

    return bytestring


def getIeee1609Dot2Data(message, key):
    message = message.encode("utf-8").hex()

    # IEEE1609Dot2Data Structure
    bytestring = ""
    # Protocol Version
    bytestring += "03"
    # ContentType ( signed data = 81)
    bytestring += "81"
    # HashID (SHA256 = 00)
    bytestring += "00"

    # start tbsData structure
    bytestring += "40"
    # Protocol Version
    bytestring += "03"

    # Content - Unsecured Data
    bytestring += "80"

    # Length of Unsecured Data
    length = hex(int(len(str(message)) / 2)).split("x")[1]
    if len(length) == 1:
        bytestring += "0"
    bytestring += length

    # unsecuredData
    bytestring += message

    # headerInfo
    bytestring += "4001"

    # PSID (BSM = 20)
    bytestring += "20"

    # generationTime (8 bytes)

    # TODO: fix this - should be actual generationTime64
    # this is a placeholder byte pattern that is unlikely to occur in practice, used to inject actual time
    # when packet is transmitted
    bytestring += "F0E0F0E0F0E0F0E0"

    # signer = "digest"
    bytestring += "80"

    # TODO: fix this - should be actual, calculated value
    # digest (8 bytes)
    bytestring += "0000000000000000"

    # signature (ecdsaNistP256Signature = 80)
    bytestring += "80"

    # ecdsaNistP256Signature (r: compressed-y-0 = 82)
    # 80 -> x-only
    # 81 -> fill (NULL)
    # 82 -> compressed-y-0
    # 83 -> compressed-y-1
    # 84 -> uncompressed
    bytestring += "80"

    private, public = import_key(key)
    r, s = ecdsa.sign(message, private, hashfunc=sha256)

    r = hex(r)
    s = hex(s)

    r = r.split("x")[1][:len(r) - 2]
    s = s.split("x")[1][:len(s) - 2]

    # these while loops pad the front of the hex key with zeros to make sure they fit the 32-byte field length
    while len(r) < 64:
        r = "0" + r

    while len(s) < 64:
        s = "0" + s

    # r (32 bytes)
    bytestring += str(r)

    # s (32 bytes)
    bytestring += str(s)

    return bytestring


#def send_payload_to_gnuradio(message_payload):
    #loader = subprocess.Popen(("echo", "-n", "-e", message_payload), stdout=subprocess.PIPE)
    #sender = subprocess.check_output(("nc", "-w0", "-u", get_wifi_tx_ip_address, str(get_wifi_tx_udp_port)), stdin=loader.stdout)
    
    
def calculate_heading(current_coords, next_coords):
    x_now, y_now = current_coords.split(",")
    x_now = float(x_now)
    y_now = float(y_now)

    x_next, y_next = next_coords.split(",")
    x_next = float(x_next)
    y_next = float(y_next)

    if x_next == x_now and y_next == y_now:
        return "-"
    else:
        if x_next > x_now:
            if y_next > y_now:
                return "SE"
            elif y_next == y_now:
                return "E"
            else:
                return "NE"
        elif x_next == x_now:
            return "S" if y_next > y_now else "N"
        elif x_next < x_now:
            if y_next > y_now:
                return "SW"
            elif y_next == y_now:
                return "W"
            else:
                return "NW"
                
                
def calc_speed(current_coords, next_coords):
    x_now, y_now = current_coords.split(",")
    x_now = float(x_now)
    y_now = float(y_now)

    x_next, y_next = next_coords.split(",")
    x_next = float(x_next)
    y_next = float(y_next)

    return math.sqrt(math.pow(x_next-x_now, 2)+math.pow(y_next-y_now, 2)) * 36     
    

def inject_time(bsm):

    # IEEE 1609.2 defines timestamps as an estimate of the microseconds elapsed since
    # 12:00 AM on January 1, 2004
    origin = datetime(2004, 1, 1, 0, 0, 0, 0)

    # get the offset since the origin time in microseconds
    offset = (datetime.now() - origin).total_seconds() * 1000
    time_string = hex(int(math.floor(offset)))
    time_string  = time_string[2:]
    if len(time_string) < 16:
        for i in range(0, 16 - len(time_string)):
            time_string = "0" + time_string
    time_string = "\\x" + "\\x".join(time_string[i:i + 2] for i in range(0, len(time_string), 2))
    bsm = bsm.replace("\\xF0\\xE0\\xF0\\xE0\\xF0\\xE0\\xF0\\xE0", time_string)

    return bsm.replace("\\xF0\\xE0\\xF0\\xE0\\xF0\\xE0\\xF0\\xE0", time_string)

########################################################################    


if __name__ == "__main__":

    # Default Values
    get_vehicle_id = 0
    get_coordinate_filepath = ""  #"/home/someguy/FISSURE/Tools/v2verifier-master/coords/coords_1"
    get_key_filepath = ""         #"/home/someguy/FISSURE/Tools/v2verifier-master/keys/0/p256.key"
    get_interval = 0.1
    get_wifi_tx_udp_port = 52001
    get_wifi_tx_ip_address = "127.0.0.1"

    # Accept Command Line Arguments
    try:
        get_vehicle_id = int(sys.argv[1])
        get_coordinate_filepath = sys.argv[2]
        get_key_filepath = sys.argv[3]
        get_interval = float(sys.argv[4])
        get_wifi_tx_udp_port = int(sys.argv[5])
        get_wifi_tx_ip_address = sys.argv[6]
    except:
        pass

#################################################

    if (len(get_coordinate_filepath) > 0) and (len(get_key_filepath) > 0):
        
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                
        # Get Coordinates
        with open(get_coordinate_filepath, "r") as coordinates_file:
            coordinate_list = coordinates_file.readlines()
            
        if len(coordinate_list) < 3:
            raise Exception("Your file must have at least 3 pairs of coordinates")

        # Send Messages to wifi_tx
        for i in range(0, len(coordinate_list) - 2):
            heading = calculate_heading(coordinate_list[i], coordinate_list[i + 1])
            speed = calc_speed(coordinate_list[i], coordinate_list[i + 1])
            bsm_text = str(get_vehicle_id) + "," + coordinate_list[i].replace("\n", "") + "," + heading + "," + \
                str(round(speed, 2)) + "\n"
            bsm_payload = get_wsm_payload(bsm_text, get_key_filepath)
            bsm_payload = inject_time(bsm_payload)
            print("Sending message: ", bsm_text)
            
            # Remove '\x'
            bsm_payload_formatted = ''
            for j in range(0,len(bsm_payload),4):
                bsm_payload_formatted = bsm_payload_formatted + bsm_payload[j+2:j+4]

            #send_payload_to_gnuradio(bsm_payload)
            udp_socket.sendto(binascii.unhexlify(bsm_payload_formatted),(get_wifi_tx_ip_address, get_wifi_tx_udp_port))
            time.sleep(get_interval)   
    else:
        print("Invalid File Selected")
        
        
        
######################################################################## 
   
