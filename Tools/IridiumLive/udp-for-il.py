import sys
import select
import time
import socket

# In my case 192.168.2.10 is the IP of the destination for the UDP datagrams below. It is the machine where IridiumLive application runs.
# Replace as needed for your network settings.

ap = ("127.0.0.1", 15007)
sk = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
def sendOverUdp(line):
    bytes = str.encode(line)
    sk.sendto(bytes, ap)
    print(len(bytes))

def no_input():
    print('no input')

while True:
    line = sys.stdin.readline()
    if line:
        sendOverUdp(line)
    else:		
        time.sleep(1)		
else:
    no_input()
