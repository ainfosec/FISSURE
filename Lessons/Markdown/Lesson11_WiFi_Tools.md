---
This lesson will cover several topics relating to Wi-Fi and provide descriptions on how to use several tools. FISSURE has many of these tools as well as other integrated Wi-Fi capabilities such as packet crafting with Scapy and miscellaneous attack scripts.  

## Table of Contents
1. [Wi-Fi Basics](#wifi_basics)
2. [Monitor Mode](#monitor_mode)
3. [Scanning](#scanning)
4. [Reacting](#reacting)
5. [Capturing](#capturing)
6. [Password Cracking](#password_cracking)
7. [Denial of Service](#dos)
8. [Probing](#probing)
9. [Silencing](#silencing)
10. [Man-in-the-Middle](#mitm)
11. [Port Scanning](#port_scanning)
12. [Decrypting](#decrypting)
13. [Packet Crafting](#packet_crafting)
14. [Replay](#replay)
15. [More Tools](#more_tools)
16. [Websites](#websites)

<div id="wifi_basics"/> 

## Wi-Fi Basics

<div id="monitor_mode"/>   

## Monitor Mode

"Monitor mode allows a computer with a wireless network interface to monitor all traffic received on a wireless channel. Unlinke promiscuous mode, which ia lso used for packet sniffing, monitor mode allows packets to be captured without having to associate with an access point or ad hoc network first."
- https://en.wikipedia.org/wiki/Monitor_mode

FISSURE contains a "Monitor Mode Tool" to help switch between managed and monitor modes. It also contains the "monitor.sh" and "managed.sh" scripts in the `/Tools` folder that can be edited for your wireless interface.

**monitor.sh**

```
#!/bin/sh
sudo service network-manager stop
sudo ifconfig wlan0 down  
sudo ifconfig wlan0 up  # some devices produce errors if not brought down and up prior to switching modes
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
sudo iwconfig wlan0 channel 1
```

**managed.sh**

```
#!/bin/sh
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode managed
sudo ifconfig wlan0 up
sudo service network-manager start
```

<div id="scanning"/>  

## Scanning

Wi-Fi scanning can come in multiple forms. 

The following tools help with acquiring:
- SSIDs
- Frequencies
- Frequency Channels
- MAC Addresses
- RSSI Values

### scan-ssid

`scan-ssid <iface>` (Might have to repeat several times to see the list)

```
BSSID              RSSI     CH    Freq    SSID
28:b3:71:xx:xx:xx  -39.00    6    2437    Airfield_Operations
28:b3:71:xx:xx:xx  -39.00    6    2437    Business_Operations
28:b3:71:xx:xx:xx  -39.00    6    2437    SyracuseAirport_Public
```

### iwlist

`sudo iwlist <iface> scan`

```
wlp2s0    Scan completed :
          Cell 01 - Address: 28:B3:71:XX:XX:XX
                    Channel:149
                    Frequency:5.745 GHz
                    Quality=45/70  Signal level=-65 dBm  
                    Encryption key:on
                    ESSID:"Airfield_Operations"
                    Bit Rates:6 Mb/s; 9 Mb/s; 12 Mb/s; 18 Mb/s; 24 Mb/s
                              36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=000028508e4cab80
                    Extra: Last beacon: 32ms ago
                    IE: Unknown: 00134169726669656C645F4F7065726174696F6E73
                    IE: Unknown: 01088C129824B048606C
                    IE: Unknown: 030195
                    IE: Unknown: 070A55532024042495042400
                    IE: Unknown: DD180050F20201018C0003A4000027A4000042435E0062322F00
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 4605FE00000000
                    IE: Unknown: 2D1AEF1903FFFF000000000000000000000000000000000000000000
                    IE: Unknown: 3D1695050200000000000000000000000000000000000000
                    IE: Unknown: 0B0500002C0000
                    IE: Unknown: 7F080000080000000040
                    IE: Unknown: BF0C92498923FAFF0000FAFF0000
                    IE: Unknown: C005000000FCFF
                    IE: Unknown: C30502B8B8B800
                    IE: Unknown: DD08001392010001051D
```

<div id="reacting"/>  

### Trackerjacker

While in monitor mode:

```
sudo trackerjacker –i <iface> --map --map-file ~/wifi_map.yaml
gedit ~/wifi_map.yaml
```

## Reacting

There are several tools that will complete a predetermined function after detecting a target device or particular types of data.

### Trackerjacker

Trackerjacker will run an alert script upon surpassing a received amount of data.

```
echo echo ALERT! > alert.sh; chmod +x alert.sh
sudo trackerjacker –i <iface> --track --threshold 100 --channels- to-monitor 1 --trigger-command “./alert.sh”
```

### whoishere.py

This tool will react on detecting a target station MAC address while listening for probe requests. The "whoishere.py" and "whoishere.conf" files are included in the FISSURE menu. While in monitor mode:

1. Edit the wireless interface name and the target MAC address in the "whoishere.conf" file 
2. Replace `pushover_notification()` in "whoishere.py" with whatever action you wish to run
3. Run the tool with `python2 whoishere.py` 

<div id="capturing"/> 

## Capturing

Wireless traffic can be sniffed over the air while in monitor mode.

### Wireshark

Open Wireshark with `wireshark` and select a wireless interface in monitor mode. If the interface is not listed, Wireshark likely needs to be run with sudo permissions. Upon double-clicking an interface, traffic will be sniffed primarily on the frequency channel of the wireless interface. Adjust the frequency channel with the `iwconfig` command. 

Wireshark traffic can be exported to .pcap files for future viewing and analysis (File>>Export Specified Packets). 

Wireshark offers filtering to display only frames of interest. To view wireless traffic to and from a particular target, isolate a message containing its MAC address and right-click the field to "Apply as Filter." To view bidirectional traffic, change the filter from something like: `wlan.sa=XX:XX:XX:XX:XX:XX` to `wlan.addr`.

### tcpdump

tcpdump offers several commands for filtering traffic. A few example commands include:

```
sudo tcpdump -i <iface> port 3389
sudo tcpdump -i <iface> src port 1025
sudo tcpdump -i <iface> tcp
sudo tcpdump -i <iface> -l host 192.168.1.1
sudo tcpdump -i <iface> -l src 192.168.1.1
sudo tcpdump -i <iface> -w capture_file
sudo tcpdump -X -r capture_file | grep “text”
```

<div id="password_cracking"/>  

## Password Cracking

There are several types of encryption for Wi-Fi and they each have their own techniques. WEP password cracking utilizes statistical methods to speed up the cracking process. Attackers can stimulate a lot of traffic or passively listen for a long time to gather enough data to ascertain the password. WPA/WPA2 requires brute force techniques to obtain a password. The handshake contains enough information to decrypt the password. The handshake can be obtained passively or actively by deauthenticating a station and waiting for it to reconnect. 

PMKID capturing...

WPS is... The Pixie Dust and PIN brute force techniques... A list of devices known to be vulnerable to Pixie Dust can be found here:

- https://docs.google.com/spreadsheets/d/1tSlbqVQ59kGn8hgmwcPTHUECQ3o9YhXR91A_p7Nnj5Y/edit#gid=2048815923

Common software tools for password cracking and often included as packages in larger tools include:
- Crunch (wordlist generator)
- Cowpatty (crack password/username)
- Pyrit (create massive databases of pre-computed WPA/WPA2-PSK authentication phase)
- Reaver (brute-force the WPA handshaking)
- Bully (WPS brute force attack)

### Handshake Capturing with airgeddon  

The following steps are used to capture a handshake between a station and an access point using airgeddon. The handshake is saved to a .cap file and remembered within the same session for future actions.

1. `cd ~/Installed_by_FISSURE/airgeddon` (or launch from the FISSURE tools menu)
2. `sudo bash airgeddon.sh`
3. Select a wireless interface using the menu
4. Place the device into monitor mode (may have to select the option in the menu even if already in monitor mode)
5. Select the "Handshake/PMKID tools menu" (5)
6. Select "Capture Handshake" (6)
7. Choose a target network with clients
8. Select a deauthentication method such as "Deauth / disassoc amok mdk4 attack" (1)
9. Choose a longer timeout (60)
10. Save .cap file upon success

### WPA2 Cracking with Dictionary using airgeddon

The following steps perform a dictionary brute force using the captured handshake from the previous section.

1. Select "Offline WPA/WPA2 decrypt menu" (6)
2. Select "Personal" (1)
3. Select "(aircrack) Dictionary attack against Handshake/PMKID capture" (1)
4. Resuse the selected capture file and BSSID
5. Enter the location of a wordlist file such as "~/home/user/Installed_by_FISSURE/wifite2/wordlist-top4800-probable.txt"

### WPA2 Brute Forcing using airgeddon

To brute force using all possible character combinations select the "(aircrack + crunch) Bruteforce attack against Handshake/PMKID capture file" (2) from the "Offline WPA/WPA2 decrypt menu. This method will take a considerable amount of time to exhaust all combinations.

### WPS & WPA2 Cracking using Wifite2

Wifite2 will automatically run a variety of WPA and WPS cracking tools with limited user interaction. To run:

1. `cd ~/Installed_by_FISSURE/wifite2` (or launch from the FISSURE tools menu)
2. `sudo ./Wifite.py`
3. Select a target with clients
4. View results and press ctrl+c and enter 'c' to skip an attack

<div id="dos"/>  

## Denial of Service

Denial of service can be performed in a variety of ways whether it is through deauthentication, disassociation, ARP poisoning, Smurf (ICMP request messages), LAND (spoofed TCP SYN packet with the same source and destination IPs and ports), SYN flood, beacon flooding, and MAC flooding.

### Deauthentication with airgeddon

Select either while in monitor mode:
- Deauth/disassoc amok mdk4 attack
- Deauth aireplay attack

<div id="probing"/>  

## Probing

Wi-Fi devices can be probed to force traffic for geolocation and/or target confirmation. This can happen via probe requests and RTS frames.

<div id="silencing"/>  

## Silencing

Some wireless devices can be silenced temporarily through the reception of specially crafted CTS frames. This takes advantage of the built-in collision avoidance found in the protocol.

<div id="mitm"/>  

## Man-in-the-Middle

Man-in-the-middle/Person-in-the-middle attacks create new connections between two points to view/modify traffic, act as an evil twin, display a fake captive portal, or deploying some other phishing tool. This can occur with ARP spoofing/poisoning or by creating a new wireless network with the same name.

Some tools with such capability include:
- airgeddon
- Wifiphisher
- Fluxion 

<div id="port_scanning"/>  

## Port Scanning

While joined to a wireless network, port scanning is useful to determine potential entry points into an access point or device on the network. This is traditionally done via nmap commands such as:
- `nmap 192.168.1.1 -sV -p- --stats-every 10s`
- `sudo nmap 192.168.1.1 -sUV`

<div id="decrypting"/>  

## Decrypting

Encrypted wireless data frames in Wireshark will show up as QoS data until the decryption keys for WEP or WPA are added and a handshake is captured. This will be enough to decrypt the data frames and have them appear as other types beyond QoS such as TCP or UDP.
- https://wiki.wireshark.org/HowToDecrypt802.11

To add encryption keys in Wireshark for a WPA2 network follow these steps:
1. Open Wireshark
2. Navigate to "Edit>Preferences>Protocols>IEEE 802.11"
3. Click the "Edit Decryption keys" button
4. Click the '+' button
5. Select "wpa-pwd" option under "Key type"
6. Add the password and SSID as "password:SSID" in the "Key" field
7. Click OK and capture a handshake (verify with "eapol" filter)

![Key Examples](./Images/KeyExamples.png)

<div id="packet_crafting"/>  

## Packet Crafting

Wi-Fi frames can be crafted with Scapy to produce custom effects. 

### Common Scapy Commands

**Help**
- lsc()
- help(command) – in Python

**Combining Data**
- SomeLayer1() / SomeLayer2() / '\x00\x55\xff'

**Accessing, Modifying Fields**
```
get_bytes = RadioTap()/Dot11()/LLC()/SNAP()/IP()/UDP()
get_bytes[IP].src = "192.168.1.1"
get_bytes[UDP].dport = 1900
```

**Formatting Bytes**
- Python2: udp_data = "0012f6e1".decode('hex')
- Python3: udp_data = bytes.fromhex("3d12aa00ff3212")
- m = RadioTap()/Dot11()/LLC()/SNAP()/IP()/UDP()/udp_data

**Viewing**
- m.show()
- ls(m)
- ans.summary()

**Reading, Writing, Iterating**
```
from scapy.all import rdpcap, wrpcap
pkts = rdpcap("filename.pcap")
stripped_pkts = [pkt.payload for pkt in pkts]
wrpcap("new_file.pcap",stripped_pkts)
```

**Transmitting**
- send(scapy_data) – Layer3
- sendp(scapy_data, iface="iface", loop=0) – Layer2
- sr()/sr1()/srloop() – send/receive
- from scapy.all import send, IP, ICMP
  send(IP(src="10.0.99.100",dst="10.1.99.100")/ICMP()/"Hello World")
- from scapy.all import *
  mysocket = socket.socket()
  mysocket.connect(("192.168.1.1",5555))
  mystream = StreamSocket(mysocket)
  a = IP(dst="192.168.1.1")/TCP(dport=5555)/fuzz(Raw())
  mystream.send(a)

<div id="replay"/>  

## Replay

There are several tools for replaying captured traffic.

### Scapy

- sendp(rdpcap("/tmp/pcapfile"))

### Tcpreplay

- tcpreplay (sudo apt-get install tcpreplay)

### udpreplay

- udpreplay -i <iface> "filepath.pcap"

<div id="more_tools"/>  

## More Tools

The following are more tools relating to Wi-Fi that were not mentioned:
- gr-ieee802-11
- NETATTACK2
- RouterSploit
- Metasploit
- ESP8266 Deauther
- ESP8266 Beacon Spammer
- Arpspoof
- Driftnet
- SHODAN
- Kismet
- Fern Wifi Cracker
- SSH Username Enumerator
- Hydra
- mdk4
- RIT V2V/802.11p simulator

<div id="websites"/>  

## Websites

Additional websites relating to Wi-Fi are:
- [Exploit Database](https://www.exploit-db.com/)
- [WiGLE.net](https://wigle.net/)
- [Pixie Dust List](https://docs.google.com/spreadsheets/d/1tSlbqVQ59kGn8hgmwcPTHUECQ3o9YhXR91A_p7Nnj5Y/edit?pli=1#gid=2048815923)
- [TechInfoDepot](http://en.techinfodepot.shoutwiki.com/wiki/Main_Page)
- [WikiDevi](http://en.techinfodepot.shoutwiki.com/wiki/Main_Page/WikiDevi)
- [Sanitized IEEE OUI Data](https://linuxnet.ca/ieee/oui)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [Metasploit Wordlists](https://github.com/rapid7/metasploit-framework/tree/master/data/wordlists)

