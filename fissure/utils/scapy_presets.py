"""Declarative Scapy presets used by the Dashboard Scapy tab.

Normal presets should be added here as data instead of adding Scapy imports,
version checks, or packet-building lambdas to ScapyTabSlots.py.

Each preset is an ordered list of:
    ("ScapyLayerClassName", {"field": value, ...})

Nested packet-valued fields can use:
    {
        "__scapy_layer__": "LayerClassName",
        "fields": {"field": value, ...},
    }

At runtime, ScapyTabSlots filters out presets whose layers are unavailable in
the installed Scapy version.
"""


BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
SOURCE_MAC = "02:11:22:33:44:55"
TARGET_MAC = "02:aa:bb:cc:dd:ee"


SCAPY_PRESETS = {
    "Wi-Fi (802.11)": {
        "Beacon": [
            ("RadioTap", {}),
            ("Dot11", {
                "type": 0,
                "subtype": 8,
                "addr1": BROADCAST_MAC,
                "addr2": SOURCE_MAC,
                "addr3": SOURCE_MAC,
            }),
            ("Dot11Beacon", {}),
            ("Dot11Elt", {
                "ID": "SSID",
                "info": b"FISSURE",
            }),
        ],
        "Probe Request": [
            ("RadioTap", {}),
            ("Dot11", {
                "type": 0,
                "subtype": 4,
                "addr1": BROADCAST_MAC,
                "addr2": SOURCE_MAC,
                "addr3": BROADCAST_MAC,
            }),
            ("Dot11ProbeReq", {}),
            ("Dot11Elt", {
                "ID": "SSID",
                "info": b"FISSURE",
            }),
        ],
        "Probe Response": [
            ("RadioTap", {}),
            ("Dot11", {
                "type": 0,
                "subtype": 5,
                "addr1": TARGET_MAC,
                "addr2": SOURCE_MAC,
                "addr3": SOURCE_MAC,
            }),
            ("Dot11ProbeResp", {}),
            ("Dot11Elt", {
                "ID": "SSID",
                "info": b"FISSURE",
            }),
        ],
        "Authentication": [
            ("RadioTap", {}),
            ("Dot11", {
                "type": 0,
                "subtype": 11,
                "addr1": TARGET_MAC,
                "addr2": SOURCE_MAC,
                "addr3": TARGET_MAC,
            }),
            ("Dot11Auth", {
                "algo": 0,
                "seqnum": 1,
                "status": 0,
            }),
        ],
        "Association Request": [
            ("RadioTap", {}),
            ("Dot11", {
                "type": 0,
                "subtype": 0,
                "addr1": TARGET_MAC,
                "addr2": SOURCE_MAC,
                "addr3": TARGET_MAC,
            }),
            ("Dot11AssoReq", {}),
            ("Dot11Elt", {
                "ID": "SSID",
                "info": b"FISSURE",
            }),
        ],
        "Deauthentication": [
            ("RadioTap", {}),
            ("Dot11", {
                "type": 0,
                "subtype": 12,
                "addr1": BROADCAST_MAC,
                "addr2": SOURCE_MAC,
                "addr3": SOURCE_MAC,
            }),
            ("Dot11Deauth", {
                "reason": 7,
            }),
        ],
    },
    "Common Wired (Ethernet/IP)": {
        "ARP Request": [
            ("Ether", {
                "dst": BROADCAST_MAC,
                "src": SOURCE_MAC,
            }),
            ("ARP", {
                "op": 1,
                "hwsrc": SOURCE_MAC,
                "psrc": "192.168.1.10",
                "hwdst": "00:00:00:00:00:00",
                "pdst": "192.168.1.1",
            }),
        ],
        "ARP Reply": [
            ("Ether", {
                "dst": TARGET_MAC,
                "src": SOURCE_MAC,
            }),
            ("ARP", {
                "op": 2,
                "hwsrc": SOURCE_MAC,
                "psrc": "192.168.1.10",
                "hwdst": TARGET_MAC,
                "pdst": "192.168.1.20",
            }),
        ],
        "IPv4 ICMP Echo Request": [
            ("Ether", {
                "dst": TARGET_MAC,
                "src": SOURCE_MAC,
            }),
            ("IP", {
                "src": "192.168.1.10",
                "dst": "192.168.1.20",
            }),
            ("ICMP", {
                "type": 8,
                "code": 0,
            }),
        ],
        "IPv4 UDP": [
            ("Ether", {
                "dst": TARGET_MAC,
                "src": SOURCE_MAC,
            }),
            ("IP", {
                "src": "192.168.1.10",
                "dst": "192.168.1.20",
            }),
            ("UDP", {
                "sport": 12345,
                "dport": 12345,
            }),
            ("Raw", {
                "load": b"FISSURE",
            }),
        ],
        "IPv4 TCP SYN": [
            ("Ether", {
                "dst": TARGET_MAC,
                "src": SOURCE_MAC,
            }),
            ("IP", {
                "src": "192.168.1.10",
                "dst": "192.168.1.20",
            }),
            ("TCP", {
                "sport": 12345,
                "dport": 80,
                "flags": "S",
            }),
        ],
        "DHCP Discover": [
            ("Ether", {
                "dst": BROADCAST_MAC,
                "src": SOURCE_MAC,
            }),
            ("IP", {
                "src": "0.0.0.0",
                "dst": "255.255.255.255",
            }),
            ("UDP", {
                "sport": 68,
                "dport": 67,
            }),
            ("BOOTP", {
                "chaddr": b"\x02\x11\x22\x33\x44\x55",
            }),
            ("DHCP", {
                "options": [
                    ("message-type", "discover"),
                    "end",
                ],
            }),
        ],
        "DNS Query": [
            ("Ether", {
                "dst": TARGET_MAC,
                "src": SOURCE_MAC,
            }),
            ("IP", {
                "src": "192.168.1.10",
                "dst": "192.168.1.1",
            }),
            ("UDP", {
                "sport": 12345,
                "dport": 53,
            }),
            ("DNS", {
                "rd": 1,
                "qd": {
                    "__scapy_layer__": "DNSQR",
                    "fields": {
                        "qname": "example.com",
                    },
                },
            }),
        ],
    },
    "IPv6": {
        "IPv6 ICMP Echo Request": [
            ("Ether", {
                "dst": TARGET_MAC,
                "src": SOURCE_MAC,
            }),
            ("IPv6", {
                "src": "2001:db8::10",
                "dst": "2001:db8::20",
            }),
            ("ICMPv6EchoRequest", {}),
        ],
        "IPv6 UDP": [
            ("Ether", {
                "dst": TARGET_MAC,
                "src": SOURCE_MAC,
            }),
            ("IPv6", {
                "src": "2001:db8::10",
                "dst": "2001:db8::20",
            }),
            ("UDP", {
                "sport": 12345,
                "dport": 12345,
            }),
            ("Raw", {
                "load": b"FISSURE",
            }),
        ],
    },
}
