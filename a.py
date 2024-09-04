"""
import pyshark

def extract_ssids(pcap_file):
    # Create a FileCapture object with the specified pcapng file
    cap = pyshark.FileCapture(pcap_file, display_filter='wlan.fc.type_subtype == 0x08')
    ssids = set()

    # Iterate through packets in the capture file
    for packet in cap:
        try:
            # Extract the SSID from the packet, if available
            ssid = packet.wlan_mgt.ssid
            if ssid:  # Check if the SSID field is not empty
                ssids.add(ssid)
        except AttributeError:
            # Skip packets that do not have WLAN management layer or SSID field
            continue

    # Print all unique SSIDs found in the capture
    for ssid in ssids:
        print(ssid)

# Replace 'path_to_your_beacon_frames.pcapng' with the actual path to your capture file
extract_ssids('first.pcapng')
"""
"""
import pyshark

def extract_ssids(pcap_file):
    try:
        # Create a FileCapture object with the specified pcapng file
        cap = pyshark.FileCapture(pcap_file, display_filter='wlan.fc.type_subtype == 0x08')
        ssids = set()

        # Iterate through packets in the capture file
        for packet in cap:
            try:
                # Extract the SSID from the packet, if available
                ssid = packet.wlan_mgt.ssid
                if ssid:  # Check if the SSID field is not empty
                    ssids.add(ssid)
            except AttributeError:
                # Skip packets that do not have WLAN management layer or SSID field
                continue

        # Print all unique SSIDs found in the capture or indicate none were found
        if ssids:
            for ssid in ssids:
                print(ssid)
        else:
            print("No SSIDs found in the provided pcap file.")

    except Exception as e:
        print(f"An error occurred: {e}")

# Replace 'path_to_your_beacon_frames.pcapng' with the actual path to your capture file
extract_ssids('firstCap.pcap')
"""
"""
from scapy.all import rdpcap, Packet

# Load packets from a pcap file
packets = rdpcap('firstCap.pcap')

# Iterate through and print out each packet's summary
for packet in packets:
    print(packet.summary())
"""

from scapy.all import *

def extract_beacon_ssids(pcap_file):
    # Load the pcap file
    packets = rdpcap(pcap_file)

    # Filter for Beacon frames and extract SSIDs
    ssids = set()
    for packet in packets:
        if packet.haslayer(Dot11Beacon):
            # Access the Dot11Elt layer where SSID information is stored
            ssid_layer = packet[Dot11Elt]
            while isinstance(ssid_layer, Dot11Elt):
                if ssid_layer.ID == 0:  # SSID parameter set ID
                    ssids.add(ssid_layer.info.decode('utf-8'))
                ssid_layer = ssid_layer.payload
    return ssids

# Usage example:
file_path = 'first.pcap'  # Change to your pcap file path
beacon_ssids = extract_beacon_ssids(file_path)
print("SSIDs found in beacon frames:")
for ssid in beacon_ssids:
    print(ssid)

