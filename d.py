"""
from scapy.all import *
from collections import Counter

def frame_types_between_devices(pcap_file, mac_d1, mac_d2):
    packets = rdpcap(pcap_file)
    frame_types = Counter()

    for packet in packets:
        if packet.haslayer(Dot11):
            if (packet.addr1 == mac_d1 and packet.addr2 == mac_d2) or \
               (packet.addr1 == mac_d2 and packet.addr2 == mac_d1):
                # Frame type and subtype are determined from the FCfield
                type_subtype = (packet.FCfield & 0b00001100, packet.FCfield & 0b11110000)
                frame_types[type_subtype] += 1

    return frame_types

# Usage example:
file_path = 'first.pcap'  # Replace with your pcap file path
mac_d1 = 'B4:B0:24:6D:DA:23'  # Replace with the MAC address of D1
mac_d2 = 'BC:32:B2:8F:F9:75'  # Replace with the MAC address of D2
types_of_frames = frame_types_between_devices(file_path, mac_d1, mac_d2)
print("Types of frames exchanged:")
for (frame_type, subtype), count in types_of_frames.items():
    print(f"Type {frame_type}, Subtype {subtype}: {count} times")
"""
"""
from scapy.all import *

# Load the pcap file
packets = rdpcap('first.pcap')

# Initialize a dictionary to count frame types
frame_types = {}

for packet in packets:
    if packet.haslayer(Dot11):
        # Ensure the packet is between D1 and D2
        if packet.addr2 == 'B4:B0:24:6D:DA:23' and packet.addr1 == 'BC:32:B2:8F:F9:75':
            # Get the type and subtype of the frame
            type_subtype = (packet.type, packet.subtype)
            
            # Define the frame type based on type and subtype
            if type_subtype in [(0, 0)]:
                frame_description = 'Association Request'
            elif type_subtype in [(0, 1)]:
                frame_description = 'Association Response'
            elif type_subtype in [(0, 4)]:
                frame_description = 'Probe Request'
            elif type_subtype in [(0, 5)]:
                frame_description = 'Probe Response'
            elif type_subtype in [(2, 0)]:
                frame_description = 'Data'
            elif type_subtype in [(1, 11)]:
                frame_description = 'ACK'
            else:
                frame_description = 'Other'
            
            # Count the frames
            if frame_description in frame_types:
                frame_types[frame_description] += 1
            else:
                frame_types[frame_description] = 1

# Print out the counts
for frame, count in frame_types.items():
    print(f"{frame}: {count}")
"""


from scapy.all import *

# Load the pcap file
packets = rdpcap('first.pcap')

# Dictionary to count frame types
frame_types = {}

for packet in packets:
    if packet.haslayer(Dot11):
        # Filter packets by MAC addresses of D1 and D2
        if packet.addr2 == 'B4:B0:24:6D:DA:23' and packet.addr1 == 'BC:32:B2:8F:F9:75':
            type_subtype = (packet.type, packet.subtype)
            frame_description = 'Other'  # Default description for uncategorized frames

            # Mapping frame types and subtypes to descriptions
            if type_subtype == (0, 0):
                frame_description = 'Association Request'
            elif type_subtype == (0, 1):
                frame_description = 'Association Response'
            elif type_subtype == (0, 4):
                frame_description = 'Probe Request'
            elif type_subtype == (0, 5):
                frame_description = 'Probe Response'
            elif type_subtype == (0, 8):
                frame_description = 'Beacon'
            elif type_subtype == (0, 11):
                frame_description = 'Authentication'
            elif type_subtype == (0, 12):
                frame_description = 'Deauthentication'
            elif type_subtype == (1, 13):
                frame_description = 'ACK'
            elif type_subtype == (2, 0):
                frame_description = 'Data'
            elif type_subtype == (2, 4):
                frame_description = 'Null (no data)'
            elif type_subtype == (2, 8):
                frame_description = 'QoS Data'

            # Count each type of frame
            if frame_description in frame_types:
                frame_types[frame_description] += 1
            else:
                frame_types[frame_description] = 1

# Output the results
for frame, count in frame_types.items():
    print(f"{frame}: {count}")



