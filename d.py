from scapy.all import *
from collections import Counter

def frame_types_between_devices(pcap_file, mac_d1, mac_d2):
    packets = rdpcap(pcap_file)
    frame_types = Counter()

    for packet in packets:
        if packet.haslayer(Dot11):
            if (packet.addr1 == mac_d1 and packet.addr2 == mac_d2) or \
               (packet.addr1 == mac_d2 and packet.addr2 == mac_d1):
                # Correct extraction of frame type and subtype
                
                frame_type = (packet.FCfield >> 2) & 0x03
                frame_subtype = (packet.FCfield >> 4) & 0x0F
                type_subtype = (frame_type, frame_subtype)
                

                # type_subtype = (packet.FCfield & 0b00001100, packet.FCfield & 0b11110000)

                frame_types[type_subtype] += 1

    return frame_types

# Usage example:
file_path = 'one.pcap'  # Replace with your pcap file path
"""
mac_d1 = 'b4:b0:24:6d:da:23'  # Replace with the MAC address of D1
mac_d2 = 'bc:32:b2:8f:f9:75'  # Replace with the MAC address of D2
"""
mac_d1 = 'aa:ba:69:94:d7:95'  # Replace with the MAC address of D1
mac_d2 = 'bc:32:b2:8f:f9:75'  # Replace with the MAC address of D2
types_of_frames = frame_types_between_devices(file_path, mac_d1, mac_d2)
print("Types of frames exchanged:")
for (frame_type, subtype), count in types_of_frames.items():
    print(f"Type {frame_type}, Subtype {subtype}: {count} times")

