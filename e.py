"""
from scapy.all import *
from collections import defaultdict

def analyze_acknowledgments(pcap_file):
    packets = rdpcap(pcap_file)
    acks = []
    acked_frames = defaultdict(int)

    for packet in packets:
        if packet.haslayer(Dot11):
            # Check if the frame is an acknowledgment frame
            if packet.type == 1 and packet.subtype == 0xD:
                acks.append(packet)
                # Capture and count the types of acknowledged frames
                # Note: Realistically, we'd need more context to understand what specific frame was acknowledged,
                # as this information isn't directly available from the acknowledgment frame itself.

    # Example: Print details about each ACK frame
    for ack in acks:
        # Try to get bitrate from the RadioTap layer, if available
        bitrate = ack.getlayer(RadioTap).Rate if ack.haslayer(RadioTap) else 'Unknown'
        print(f"ACK Frame: {ack.summary()}, Bitrate: {bitrate} Mbps")

    # Print summary of acked frame types
    print("Acknowledged frame types:")
    for frame_type, count in acked_frames.items():
        print(f"Type {frame_type}: {count} times")

# Usage example:
file_path = 'first.pcap'  # Replace with your pcap file path
analyze_acknowledgments(file_path)
"""

from scapy.all import *
from collections import defaultdict, Counter

def analyze_acknowledgments(pcap_file):
    packets = rdpcap(pcap_file)
    last_frame_type_per_transmitter = {}
    acked_frames = Counter()

    for packet in packets:
        if packet.haslayer(Dot11):
            if packet.type == 1 and packet.subtype == 0xD:
                # This is an ACK frame
                ra = packet.addr1
                if ra in last_frame_type_per_transmitter:
                    frame_desc = last_frame_type_per_transmitter[ra]
                    acked_frames[frame_desc] += 1
                    bitrate = packet.getlayer(RadioTap).Rate if packet.haslayer(RadioTap) else 'Unknown'
                    print(f"ACK Frame for {frame_desc}: {packet.summary()}, Bitrate: {bitrate} Mbps")
            else:
                # Track the last non-ACK frame per transmitter
                ta = packet.addr2 if packet.addr2 else packet.addr1
                frame_type = (packet.type, packet.subtype)
                last_frame_type_per_transmitter[ta] = frame_type

    # Print summary of acked frame types
    print("Acknowledged frame types:")
    for frame_type, count in acked_frames.items():
        print(f"Type {frame_type}: {count} times")

# Usage example:
file_path = 'first.pcap'  # Replace with your pcap file path
analyze_acknowledgments(file_path)

