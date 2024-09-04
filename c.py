from scapy.all import *
from collections import defaultdict
import numpy as np

def compute_avg_bitrate(pcap_file):
    packets = rdpcap(pcap_file)

    # Dictionary to store rates for each BSSID
    rates_dict = defaultdict(list)

    # Extract rates and BSSID from each beacon frame
    for packet in packets:
        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr2
            # Find the Rates element
            rates_element = packet.getlayer(Dot11Elt, ID=1)
            if rates_element:
                rates = rates_element.info
                # Convert rates from a bytes object to a list of integers
                rates = [rate // 2 for rate in rates]  # Divide by 2 to convert from 500kbps units to Mbps
                rates_dict[bssid].extend(rates)

    print("printing dict for fun")
    print(rates_dict)
    print()

    # Compute average rate for each BSSID
    avg_bitrates = {bssid: np.mean(rates) for bssid, rates in rates_dict.items()}

    return avg_bitrates

# Usage example:
file_path = 'first.pcap'  # Replace with your pcap file path
avg_bitrates = compute_avg_bitrate(file_path)
print("Average Bitrates by BSSID:")
for bssid, avg_rate in avg_bitrates.items():
    print(f"{bssid}: {avg_rate} Mbps")

