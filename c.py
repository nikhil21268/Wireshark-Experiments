from scapy.all import *
from collections import defaultdict
import numpy as np

def compute_avg_bitrate(pcap_file):
    packets = rdpcap(pcap_file)

    # Dictionary to store rates for each BSSID
    rates_dict = defaultdict(list)

    i = 1

    # Extract rates and BSSID from each beacon frame
    for packet in packets:
        
        """
        if i == 1:
            i = 2
            packet.show()
        """

        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr2
            # Find the Rates element
            rates_element = packet.getlayer(Dot11Elt, ID=1)
            if rates_element:
                rates = rates_element.info
                # Convert rates from a bytes object to a list of integers
                rates = [rate // 2 for rate in rates]  # Divide by 2 to convert from 500kbps units to Mbps
                # print(rates)
                # print('\n')
                rates_dict[bssid].extend(rates)
    """
    print("printing dict for fun")
    print(rates_dict)
    print()
    """

    # Compute average rate for each BSSID
    avg_bitrates = {bssid: np.mean(rates) for bssid, rates in rates_dict.items()}

    return avg_bitrates

# Usage example:
file_path = 'one.pcap'  # Replace with your pcap file path
avg_bitrates = compute_avg_bitrate(file_path)
print("Average Bitrates by BSSID")
print()
print("The following is essentially just the average of all possible Bitrates that are currently supported for the frames corresponding to a particular BSSID:")
print()
for bssid, avg_rate in avg_bitrates.items():
    print(f"{bssid}: {avg_rate} Mbps")

print()
print("For the actual bitrates (in the form of data rates of the packets), we've the following:")
print()

"""
def extract_data_rates(pcap_file):
    packets = rdpcap(pcap_file)
    data_rates = []

    # Loop through each packet
    for packet in packets:
        if packet.haslayer(Dot11):
            # Check if the packet has a RadioTap layer where the data rate is stored
            if packet.haslayer(RadioTap):
                # Extract the rate if it exists
                rate = packet[RadioTap].Rate
                data_rates.append(rate)
                print(f"Data rate: {rate} Mbps")  # The Rate field in RadioTap is usually in 500kbps units

    return data_rates
"""

def extract_data_rates(pcap_file):
    packets = rdpcap(pcap_file)
    bssid_data_rates = defaultdict(list)

    # Loop through each packet
    for packet in packets:
        if packet.haslayer(Dot11Beacon):  # Check specifically for Beacon frames
            bssid = packet[Dot11].addr2  # BSSID usually is in addr2 for management frames
            if packet.haslayer(RadioTap):
                # Extract the rate if it exists
                rate = packet[RadioTap].Rate
                if rate is not None:
                    bssid_data_rates[bssid].append(rate)  # Convert to Mbps

    # Compute average data rate for each BSSID
    avg_data_rates = {bssid: np.mean(rates) for bssid, rates in bssid_data_rates.items() if rates}

    return avg_data_rates

# Usage example:
file_path = 'one.pcap'  # Replace with your pcap file path
# extract_data_rates(file_path)
average_rates_by_bssid = extract_data_rates(file_path)
print("Average data rates by BSSID:")
for bssid, avg_rate in average_rates_by_bssid.items():
    print(f"{bssid}: {avg_rate} Mbps")
