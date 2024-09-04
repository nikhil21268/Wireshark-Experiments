from scapy.all import *
from collections import defaultdict

def compute_avg_signal_strength(pcap_file):
    # Load the pcap file
    packets = rdpcap(pcap_file)

    # Dictionary to hold signal strengths for each BSSID
    signal_strengths = defaultdict(list)

    # Extract signal strength and BSSID from each beacon frame
    for packet in packets:
        if packet.haslayer(Dot11Beacon):
            if packet.haslayer(RadioTap):
                bssid = packet[Dot11].addr2
                dbm_signal = packet[RadioTap].dBm_AntSignal
                signal_strengths[bssid].append(dbm_signal)
    """    
    print("printing dict for fun")
    print(signal_strengths)
    print()
    """

    # Compute average signal strength for each BSSID
    avg_signal_strengths = {bssid: sum(values) / len(values) for bssid, values in signal_strengths.items() if values}

    return avg_signal_strengths

# Usage example:
file_path = 'one.pcap'  # Change to your pcap file path
avg_signals = compute_avg_signal_strength(file_path)
print("Average Signal Strengths by BSSID:")
for bssid, avg_signal in avg_signals.items():
    print(f"{bssid}: {avg_signal} dBm")

