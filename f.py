"""
from scapy.all import *
import numpy as np

# MAC addresses for the devices
D1 = 'B4:B0:24:6D:DA:23'
D2 = 'BC:32:B2:8F:F9:75'

# Load packets from a pcap file
packets = rdpcap('first.pcap')

# Filter packets between D1 and D2
filtered_packets = [pkt for pkt in packets if (pkt.haslayer(Dot11) and 
                                               ((pkt.addr1 == D1 and pkt.addr2 == D2) or 
                                                (pkt.addr1 == D2 and pkt.addr2 == D1)))]

# Initialize lists to hold signal strengths and bitrates
signal_strengths = []
bitrates = []

# Extract signal strength and bitrate
for pkt in filtered_packets:
    try:
        # Check for RadioTap layer where signal strength and bitrate are present
        if pkt.haslayer(RadioTap):
            signal_strengths.append(pkt.dBm_AntSignal)
            bitrates.append(pkt.Rate)
    except AttributeError:
        # Continue if any attributes are missing in the packet
        continue

# Compute average signal strength and bitrate if the lists are not empty
if signal_strengths and bitrates:
    average_signal_strength = np.mean(signal_strengths)
    average_bitrate = np.mean(bitrates)
    print(f"Average Signal Strength: {average_signal_strength} dBm")
    print(f"Average Bitrate: {average_bitrate} Mbps")
else:
    print("No relevant data found to compute averages.")
"""
"""
from scapy.all import *
import numpy as np

# MAC addresses for the devices
D1 = 'B4:B0:24:6D:DA:23'
D2 = 'BC:32:B2:8F:F9:75'

# Load packets from a pcap file
packets = rdpcap('first.pcap')
print(f"Total packets in file: {len(packets)}")

# Filter packets between D1 and D2
filtered_packets = [pkt for pkt in packets if (pkt.haslayer(Dot11) and 
                                               ((pkt.addr1 == D1 and pkt.addr2 == D2) or 
                                                (pkt.addr1 == D2 and pkt.addr2 == D1)))]
print(f"Filtered packets between D1 and D2: {len(filtered_packets)}")

# Initialize lists to hold signal strengths and bitrates
signal_strengths = []
bitrates = []

# Extract signal strength and bitrate
for pkt in filtered_packets:
    try:
        # Check for RadioTap layer where signal strength and bitrate are present
        if pkt.haslayer(RadioTap):
            signal_strengths.append(pkt.dBm_AntSignal)
            bitrates.append(pkt.Rate)
        else:
            print("RadioTap layer missing in a filtered packet.")
    except AttributeError as e:
        # Continue if any attributes are missing in the packet
        print(f"AttributeError for a packet: {e}")

# Compute average signal strength and bitrate if the lists are not empty
if signal_strengths and bitrates:
    average_signal_strength = np.mean(signal_strengths)
    average_bitrate = np.mean(bitrates)
    print(f"Average Signal Strength: {average_signal_strength} dBm")
    print(f"Average Bitrate: {average_bitrate} Mbps")
else:
    print("No relevant data found to compute averages.")
"""
"""
from scapy.all import *
import numpy as np

# MAC addresses for the devices
D1 = 'B4:B0:24:6D:DA:23'  # Access Point
D2 = 'BC:32:B2:8F:F9:75'  # Client

# Load packets from a pcap file
packets = rdpcap('first.pcap')
print(f"Total packets in file: {len(packets)}")

# Filter packets where D1 or D2 is involved
filtered_packets = [pkt for pkt in packets if pkt.haslayer(Dot11) and
                    (D1 in [pkt.addr1, pkt.addr2, pkt.addr3] or
                     D2 in [pkt.addr1, pkt.addr2, pkt.addr3])]
print(f"Filtered packets involving D1 and D2: {len(filtered_packets)}")

# Initialize lists to hold signal strengths and bitrates
signal_strengths = []
bitrates = []

# Extract signal strength and bitrate
for pkt in filtered_packets:
    try:
        # Check for RadioTap layer where signal strength and bitrate are present
        if pkt.haslayer(RadioTap):
            signal_strengths.append(pkt.dBm_AntSignal)
            bitrates.append(pkt.Rate)
    except AttributeError as e:
        # Continue if any attributes are missing in the packet
        print(f"AttributeError for a packet: {e}")

# Compute average signal strength and bitrate if the lists are not empty
if signal_strengths and bitrates:
    average_signal_strength = np.mean(signal_strengths)
    average_bitrate = np.mean(bitrates)
    print(f"Average Signal Strength: {average_signal_strength} dBm")
    print(f"Average Bitrate: {average_bitrate} Mbps")
else:
    print("No relevant data found to compute averages.")

"""
"""
from scapy.all import *
import numpy as np

# MAC addresses for the devices
D1 = 'B4:B0:24:6D:DA:23'  # Access Point
D2 = 'BC:32:B2:8F:F9:75'  # Client

# Load packets from a pcap file
packets = rdpcap('first.pcap')
print(f"Total packets in file: {len(packets)}")

# Filter packets where D1 or D2 is involved
filtered_packets = []
for pkt in packets:
    if pkt.haslayer(Dot11):
        # Print details from the first few packets for debugging
        if len(filtered_packets) < 5:
            print(f"Addresses in packet: {pkt.addr1}, {pkt.addr2}, {pkt.addr3}")
        if D1 in [pkt.addr1, pkt.addr2, pkt.addr3] or D2 in [pkt.addr1, pkt.addr2, pkt.addr3]:
            filtered_packets.append(pkt)

print(f"Filtered packets involving D1 and D2: {len(filtered_packets)}")

# Initialize lists to hold signal strengths and bitrates
signal_strengths = []
bitrates = []

# Extract signal strength and bitrate
for pkt in filtered_packets:
    try:
        # Check for RadioTap layer where signal strength and bitrate are present
        if pkt.haslayer(RadioTap):
            signal_strengths.append(pkt.dBm_AntSignal)
            bitrates.append(pkt.Rate)
    except AttributeError as e:
        # Continue if any attributes are missing in the packet
        print(f"AttributeError for a packet: {e}")

# Compute average signal strength and bitrate if the lists are not empty
if signal_strengths and bitrates:
    average_signal_strength = np.mean(signal_strengths)
    average_bitrate = np.mean(bitrates)
    print(f"Average Signal Strength: {average_signal_strength} dBm")
    print(f"Average Bitrate: {average_bitrate} Mbps")
else:
    print("No relevant data found to compute averages.")
"""


from scapy.all import *
import numpy as np

# MAC addresses for the devices
D1 = 'aa:ba:69:94:d7:95'  # Access Point
D2 = 'bc:32:b2:8f:f9:75'  # Client

# Load packets from a pcap file
packets = rdpcap('two.pcap')
print(f"Total packets in file: {len(packets)}")
# print("Printing the first few packets for debugging\n")
# Filter packets where D1 or D2 is involved
filtered_packets = []
for pkt in packets:
    if pkt.haslayer(Dot11):
        # Print details from the first few packets for debugging
        # print("Printing the first few packets for debugging\n")
        # if len(filtered_packets) < 1:
            # print(f"Addresses in packet: {pkt.addr1}, {pkt.addr2}, {pkt.addr3}")

        # if D1 in [pkt.addr1, pkt.addr2, pkt.addr3] or D2 in [pkt.addr1, pkt.addr2, pkt.addr3]:

        if (pkt.addr1 == D1 and pkt.addr2 == D2) or \
               (pkt.addr1 == D2 and pkt.addr2 == D1):

            filtered_packets.append(pkt)
print()
print(f"Filtered packets involving D1 and D2: {len(filtered_packets)}")

# Initialize lists to hold signal strengths and bitrates
signal_strengths = []
bitrates = []

for pkt in filtered_packets:
    try:
        # Check for RadioTap layer where signal strength and bitrate are present
        if pkt.haslayer(RadioTap):
            # Only add signal strength if it's not None
            if pkt.dBm_AntSignal is not None:
                signal_strengths.append(pkt.dBm_AntSignal)
            # Only add bitrate if it's not None
            if pkt.Rate is not None:
                bitrates.append(pkt.Rate)
        else:
            print("RadioTap layer missing in a filtered packet.")
    except AttributeError as e:
        # Continue if any attributes are missing in the packet
        print(f"AttributeError for a packet: {e}")

# Compute average signal strength and bitrate if the lists are not empty
if signal_strengths and bitrates:
    average_signal_strength = np.mean(signal_strengths)
    average_bitrate = np.mean(bitrates)
    print(f"Average Signal Strength: {average_signal_strength} dBm")
    print(f"Average Bitrate: {average_bitrate} Mbps")
else:
    print("No relevant data found to compute averages.")


"""
# Extract signal strength and bitrate
for pkt in filtered_packets:
    try:
        # Check for RadioTap layer where signal strength and bitrate are present
        if pkt.haslayer(RadioTap):
            signal_strengths.append(pkt.dBm_AntSignal)
            bitrates.append(pkt.Rate)
    except AttributeError as e:
        # Continue if any attributes are missing in the packet
        print(f"AttributeError for a packet: {e}")

# Compute average signal strength and bitrate if the lists are not empty
if signal_strengths and bitrates:
    average_signal_strength = np.mean(signal_strengths)
    average_bitrate = np.mean(bitrates)
    print(f"Average Signal Strength: {average_signal_strength} dBm")
    print(f"Average Bitrate: {average_bitrate} Mbps")
else:
    print("No relevant data found to compute averages.")
"""
