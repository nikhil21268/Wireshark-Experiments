import pandas as pd
import matplotlib.pyplot as plt

# Load the data
data = pd.read_csv('wireless_moving_data.csv')

# Convert signal level to numeric values for plotting
data['Signal Level'] = pd.to_numeric(data['Signal Level'], errors='coerce')

# Plotting
plt.figure(figsize=(10, 5))
plt.plot(data['Time'], data['Signal Level'], label='Signal Strength')
# plt.plot(data['Time'], data['Bit Rate'], label='Bit Rate', linestyle='--')
plt.xlabel('Time')
plt.ylabel('Signal Strength (dBm)')
plt.title('Signal Strength Over Time')
plt.legend()
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Plotting
plt.figure(figsize=(10, 5))
# plt.plot(data['Time'], data['Signal Level'], label='Signal Strength')
plt.plot(data['Time'], data['Bit Rate'], label='Bit Rate', linestyle='--')
plt.xlabel('Time')
plt.ylabel('Bit Rate (Mbps)')
plt.title('Bit Rate Over Time')
plt.legend()
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()



