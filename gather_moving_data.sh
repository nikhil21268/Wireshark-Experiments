#!/bin/bash

# This script assumes your wireless interface is named wlan0. Adjust if different.
INTERFACE="wlp0s20f3"


# Create a file to store your data
OUTPUT_FILE="wireless_moving_data.csv"
# echo "Time,SSID,BSSID,Signal Level,Bit Rate" > $OUTPUT_FILE
echo "Time,SSID,BSSID,Signal Level,Bit Rate,Transmission Power,Frequency Band" > $OUTPUT_FILE

# Collect data for 2 minutes (12 intervals of 10 seconds)
for i in {1..12}
do
    # Fetch wireless details
    SSID=$(iwconfig $INTERFACE | grep 'ESSID' | awk '{print $4}' | cut -d":" -f2)
    BSSID=$(iwconfig $INTERFACE | grep 'Access Point' | awk '{print $6}')
    SIGNAL_LEVEL=$(iwconfig $INTERFACE | grep 'Signal level' | awk '{print $4}' | cut -d"=" -f2)
    BIT_RATE=$(iwconfig $INTERFACE | grep 'Bit Rate' | awk '{print $2}' | cut -d"=" -f2)
    
    # Save to file
    # echo "$(date +%H:%M:%S),$SSID,$BSSID,$SIGNAL_LEVEL,$BIT_RATE" >> $OUTPUT_FILE
    
    # Placeholder: You might need to adjust these commands based on your system's capabilities
    TX_POWER=$(iw dev $INTERFACE info | grep 'txpower' | awk '{print $2}')
    FREQ_BAND=$(iw dev $INTERFACE info | grep 'channel' | awk '{print $2 " " $3}')  # Assumes channel and width might indicate band

    # Save to file
    echo "$(date +%H:%M:%S),$SSID,$BSSID,$SIGNAL_LEVEL,$BIT_RATE,$TX_POWER,$FREQ_BAND" >> $OUTPUT_FILE

    # Wait for 10 seconds
    sleep 10
done


