"""
WiFi Network Scanner (Passive)

This script uses the scapy library to perform passive scanning of nearby WiFi networks,
capturing beacon frames and printing out discovered SSIDs and their signal strengths.

Requirements:
- Linux OS with wireless card supporting monitor mode
- Run as root
- scapy installed: pip install scapy

Steps:
- Put your wireless interface into monitor mode
  (e.g., using `sudo airmon-ng start wlan0` or `sudo ip link set wlan0 down` and `iwconfig wlan0 mode monitor` etc.)
- Run this script as root: sudo python3 wifi_scanner.py

Note:
- This tool is for authorized, educational, and testing purposes only.
- Respect privacy and legal boundaries.
"""

from scapy.all import *
import sys
import os

# Dictionary to store networks found: {SSID: (BSSID, signal_strength)}
networks = {}

def packet_handler(packet):
    # Look for 802.11 beacon frames
    if packet.haslayer(Dot11Beacon):
        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
        bssid = packet[Dot11].addr3
        # Signal strength (dBm) from RadioTap header (if present)
        try:
            signal = packet.dBm_AntSignal
        except:
            signal = "N/A"
        if ssid not in networks:
            networks[ssid] = (bssid, signal)
            print(f"Discovered SSID: {ssid}, BSSID: {bssid}, Signal: {signal} dBm")

def main():
    if os.name != "nt":
        # On Linux, check for root
        if os.geteuid() != 0:
            print("Script must be run as root. Use sudo.")
            sys.exit(1)
    else:
        print("This script only works on Linux with monitor mode support.")
        sys.exit(1)

    iface = input("Enter your wireless interface (in monitor mode) (e.g. wlan0mon): ").strip()
    print(f"Starting WiFi scan on interface: {iface}")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(iface=iface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\nScan stopped by user.")
        print("\nSummary of discovered networks:")
        for ssid, (bssid, signal) in networks.items():
            print(f"SSID: {ssid}, BSSID: {bssid}, Signal: {signal} dBm")
        print("\nExiting.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
