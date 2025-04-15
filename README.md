# Swopy Network Tool

![Swopy Network](https://img.shields.io/badge/Swopy-Network-blue)
![Version](https://img.shields.io/badge/Version-1.2-green)
![Python](https://img.shields.io/badge/Python-3.6%2B-yellow)
![License](https://img.shields.io/badge/License-Open%20Source-brightgreen)
![Ekran görüntüsü 2025-04-15 030524](https://github.com/user-attachments/assets/f9a53ef6-734f-47be-907f-504ff850005f)


## Overview

Swopy Network is a comprehensive network analysis and monitoring tool developed with Python. It offers various network-related functions including network scanning, device detection, traffic analysis, and more.

## Features

Swopy Network offers the following modules:

1. **Comprehensive Network Scanning** - Performs ARP, Nmap TCP/UDP, and script scans to identify devices and open ports on your network
2. **Network Device Detection** - Identifies devices on your network with detailed information about their types, manufacturers, and open ports
3. **Network Speed Test** - Measures your internet connection's download speed, upload speed, and ping time
4. **Network Live Log Capture** - Captures and records network traffic in real-time
5. **Network Traffic Analysis** - Analyzes network traffic patterns and detects suspicious activities
6. **Network Interface Information** - Provides detailed information about your network interfaces
7. **Network Topology Mapping** - Creates a visual map of your network's topology
8. **Phone Device Scanner** - Specifically detects and analyzes mobile devices on your network

## Installation
![ultra-ezgif com-video-to-gif-converter](https://github.com/user-attachments/assets/79fdb414-f6b3-492b-b3c0-12c40f89c209)
### Prerequisites

- Python 3.6 or higher version
- Administrator privileges (especially for Windows users)

### Required Python Packages

```
python-nmap
scapy
colorama
speedtest-cli
manuf
psutil
tabulate
```

### Installation Steps

1. Clone or download this repository:

```bash
git clone https://github.com/JosephSpace/Swopy-Wifi.git
cd Swopy-Wifi
```

2. **Recommended Method (Windows)**: Use the provided batch file for automatic setup:

```bash
run.bat
```

This batch file will:
- Check if Python is installed
- Install all required packages automatically
- Launch the Swopy Network application

3. **Alternative Method**: Manually install the required packages:

```bash
pip install python-nmap scapy colorama speedtest-cli manuf psutil tabulate
```

4. For Windows users, you may need to install Npcap (https://npcap.com/) for packet capture functionality

## Usage

Run the script with administrator privileges:

```bash
# Recommended method (Windows)
Right-click on run.bat and select "Run as administrator"

# Alternative method (Windows)
Right-click on Command Prompt or PowerShell and select "Run as administrator"
python swopy-network.py

# On Linux/macOS
sudo python swopy-network.py
```

When launched, you will be presented with an options menu:

```
[01] Network Scanning          [02] Network Device Detection   [03] Network Speed Test      
[04] Network Live Log Capture   [05] Network Traffic Analysis   [06] Network Interface Information  
[07] Network Topology Mapping   [08] Phone Device Scanner       [99] Run All Modules         
[50] About                      [00] Exit                      
```

Select an option by entering the corresponding number.

## Module Descriptions

### 1. Network Scanning

Performs a comprehensive network scan using multiple techniques:
- ARP scanning to discover devices on the local network
- Nmap ping scan to verify host availability
- Detailed TCP port scan to identify open services
- UDP port scan to find UDP services
- Script scan to detect potential vulnerabilities

### 2. Network Device Detection

Detects and identifies devices on your network with information about:
- IP and MAC addresses
- Device type (based on OS fingerprinting)
- Manufacturer information (based on MAC address)
- Open ports

### 3. Network Speed Test

Measures the performance of your internet connection:
- Download speed (Mbps)
- Upload speed (Mbps)
- Ping (ms)

### 4. Network Live Log Capture

Captures and records network traffic in real-time:
- Monitors selected network interface
- Records packet information including source/destination IPs, ports, and protocols
- Captures HTTP requests and DNS queries
- Saves logs to a JSON file for later analysis

### 5. Network Traffic Analysis

Analyzes network traffic patterns:
- Captures packets for a specified duration
- Shows protocol distribution (TCP, UDP, ICMP, etc.)
- Calculates total data transferred
- Detects suspicious activities such as potential SYN flood attacks

### 6. Network Interface Information

Provides detailed information about your network interfaces:
- Lists all available interfaces
- Shows IP and MAC addresses
- Displays interface status and configuration

### 7. Network Topology Mapping

Creates a visual map of your network:
- Identifies all devices on the network
- Shows connections between devices
- Provides manufacturer information
- Saves topology data to a JSON file

### 8. Phone Device Scanner

Specifically detects and analyzes mobile devices on your network:
- Identifies smartphones and tablets
- Shows device details including manufacturer and operating system
- Scans for open ports on mobile devices
- Captures and analyzes traffic from mobile devices

## Output Files

Some modules create output files for later analysis:
- Network logs: `network_logs_YYYYMMDD_HHMMSS.json`
- Network topology: `topology_YYYYMMDD_HHMMSS.json`
- Phone devices: `phone_devices_YYYYMMDD_HHMMSS.json`

Example topology file content:
```json
{
    "scan_date": "2025-04-14 21:25:04",
    "devices": [
        {
            "ip": "192.168.1.1",
            "mac": "6c:e8:73:f1:74:08",
            "vendor": "Tp-LinkT"
        },
        {
            "ip": "192.168.1.105",
            "mac": "00:d4:9e:92:9e:ec",
            "vendor": "Unknown"
        }
    ]
}
```

## Notes

- This tool should only be used on networks that you own or have explicit permission to monitor
- Some features require administrator/root privileges
- Run with administrator privileges for best results
- Network scanning and monitoring operations may affect network traffic and can be detected by some security software

## Author

Developed by JosephSpace (SW)

GitHub: https://github.com/JosephSpace

## License

This project is made available under open source terms. Please use responsibly and only on networks you have permission to analyze.
