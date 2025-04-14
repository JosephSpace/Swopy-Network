import nmap  # I’m using the Nmap library for network scanning
import scapy.all as scapy  # I’m using Scapy to analyze network packets and perform ARP scans
import time  # I need the time module for animations and delays
import subprocess  # I use this to run system commands (like netsh)
import re  # I need this for working with regular expressions to process text
import socket  # I use socket for working with network interfaces and IP info
from colorama import Fore, Style, init  # I’m using Colorama for colored terminal output, and Style for bright colors
import signal  # I use this to handle Ctrl+C for a graceful exit
import sys  # I need this to exit the system or handle program termination
import json  # I use JSON to save scan results in a structured format
from datetime import datetime  # I need this to get date and time info
import speedtest  # I’m using the Speedtest library to test internet speed
import manuf  # I use manuf to get vendor info from MAC addresses
import platform  # I need this to get operating system information
import os  # I use this for file operations
import psutil  # I’m using psutil to list network interfaces, it helps with cross-platform support

# I’m initializing Colorama so colored output works in the terminal
init()

# I’m creating an Nmap scanner object, I’ll use this for network scans
nm = nmap.PortScanner()

# I’m creating a manuf object to get vendor info from MAC addresses
mac_db = manuf.MacParser()

# I wrote a signal handler to gracefully exit the program when Ctrl+C is pressed
def signal_handler(sig, frame):
    print(Fore.MAGENTA + Style.BRIGHT + "\n\n[*] Exiting...")
    print(Fore.GREEN + Style.BRIGHT + "Thank you! Developed by JosephSpace (SW).")
    print(Fore.CYAN + Style.BRIGHT + "See you! 😊")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# I created a simple loading animation to show the user that something is happening
def loading_animation(message="Loading", duration=2):
    # I’m using these characters for a spinning animation
    spinner = "|/-\\"
    start_time = time.time()
    while time.time() - start_time < duration:
        for char in spinner:
            sys.stdout.write(f"\r{Fore.YELLOW + Style.BRIGHT}[{char}] {message}...{Style.RESET_ALL}")
            sys.stdout.flush()
            time.sleep(0.1)
    print()

# I added a nice transition animation when switching between menus
def transition_animation():
    width = 50  # I set the width of the animation
    for i in range(width + 1):
        sys.stdout.write(f"\r{Fore.CYAN + Style.BRIGHT}{'=' * i}{Style.RESET_ALL}" + " " * (width - i))
        sys.stdout.flush()
        time.sleep(0.02)
    print()

# I made a typing effect to display text character by character, it looks cooler
def type_effect(text, delay=0.03):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

# I wrote this function to wait for the user to press 'S' to return to the main menu
def wait_for_return():
    while True:
        choice = input(Fore.YELLOW + Style.BRIGHT + "\nPress S to return to the main menu: ").upper()
        if choice == "S":
            transition_animation()
            break

# 1. Comprehensive Network Scan (ARP, Nmap TCP/UDP, Scripts)
def network_scan(ip_range):
    print(Fore.YELLOW + Style.BRIGHT + "[*] Starting comprehensive network scan...")
    loading_animation("Initializing Network Scan", 2)
    
    # I’m using Scapy to perform an ARP scan to find devices on the network
    print(Fore.CYAN + Style.BRIGHT + "[*] Performing ARP scan with Scapy...")
    devices = []
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]

        for element in answered_list:
            device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            devices.append(device)
            vendor = mac_db.get_manuf(device['mac']) or "Unknown"
            print(Fore.GREEN + Style.BRIGHT + f"[+] Device: IP: {device['ip']}, MAC: {device['mac']}, Vendor: {vendor}")
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[-] Error during Scapy ARP scan: {e}")
        print(Fore.YELLOW + Style.BRIGHT + "[!] Ensure you have sufficient permissions (run as admin on Windows).")

    # I’m doing a ping scan with Nmap to find active devices
    print(Fore.CYAN + Style.BRIGHT + "[*] Performing ping scan with Nmap...")
    loading_animation("Running Nmap Ping Scan", 1)
    try:
        nm.scan(hosts=ip_range, arguments='-sn')
        for host in nm.all_hosts():
            print(Fore.GREEN + Style.BRIGHT + f"[+] Device found: {host}")
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[-] Error during Nmap ping scan: {e}")
        wait_for_return()
        return devices

    # I’m performing a detailed TCP port scan with Nmap to find open ports and services
    print(Fore.CYAN + Style.BRIGHT + "[*] Performing detailed TCP port scan with Nmap...")
    loading_animation("Scanning TCP Ports", 1)
    for host in nm.all_hosts():
        try:
            nm.scan(hosts=host, arguments='-p- --open -sV')
            print(Fore.YELLOW + Style.BRIGHT + f"\n[+] Device: {host}")
            if host in nm._scan_result.get('scan', {}):
                if 'tcp' in nm[host]:
                    for port in nm[host].all_tcp():
                        service = nm[host]['tcp'][port]['name']
                        state = nm[host]['tcp'][port]['state']
                        print(Fore.GREEN + Style.BRIGHT + f"    TCP Port: {port}, State: {state}, Service: {service}")
                else:
                    print(Fore.RED + Style.BRIGHT + f"[-] No open TCP ports found for {host}")
            else:
                print(Fore.RED + Style.BRIGHT + f"[-] Host {host} not found in TCP scan results")
        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f"[-] Error scanning host {host}: {e}")

    # I’m doing a UDP port scan with Nmap to check for open UDP ports
    print(Fore.CYAN + Style.BRIGHT + "[*] Performing UDP port scan with Nmap...")
    loading_animation("Scanning UDP Ports", 1)
    for host in nm.all_hosts():
        try:
            nm.scan(hosts=host, arguments='-sU -p1-1000 --open')
            print(Fore.YELLOW + Style.BRIGHT + f"\n[+] Device: {host}")
            if host in nm._scan_result.get('scan', {}):
                if 'udp' in nm[host]:
                    for port in nm[host].all_udp():
                        service = nm[host]['udp'][port]['name']
                        state = nm[host]['udp'][port]['state']
                        print(Fore.GREEN + Style.BRIGHT + f"    UDP Port: {port}, State: {state}, Service: {service}")
                else:
                    print(Fore.RED + Style.BRIGHT + f"[-] No open UDP ports found for {host}")
            else:
                print(Fore.RED + Style.BRIGHT + f"[-] Host {host} not found in UDP scan results")
        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f"[-] Error scanning host {host}: {e}")

    # I’m using Nmap scripts to scan for vulnerabilities and grab banners
    print(Fore.CYAN + Style.BRIGHT + "[*] Performing Nmap script scan for vulnerabilities...")
    loading_animation("Running Vulnerability Scan", 1)
    for host in nm.all_hosts():
        try:
            nm.scan(hosts=host, arguments='--script=vuln,banner')
            print(Fore.YELLOW + Style.BRIGHT + f"\n[+] Device: {host}")
            if 'script' in nm[host]:
                for script, output in nm[host]['script'].items():
                    print(Fore.GREEN + Style.BRIGHT + f"    Script: {script}")
                    print(Fore.CYAN + Style.BRIGHT + f"    Output: {output}")
            else:
                print(Fore.RED + Style.BRIGHT + f"[-] No script scan results for {host}")
        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f"[-] Error during script scan for {host}: {e}")

    wait_for_return()
    return devices

# 2. Network Device Detection
def network_device_detection(ip_range):
    print(Fore.YELLOW + Style.BRIGHT + "[*] Starting network device detection...")
    loading_animation("Detecting Devices", 2)
    devices = []
    
    # I’m using Scapy to perform an ARP scan to find devices on the network
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]

        for element in answered_list:
            device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            devices.append(device)
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[-] Error during Scapy ARP scan: {e}")

    # I’m using Nmap to detect device types (e.g., what operating system they’re running)
    print(Fore.CYAN + Style.BRIGHT + "[*] Performing device detection with Nmap...")
    loading_animation("Analyzing Device Types", 1)
    try:
        nm.scan(hosts=ip_range, arguments='-O --osscan-guess')
        for host in nm.all_hosts():
            if host in nm._scan_result.get('scan', {}):
                os_info = nm[host].get('osmatch', [])
                device_type = "Unknown"
                if os_info:
                    device_type = os_info[0].get('name', 'Unknown')
                print(Fore.GREEN + Style.BRIGHT + f"[+] Device: IP: {host}, Type: {device_type}")
                for device in devices:
                    if device['ip'] == host:
                        vendor = mac_db.get_manuf(device['mac']) or "Unknown"
                        print(Fore.CYAN + Style.BRIGHT + f"    MAC: {device['mac']}, Vendor: {vendor}")
                        try:
                            nm.scan(hosts=host, arguments='-p1-100 --open')
                            if 'tcp' in nm[host]:
                                print(Fore.CYAN + Style.BRIGHT + f"    Open Ports: {[port for port in nm[host].all_tcp()]}")
                        except:
                            pass
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[-] Error during device detection: {e}")

    wait_for_return()

# 3. Network Speed Test
def network_speed_test():
    print(Fore.YELLOW + Style.BRIGHT + "[*] Starting network speed test...")
    loading_animation("Connecting to Speed Test Server", 2)
    try:
        # I’m using the Speedtest library to measure internet speed
        st = speedtest.Speedtest()
        st.get_best_server()
        print(Fore.CYAN + Style.BRIGHT + "[*] Measuring download speed...")
        download_speed = st.download() / 1_000_000  # I’m converting bits to Mbps
        print(Fore.CYAN + Style.BRIGHT + "[*] Measuring upload speed...")
        upload_speed = st.upload() / 1_000_000
        ping = st.results.ping

        print(Fore.GREEN + Style.BRIGHT + f"[+] Download Speed: {download_speed:.2f} Mbps")
        print(Fore.GREEN + Style.BRIGHT + f"[+] Upload Speed: {upload_speed:.2f} Mbps")
        print(Fore.GREEN + Style.BRIGHT + f"[+] Ping: {ping:.2f} ms")
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[-] Could not perform speed test: {e}")
    
    wait_for_return()

# 4. Network Live Log Capture
def network_live_log_capture():
    print(Fore.YELLOW + Style.BRIGHT + "[*] Starting live network log capture...")
    print(Fore.RED + Style.BRIGHT + "[!] WARNING: This tool should only be used on networks you own or have explicit permission to monitor.")

    # I’m listing the network interfaces that the user can choose from
    interfaces = get_network_interfaces()
    if not interfaces:
        print(Fore.RED + Style.BRIGHT + "[-] No network interfaces found. Please ensure your system has active network interfaces.")
        wait_for_return()
        return

    print(Fore.CYAN + Style.BRIGHT + "[*] Available network interfaces:")
    for idx, iface in enumerate(interfaces, 1):
        print(Fore.CYAN + Style.BRIGHT + f"    {idx}. {iface}")

    # I’m asking the user to select a network interface
    try:
        choice = int(input(Fore.WHITE + Style.BRIGHT + "\nSelect a network interface to monitor (1-{}): ".format(len(interfaces))))
        if choice < 1 or choice > len(interfaces):
            print(Fore.RED + Style.BRIGHT + "[-] Invalid choice!")
            wait_for_return()
            return
    except ValueError:
        print(Fore.RED + Style.BRIGHT + "[-] Invalid input! Please enter a number.")
        wait_for_return()
        return

    selected_iface = interfaces[choice - 1]
    print(Fore.YELLOW + Style.BRIGHT + f"\n[*] Selected interface: {selected_iface}")

    # I’m asking the user how long they want to capture logs for
    try:
        duration = int(input(Fore.WHITE + Style.BRIGHT + "Enter the duration to capture logs (in seconds, e.g., 60): "))
        if duration <= 0:
            print(Fore.RED + Style.BRIGHT + "[-] Duration must be a positive number!")
            wait_for_return()
            return
    except ValueError:
        print(Fore.RED + Style.BRIGHT + "[-] Invalid input! Please enter a number.")
        wait_for_return()
        return

    print(Fore.YELLOW + Style.BRIGHT + f"[*] Capturing network logs for {duration} seconds... Press Ctrl+C to stop early.")
    loading_animation("Starting Packet Capture", 1)

    logs = []

    # I wrote a function to process incoming packets
    def packet_handler(packet):
        log_entry = {}
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if packet.haslayer(scapy.IP):
            log_entry["Timestamp"] = timestamp
            log_entry["Source IP"] = packet[scapy.IP].src
            log_entry["Destination IP"] = packet[scapy.IP].dst
            log_entry["Protocol"] = packet[scapy.IP].proto

            if packet.haslayer(scapy.TCP):
                log_entry["Protocol Name"] = "TCP"
                log_entry["Source Port"] = packet[scapy.TCP].sport
                log_entry["Destination Port"] = packet[scapy.TCP].dport
                if packet.haslayer(scapy.Raw) and packet[scapy.TCP].dport == 80:
                    raw_data = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                    if "GET" in raw_data or "POST" in raw_data:
                        log_entry["HTTP Request"] = raw_data.split('\n')[0]
            elif packet.haslayer(scapy.UDP):
                log_entry["Protocol Name"] = "UDP"
                log_entry["Source Port"] = packet[scapy.UDP].sport
                log_entry["Destination Port"] = packet[scapy.UDP].dport
                if packet.haslayer(scapy.DNS):
                    dns = packet[scapy.DNS]
                    if dns.qr == 0:
                        log_entry["DNS Query"] = dns.qd.qname.decode('utf-8', errors='ignore')
            else:
                log_entry["Protocol Name"] = "Other"
                log_entry["Source Port"] = "N/A"
                log_entry["Destination Port"] = "N/A"

            print(Fore.GREEN + Style.BRIGHT + f"[+] {timestamp} | {log_entry['Source IP']}:{log_entry['Source Port']} -> "
                  f"{log_entry['Destination IP']}:{log_entry['Destination Port']} | "
                  f"Protocol: {log_entry['Protocol Name']}")
            if "HTTP Request" in log_entry:
                print(Fore.CYAN + Style.BRIGHT + f"    HTTP: {log_entry['HTTP Request']}")
            if "DNS Query" in log_entry:
                print(Fore.CYAN + Style.BRIGHT + f"    DNS Query: {log_entry['DNS Query']}")

            logs.append(log_entry)

    # I’m capturing packets for the specified duration
    try:
        scapy.sniff(iface=selected_iface, prn=packet_handler, timeout=duration)
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[-] Error capturing packets: {e}")
        print(Fore.YELLOW + Style.BRIGHT + "[!] Ensure you have sufficient permissions (run as admin on Windows).")
        wait_for_return()
        return

    print(Fore.YELLOW + Style.BRIGHT + f"\n[*] Captured {len(logs)} packets.")
    if logs:
        print(Fore.GREEN + Style.BRIGHT + "[+] Summary of captured logs:")
        for log in logs:
            print(Fore.CYAN + Style.BRIGHT + f"    {log['Timestamp']} | {log['Source IP']}:{log['Source Port']} -> "
                  f"{log['Destination IP']}:{log['Destination Port']} | "
                  f"Protocol: {log['Protocol Name']}")
            if "HTTP Request" in log:
                print(Fore.CYAN + Style.BRIGHT + f"        HTTP: {log['HTTP Request']}")
            if "DNS Query" in log:
                print(Fore.CYAN + Style.BRIGHT + f"        DNS Query: {log['DNS Query']}")

        # I’m saving the captured logs to a JSON file
        filename = f"network_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(logs, f, ensure_ascii=False, indent=4)
            print(Fore.GREEN + Style.BRIGHT + f"[+] Logs saved to '{filename}'.")
        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f"[-] Error saving logs: {e}")

    wait_for_return()

# 5. Network Traffic Analysis
def network_traffic_analysis():
    print(Fore.YELLOW + Style.BRIGHT + "[*] Starting network traffic analysis...")
    print(Fore.CYAN + Style.BRIGHT + "[*] Capturing packets for 10 seconds... Press Ctrl+C to stop early.")

    # I’m listing the network interfaces
    interfaces = get_network_interfaces()
    if not interfaces:
        print(Fore.RED + Style.BRIGHT + "[-] No network interfaces found. Please ensure your system has active network interfaces.")
        wait_for_return()
        return

    try:
        choice = int(input(Fore.WHITE + Style.BRIGHT + "\nSelect a network interface to monitor (1-{}): ".format(len(interfaces))))
        if choice < 1 or choice > len(interfaces):
            print(Fore.RED + Style.BRIGHT + "[-] Invalid choice!")
            wait_for_return()
            return
    except ValueError:
        print(Fore.RED + Style.BRIGHT + "[-] Invalid input! Please enter a number.")
        wait_for_return()
        return

    selected_iface = interfaces[choice - 1]
    print(Fore.YELLOW + Style.BRIGHT + f"\n[*] Selected interface: {selected_iface}")
    loading_animation("Starting Traffic Analysis", 1)

    # I’m capturing packets for 10 seconds and analyzing them
    try:
        packets = scapy.sniff(iface=selected_iface, timeout=10)
        print(Fore.GREEN + Style.BRIGHT + f"[+] Captured {len(packets)} packets.")
        
        protocols = {}
        total_bytes = 0
        suspicious = []

        for packet in packets:
            if packet.haslayer(scapy.IP):
                proto = packet[scapy.IP].proto
                protocols[proto] = protocols.get(proto, 0) + 1
                packet_size = len(packet)
                total_bytes += packet_size

                # I’m checking for suspicious activities (like SYN floods)
                if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == "S":
                    if protocols.get(proto, 0) > 50:
                        suspicious.append(f"SYN Flood detected from {packet[scapy.IP].src}")

        print(Fore.YELLOW + Style.BRIGHT + "[*] Protocol Distribution:")
        for proto, count in protocols.items():
            proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"Other ({proto})")
            print(Fore.CYAN + Style.BRIGHT + f"    {proto_name}: {count} packets")

        print(Fore.YELLOW + Style.BRIGHT + "[*] Total Data Transferred:")
        print(Fore.CYAN + Style.BRIGHT + f"    {total_bytes / 1024:.2f} KB")

        if suspicious:
            print(Fore.RED + Style.BRIGHT + "[!] Suspicious Activities Detected:")
            for activity in suspicious:
                print(Fore.RED + Style.BRIGHT + f"    - {activity}")
        else:
            print(Fore.GREEN + Style.BRIGHT + "[+] No suspicious activities detected.")

    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[-] Could not capture packets: {e}")
        print(Fore.YELLOW + Style.BRIGHT + "[!] Ensure you have sufficient permissions.")
    
    wait_for_return()

# 6. Network Interface Information
def network_interface_info():
    print(Fore.YELLOW + Style.BRIGHT + "[*] Starting network interface analysis...")
    loading_animation("Gathering Interface Info", 2)

    # I’m listing the network interfaces on the system
    interfaces = get_network_interfaces()
    if not interfaces:
        print(Fore.RED + Style.BRIGHT + "[-] No network interfaces found. Please ensure your system has active network interfaces.")
        wait_for_return()
        return

    for iface in interfaces:
        print(Fore.GREEN + Style.BRIGHT + f"[+] Interface: {iface}")
        try:
            addrs = psutil.net_if_addrs().get(iface, [])
            ip_addr = "Unknown"
            mac_addr = "Unknown"
            for addr in addrs:
                if addr.family == socket.AF_INET:  # I’m finding the IPv4 address
                    ip_addr = addr.address
                elif addr.family == psutil.AF_LINK:  # I’m finding the MAC address
                    mac_addr = addr.address
            print(Fore.CYAN + Style.BRIGHT + f"    IP: {ip_addr}")
            print(Fore.CYAN + Style.BRIGHT + f"    MAC: {mac_addr}")
        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f"[-] Could not fetch details for {iface}: {e}")

    wait_for_return()

# 7. Network Topology Mapping
def network_topology_mapping(ip_range):
    print(Fore.YELLOW + Style.BRIGHT + "[*] Starting network topology mapping...")
    loading_animation("Mapping Network Topology", 2)
    devices = []

    # I’m using Scapy to perform an ARP scan to find devices on the network
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]

        for element in answered_list:
            device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            devices.append(device)
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[-] Error during Scapy ARP scan: {e}")
        print(Fore.YELLOW + Style.BRIGHT + "[!] Ensure you have sufficient permissions.")

    # I’m drawing a simple network topology map
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Network Topology Map:")
    print(Fore.CYAN + Style.BRIGHT + "    +-------------------+")
    print(Fore.CYAN + Style.BRIGHT + "    |   Local Machine   |")
    print(Fore.CYAN + Style.BRIGHT + "    +-------------------+")
    for device in devices:
        vendor = mac_db.get_manuf(device['mac']) or "Unknown"
        ip_label = f"{device['ip']} ({vendor})"
        print(Fore.CYAN + Style.BRIGHT + "          |")
        print(Fore.CYAN + Style.BRIGHT + f"          +--> {ip_label}")
        print(Fore.CYAN + Style.BRIGHT + f"                MAC: {device['mac']}")

    # I’m saving the topology to a JSON file
    topology_data = {
        "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "devices": [
            {
                "ip": device['ip'],
                "mac": device['mac'],
                "vendor": mac_db.get_manuf(device['mac']) or "Unknown"
            } for device in devices
        ]
    }
    filename = f"topology_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(topology_data, f, ensure_ascii=False, indent=4)
        print(Fore.GREEN + Style.BRIGHT + f"[+] Topology saved to '{filename}'.")
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[-] Error saving topology: {e}")

    wait_for_return()

# 8. Phone Device Scanner
def phone_device_scanner(ip_range):
    print(Fore.YELLOW + Style.BRIGHT + "[*] Starting phone device scanner...")
    loading_animation("Scanning for Phone Devices", 2)
    devices = []
    
    # I’m using Scapy to perform an ARP scan to find devices on the network
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]

        for element in answered_list:
            device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            devices.append(device)
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[-] Error during Scapy ARP scan: {e}")

    # I’m using Nmap to scan devices and check if they’re phones
    print(Fore.CYAN + Style.BRIGHT + "[*] Scanning for phone devices with Nmap...")
    phone_devices = []
    for device in devices:
        host = device['ip']
        try:
            nm.scan(hosts=host, arguments='-O --osscan-guess')
            if host in nm._scan_result.get('scan', {}):
                os_info = nm[host].get('osmatch', [])
                device_type = "Unknown"
                if os_info:
                    device_type = os_info[0].get('name', 'Unknown')
                # I’m using some keywords to detect phones
                if any(keyword in device_type.lower() for keyword in ["android", "ios", "mobile", "phone"]) or "xiaomi" in (mac_db.get_manuf(device['mac']) or "").lower():
                    phone_devices.append({
                        "ip": host,
                        "mac": device['mac'],
                        "type": device_type,
                        "vendor": mac_db.get_manuf(device['mac']) or "Unknown"
                    })
                    print(Fore.GREEN + Style.BRIGHT + f"[+] Phone Device: IP: {host}, Type: {device_type}, MAC: {device['mac']}, Vendor: {phone_devices[-1]['vendor']}")
                    
                    print(Fore.CYAN + Style.BRIGHT + f"[*] Scanning ports for {host}...")
                    loading_animation("Port Scanning", 1)
                    nm.scan(hosts=host, arguments='-p1-1000,5228,62078 --open -sV')
                    if 'tcp' in nm[host]:
                        print(Fore.CYAN + Style.BRIGHT + "    Open TCP Ports:")
                        for port in nm[host].all_tcp():
                            service = nm[host]['tcp'][port]['name']
                            state = nm[host]['tcp'][port]['state']
                            print(Fore.CYAN + Style.BRIGHT + f"        Port: {port}, State: {state}, Service: {service}")
                    if 'udp' in nm[host]:
                        print(Fore.CYAN + Style.BRIGHT + "    Open UDP Ports:")
                        for port in nm[host].all_udp():
                            service = nm[host]['udp'][port]['name']
                            state = nm[host]['udp'][port]['state']
                            print(Fore.CYAN + Style.BRIGHT + f"        Port: {port}, State: {state}, Service: {service}")
                    
                    print(Fore.CYAN + Style.BRIGHT + f"[*] Capturing traffic for {host}...")
                    loading_animation("Capturing Traffic", 1)
                    try:
                        packets = scapy.sniff(iface=get_default_interface(), filter=f"host {host}", timeout=10)
                        for pkt in packets:
                            if pkt.haslayer(scapy.Raw) and pkt.haslayer(scapy.TCP) and pkt[scapy.TCP].dport == 80:
                                raw_data = pkt[scapy.Raw].load.decode('utf-8', errors='ignore')
                                if "GET" in raw_data or "POST" in raw_data:
                                    print(Fore.CYAN + Style.BRIGHT + f"    HTTP: {raw_data.split('\n')[0]}")
                            elif pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qr == 0:
                                print(Fore.CYAN + Style.BRIGHT + f"    DNS Query: {pkt[scapy.DNS].qd.qname.decode('utf-8', errors='ignore')}")
                    except:
                        print(Fore.RED + Style.BRIGHT + f"[-] Error capturing traffic for {host}")
        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f"[-] Error scanning {host}: {e}")

    if phone_devices:
        print(Fore.GREEN + Style.BRIGHT + f"\n[+] Found {len(phone_devices)} phone devices:")
        for dev in phone_devices:
            print(Fore.CYAN + Style.BRIGHT + f"    IP: {dev['ip']}, Type: {dev['type']}, MAC: {dev['mac']}, Vendor: {dev['vendor']}")
    else:
        print(Fore.RED + Style.BRIGHT + "[-] No phone devices detected.")

    # I’m saving the detected phone devices to a JSON file
    if phone_devices:
        filename = f"phone_devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(phone_devices, f, ensure_ascii=False, indent=4)
            print(Fore.GREEN + Style.BRIGHT + f"[+] Phone devices saved to '{filename}'.")
        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f"[-] Error saving phone devices: {e}")

    wait_for_return()

# Helper Function: I’m finding the default network interface
def get_default_interface():
    try:
        interfaces = psutil.net_if_stats()
        for iface, stats in interfaces.items():
            if stats.isup and stats.speed > 0:
                addrs = psutil.net_if_addrs().get(iface, [])
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        return iface
        print(Fore.RED + Style.BRIGHT + "[-] No active network interface with an IPv4 address found.")
        return None
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[-] Error detecting default interface: {e}")
        return None

# Helper Function: I’m listing the network interfaces on the system
def get_network_interfaces():
    try:
        interfaces = list(psutil.net_if_addrs().keys())
        interfaces = [iface for iface in interfaces if not iface.lower().startswith('lo')]
        return interfaces
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[-] Error listing interfaces: {e}")
        return []

# I wrote a function to run all modules at once
def run_all_modules(ip_range, devices):
    network_scan(ip_range)
    network_device_detection(ip_range)
    network_speed_test()
    network_live_log_capture()
    network_traffic_analysis()
    network_interface_info()
    network_topology_mapping(ip_range)
    phone_device_scanner(ip_range)

# I designed a banner to display at the start of the program
def draw_banner():
    banner = r"""
  _____ __          __  ____   _____  __     __
 / ____|\ \        / / / __ \ |  __ \ \ \   / /
| (___   \ \  /\  / / | |  | || |__) | \ \_/ /
 \___ \   \ \/  \/ /  | |  | ||  ___/   \   / 
 ____) |   \  /\  /   | |__| || |        | |  
|_____/     \/  \/     \____/ |_|        |_|  
    """
    type_effect(Fore.MAGENTA + Style.BRIGHT + banner, delay=0.01)
    print(Fore.YELLOW + Style.BRIGHT + "Version: 1.2")
    print(Fore.WHITE + Style.BRIGHT + "[!] Tool Created by JosephSpace (SW)")
    print(Fore.WHITE + Style.BRIGHT + "[!] GitHub: https://github.com/JosephSpace")
    transition_animation()

# Main Menu
def main_menu():
    print(Fore.YELLOW + Style.BRIGHT + "[*] Note: Run this tool with administrator privileges for best results.")
    loading_animation("Starting Swopy Network Tool", 3)
    # I’m asking the user for the IP range they want to scan
    ip_range = input(Fore.WHITE + Style.BRIGHT + "Please enter the IP range to scan (e.g., 192.168.1.0/24): ")
    if not ip_range:
        print(Fore.RED + Style.BRIGHT + "[-] IP range not specified. Using default range (192.168.1.0/24).")
        ip_range = "192.168.1.0/24"

    print(Fore.YELLOW + Style.BRIGHT + "[*] Performing initial scan...")
    loading_animation("Initial Scan in Progress", 2)
    devices = []
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]

        for element in answered_list:
            device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            devices.append(device)
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[-] Error during initial scan: {e}")

    # I’m showing the user a menu and running the option they choose
    while True:
        draw_banner()
        print(Fore.YELLOW + Style.BRIGHT + "\n[+] Select An Option For Network Analysis [::]")
        print()

        options = [
            ("01", "Network Scan"),
            ("02", "Network Device Detection"),
            ("03", "Network Speed Test"),
            ("04", "Network Live Log Capture"),
            ("05", "Network Traffic Analysis"),
            ("06", "Network Interface Info"),
            ("07", "Network Topology Mapping"),
            ("08", "Phone Device Scanner"),
            ("99", "Run All Modules"),
            ("50", "About"),
            ("00", "Exit")
        ]

        for i in range(0, len(options), 3):
            row = options[i:i+3]
            line = ""
            for opt in row:
                line += f"{Fore.GREEN + Style.BRIGHT}[{opt[0]}] {Fore.WHITE + Style.BRIGHT}{opt[1]:<25} "
            print(line)

        choice = input(Fore.RED + Style.BRIGHT + "\nSwopy> ")
        transition_animation()

        if choice == "00":
            print(Fore.MAGENTA + Style.BRIGHT + "[*] Exiting program...")
            print(Fore.GREEN + Style.BRIGHT + "Thank you! Developed by JosephSpace (SW).")
            print(Fore.CYAN + Style.BRIGHT + "See you! 😊")
            break
        elif choice == "50":
            print(Fore.CYAN + Style.BRIGHT + "\n[+] About Swopi Troi Network")
            print(Fore.YELLOW + Style.BRIGHT + "    Version: 1.2")
            print(Fore.GREEN + Style.BRIGHT + "    Authors: JosephSpace (SW)")
            print(Fore.GREEN + Style.BRIGHT + "    Description: A comprehensive network analysis tool using pure Python libraries.")
            wait_for_return()
        elif choice == "99":
            run_all_modules(ip_range, devices)
        else:
            if choice == "01":
                network_scan(ip_range)
            elif choice == "02":
                network_device_detection(ip_range)
            elif choice == "03":
                network_speed_test()
            elif choice == "04":
                network_live_log_capture()
            elif choice == "05":
                network_traffic_analysis()
            elif choice == "06":
                network_interface_info()
            elif choice == "07":
                network_topology_mapping(ip_range)
            elif choice == "08":
                phone_device_scanner(ip_range)
            else:
                print(Fore.RED + Style.BRIGHT + f"[-] Invalid choice: {choice}")
                wait_for_return()

if __name__ == "__main__":
    main_menu()