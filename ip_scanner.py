#This Program will Scan the IPv4 in your network
import os
import sys
import platform
import subprocess
import socket
import ipaddress

# --- NEW: Added requests for manufacturer lookup ---
try:
    import requests
except ImportError:
    print("[-] requests library not found. Installing now...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

try:
    import scapy.all as scapy
except ImportError:
    print("[-] Scapy not installed. Installing now...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
    import scapy.all as scapy


def is_admin():
    if os.name == "nt":  # Windows
        try:
            from ctypes import windll
            return windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:  # Linux / macOS
        return os.geteuid() == 0


def check_requirements():
    system_os = platform.system().lower()
    if not is_admin():
        print("\n[!] ERROR: This script must be run as Administrator (Windows) or with sudo (Linux/macOS).")
        sys.exit(1)
    if "windows" in system_os:
        npcap_path = r"C:\Windows\System32\Npcap"
        if not os.path.exists(npcap_path):
            print("\n[!] ERROR: Npcap is not installed.")
            print("    Install it from: https://nmap.org/npcap/")
            sys.exit(1)


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print("[-] Error detecting IP:", e)
        return None


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        clients_list.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return clients_list


# --- MODIFIED: Function to add Hostname and Vendor ---
def get_device_details(clients_list):
    for client in clients_list:
        # Get Hostname
        try:
            client['hostname'] = socket.gethostbyaddr(client['ip'])[0]
        except socket.herror:
            client['hostname'] = "N/A"

        # Get Manufacturer/Vendor
        try:
            response = requests.get(f"https://api.macvendors.com/{client['mac']}")
            if response.status_code == 200:
                client['vendor'] = response.text
            else:
                client['vendor'] = "N/A"
        except requests.exceptions.RequestException:
            client['vendor'] = "N/A"
    return clients_list


# --- MODIFIED: Print function to show new details ---
def print_result(results_list):
    print("\n=======================================================================================")
    print("                           Network Scan Results")
    print("=======================================================================================")
    print(" IP Address\t\tMAC Address\t\tHostname\t\tManufacturer")
    print("---------------------------------------------------------------------------------------")
    for client in results_list:
        print(f" {client['ip']:<15}\t{client['mac']:<17}\t{client['hostname']:<25}\t{client['vendor']}")
    print("=======================================================================================")


if __name__ == "__main__":
    print("\nStarting Strict Cross-Platform Network Scanner...\n")
    check_requirements()
    local_ip = get_local_ip()
    if not local_ip:
        sys.exit("[-] Could not detect local IP. Exiting.")
    print(f"[+] Local IP Detected: {local_ip}")
    ip_interface = ipaddress.ip_interface(f"{local_ip}/24")
    network = ip_interface.network
    print(f"[+] Scanning Network: {network}")
    scan_result = scan(str(network))

    if scan_result:
        print(f"\n[+] Found {len(scan_result)} devices. Fetching details...")
        # --- NEW: Call the function to get details ---
        detailed_results = get_device_details(scan_result)
        print_result(detailed_results)
    else:
        print("[-] No devices found on the network.")
