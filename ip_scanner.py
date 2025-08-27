#!/usr/bin/env python3
"""
Network Scanner - IPv4 Device Discovery Tool
Scans local network for active devices and gathers device information
"""

import os
import sys
import time
import platform
import subprocess
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import threading

# Import required libraries with installation fallback
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


# ========================================
# PRIVILEGE AND REQUIREMENT CHECKING
# ========================================

def is_admin():
    """
    Check if the script is running with administrator privileges
    Required for raw packet operations in Scapy
    """
    if os.name == "nt":  # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:  # Linux / macOS
        return os.geteuid() == 0


def check_requirements():
    """
    Verify system requirements before running the scanner
    - Administrator/root privileges
    - Npcap on Windows systems
    """
    system_os = platform.system().lower()
    
    # Check for admin privileges
    if not is_admin():
        print("\n[!] ERROR: This script must be run as Administrator (Windows) or with sudo (Linux/macOS).")
        print("    Raw packet operations require elevated privileges.")
        sys.exit(1)
    
    # Windows-specific: Check for Npcap
    if "windows" in system_os:
        npcap_paths = [
            r"C:\Windows\System32\Npcap",
            r"C:\Program Files\Npcap"
        ]
        npcap_found = any(os.path.exists(path) for path in npcap_paths)
        if not npcap_found:
            print("\n[!] ERROR: Npcap is not installed.")
            print("    Download and install from: https://nmap.org/npcap/")
            sys.exit(1)


# ========================================
# NETWORK DETECTION
# ========================================

def get_local_ip_and_interface():
    """
    Detect the local IP address and determine the network interface
    Returns both IP and the appropriate network range
    """
    try:
        # Create a socket to determine the local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        
        # Try to determine the subnet mask
        import psutil
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    if addr.netmask:
                        # Calculate network with proper subnet mask
                        ip_interface = ipaddress.ip_interface(f"{local_ip}/{addr.netmask}")
                        return local_ip, str(ip_interface.network)
        
        # Fallback to /24 if subnet mask detection fails
        ip_interface = ipaddress.ip_interface(f"{local_ip}/24")
        return local_ip, str(ip_interface.network)
        
    except Exception as e:
        print(f"[-] Error detecting network configuration: {e}")
        return None, None


def get_local_ip_fallback():
    """
    Fallback method for IP detection without psutil
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        
        # Default to /24 subnet
        ip_interface = ipaddress.ip_interface(f"{local_ip}/24")
        return local_ip, str(ip_interface.network)
    except Exception as e:
        print(f"[-] Error detecting IP: {e}")
        return None, None


# ========================================
# NETWORK SCANNING
# ========================================

def scan_network(network_range):
    """
    Perform ARP scan on the specified network range
    
    Args:
        network_range: Network range to scan (e.g., '192.168.1.0/24')
    
    Returns:
        List of dictionaries containing IP and MAC addresses of discovered devices
    """
    print(f"[+] Performing ARP scan on {network_range}")
    
    try:
        # Create ARP request packet
        arp_request = scapy.ARP(pdst=network_range)
        # Create Ethernet broadcast frame
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        # Combine Ethernet and ARP layers
        arp_request_broadcast = broadcast / arp_request
        
        # Send packets and receive responses
        # timeout=2 gives devices more time to respond
        # verbose=False suppresses Scapy output
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        # Parse responses into list of devices
        devices = []
        for element in answered_list:
            device_info = {
                "ip": element[1].psrc,    # Source IP from ARP response
                "mac": element[1].hwsrc   # Source MAC from ARP response
            }
            devices.append(device_info)
        
        return devices
        
    except Exception as e:
        print(f"[-] Error during network scan: {e}")
        return []


# ========================================
# DEVICE INFORMATION GATHERING
# ========================================

# Thread lock for API rate limiting
api_lock = threading.Lock()

def get_hostname(ip_address):
    """
    Attempt to resolve hostname for given IP address
    
    Args:
        ip_address: IP address to resolve
    
    Returns:
        Hostname string or "Unknown" if resolution fails
    """
    try:
        # Reverse DNS lookup with timeout
        socket.setdefaulttimeout(3)
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except (socket.herror, socket.timeout, OSError):
        return "Unknown"
    finally:
        socket.setdefaulttimeout(None)


def get_vendor_info(mac_address):
    """
    Look up device manufacturer using MAC address OUI (first 3 octets)
    
    Args:
        mac_address: MAC address in format XX:XX:XX:XX:XX:XX
    
    Returns:
        Manufacturer name or "Unknown" if lookup fails
    """
    try:
        # Rate limiting to avoid overwhelming the API
        with api_lock:
            time.sleep(0.1)  # Small delay between API calls
        
        # Clean MAC address format
        clean_mac = mac_address.replace(":", "").replace("-", "").upper()
        if len(clean_mac) != 12:
            return "Invalid MAC"
        
        # Try primary API
        try:
            response = requests.get(
                f"https://api.macvendors.com/{mac_address}",
                timeout=5,
                headers={'User-Agent': 'Network-Scanner/1.0'}
            )
            if response.status_code == 200:
                vendor = response.text.strip()
                return vendor if vendor else "Unknown"
        except requests.exceptions.RequestException:
            pass
        
        # Fallback to alternative API
        try:
            oui = clean_mac[:6]  # First 6 characters (3 octets)
            response = requests.get(
                f"https://api.maclookup.app/v2/macs/{mac_address}",
                timeout=5,
                headers={'User-Agent': 'Network-Scanner/1.0'}
            )
            if response.status_code == 200:
                data = response.json()
                return data.get('company', 'Unknown')
        except (requests.exceptions.RequestException, ValueError):
            pass
        
        return "Unknown"
        
    except Exception as e:
        print(f"[-] Error looking up vendor for {mac_address}: {e}")
        return "Error"


def get_device_details(devices):
    """
    Enrich device list with hostname and vendor information
    Uses threading for concurrent lookups to improve performance
    
    Args:
        devices: List of device dictionaries with 'ip' and 'mac' keys
    
    Returns:
        Enhanced list with 'hostname' and 'vendor' information added
    """
    if not devices:
        return devices
    
    print(f"[+] Gathering detailed information for {len(devices)} devices...")
    
    def enrich_device(device):
        """Thread worker function to enrich a single device"""
        device['hostname'] = get_hostname(device['ip'])
        device['vendor'] = get_vendor_info(device['mac'])
        return device
    
    # Use ThreadPoolExecutor for concurrent processing
    # Limit workers to avoid overwhelming APIs
    max_workers = min(10, len(devices))
    
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            enriched_devices = list(executor.map(enrich_device, devices))
        return enriched_devices
    except Exception as e:
        print(f"[-] Error during device enrichment: {e}")
        # Return original devices if enrichment fails
        return devices


# ========================================
# RESULTS DISPLAY
# ========================================

def print_results(devices):
    """
    Display scan results in a formatted table
    
    Args:
        devices: List of device dictionaries with complete information
    """
    if not devices:
        print("[-] No devices found on the network.")
        return
    
    print(f"\n[+] Found {len(devices)} active devices")
    print("\n" + "="*100)
    print("                                   NETWORK SCAN RESULTS")
    print("="*100)
    print(f"{'IP Address':<15} {'MAC Address':<18} {'Hostname':<25} {'Manufacturer':<30}")
    print("-"*100)
    
    # Sort devices by IP address for better readability
    try:
        sorted_devices = sorted(devices, key=lambda x: ipaddress.ip_address(x['ip']))
    except:
        sorted_devices = devices
    
    for device in sorted_devices:
        ip = device.get('ip', 'Unknown')
        mac = device.get('mac', 'Unknown')
        hostname = device.get('hostname', 'Unknown')
        vendor = device.get('vendor', 'Unknown')
        
        # Truncate long values for better table formatting
        hostname = hostname[:24] if len(hostname) > 24 else hostname
        vendor = vendor[:29] if len(vendor) > 29 else vendor
        
        print(f"{ip:<15} {mac:<18} {hostname:<25} {vendor:<30}")
    
    print("="*100)


def save_results_to_file(devices, filename="network_scan_results.txt"):
    """
    Save scan results to a text file
    
    Args:
        devices: List of device dictionaries
        filename: Output filename
    """
    try:
        with open(filename, 'w') as f:
            f.write("Network Scan Results\n")
            f.write("="*50 + "\n")
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Devices Found: {len(devices)}\n\n")
            
            for i, device in enumerate(devices, 1):
                f.write(f"Device {i}:\n")
                f.write(f"  IP Address: {device.get('ip', 'Unknown')}\n")
                f.write(f"  MAC Address: {device.get('mac', 'Unknown')}\n")
                f.write(f"  Hostname: {device.get('hostname', 'Unknown')}\n")
                f.write(f"  Manufacturer: {device.get('vendor', 'Unknown')}\n")
                f.write("\n")
        
        print(f"[+] Results saved to {filename}")
    except Exception as e:
        print(f"[-] Error saving results: {e}")


# ========================================
# MAIN EXECUTION
# ========================================

def main():
    """
    Main function that orchestrates the network scanning process
    """
    print("\n" + "="*60)
    print("         IPv4 Network Scanner v2.0")
    print("    Discover devices on your local network")
    print("="*60)
    
    # Check system requirements
    print("\n[+] Checking system requirements...")
    check_requirements()
    print("[+] System requirements satisfied")
    
    # Detect network configuration
    print("\n[+] Detecting network configuration...")
    
    # Try advanced detection first
    try:
        import psutil
        local_ip, network_range = get_local_ip_and_interface()
    except ImportError:
        print("[!] psutil not available, using fallback method")
        local_ip, network_range = get_local_ip_fallback()
    
    if not local_ip or not network_range:
        print("[-] Failed to detect network configuration. Exiting.")
        sys.exit(1)
    
    print(f"[+] Local IP Address: {local_ip}")
    print(f"[+] Network Range: {network_range}")
    
    # Perform network scan
    print(f"\n[+] Starting ARP scan...")
    start_time = time.time()
    
    devices = scan_network(network_range)
    
    if not devices:
        print("[-] No devices found on the network.")
        print("    This could be due to:")
        print("    - Network isolation/segmentation")
        print("    - Firewall blocking ARP responses")
        print("    - Incorrect network range detection")
        return
    
    scan_time = time.time() - start_time
    print(f"[+] ARP scan completed in {scan_time:.2f} seconds")
    
    # Gather detailed information
    detailed_devices = get_device_details(devices)
    
    # Display results
    print_results(detailed_devices)
    
    # Optionally save results
    try:
        save_choice = input("\n[?] Save results to file? (y/n): ").lower().strip()
        if save_choice in ['y', 'yes']:
            filename = input("Enter filename (or press Enter for default): ").strip()
            if not filename:
                filename = f"network_scan_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            save_results_to_file(detailed_devices, filename)
    except KeyboardInterrupt:
        print("\n[+] Scan completed successfully")
    
    total_time = time.time() - start_time
    print(f"\n[+] Total execution time: {total_time:.2f} seconds")
    print("[+] Scan completed successfully!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Unexpected error occurred: {e}")
        print("[-] Please ensure you're running as administrator and have proper network access")
        sys.exit(1)
