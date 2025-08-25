import sys
import time
import threading
import subprocess
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP

# --- Configuration ---
# Packets per second from a single IP to trigger a block.
PACKET_THRESHOLD = 40

# How long an IP remains blocked in seconds before being unblocked.
BLOCKED_TIMEOUT = 300 # 5 minutes

# The time window for packet rate calculation.
TIME_WINDOW = 1.0


class NetSentry:
    """
    A network traffic monitor that detects and temporarily blocks
    IPs exceeding a packet rate threshold using iptables.
    """
    def __init__(self, threshold, window, timeout):
        self.threshold = threshold
        self.window = window
        self.timeout = timeout
        
        self.packet_counts = defaultdict(int)
        self.packet_timestamps = defaultdict(deque)
        self.blocked_ips = {}
        self.lock = threading.Lock()
        
        self._check_privileges()
        
        self.running = True
        self.rate_calc_thread = threading.Thread(target=self._periodic_rate_calculation, daemon=True)
        self.rate_calc_thread.start()

    def _check_privileges(self):
        """Checks if the script has root privileges."""
        try:
            # Use a platform-independent way to check for root/admin
            if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
                if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() != "0":
                    print("This script requires root privileges.", file=sys.stderr)
                    sys.exit(1)
            elif sys.platform == 'win32':
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    print("This script requires Administrator privileges on Windows.", file=sys.stderr)
                    sys.exit(1)
        except Exception as e:
            print(f"Error checking privileges: {e}. Please run as administrator.", file=sys.stderr)
            sys.exit(1)

    def _block_ip(self, ip):
        """Blocks an IP address using iptables."""
        block_until = time.time() + self.timeout
        self.blocked_ips[ip] = block_until
        
        print(f"[*] Blocking IP: {ip}. Exceeded threshold of {self.threshold} pps.")
        try:
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"[!] Failed to block IP {ip}: {e}")
            
    def _unblock_ip(self, ip):
        """Removes the block rule for a given IP."""
        print(f"[*] Unblocking IP: {ip}. Timeout expired.")
        try:
            subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
            del self.blocked_ips[ip]
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"[!] Failed to unblock IP {ip}: {e}. The rule may not exist.")

    def _calculate_packet_rate(self, ip):
        """Calculate the current packet rate for an IP."""
        current_time = time.time()
        timestamps = self.packet_timestamps[ip]
        while timestamps and timestamps[0] < current_time - self.window:
            timestamps.popleft()
        return len(timestamps)

    def _periodic_rate_calculation(self):
        """Periodic thread to check rates and block IPs."""
        while self.running:
            try:
                time.sleep(self.window)
                with self.lock:
                    ips_to_check = list(self.packet_timestamps.keys())
                    
                    # Unblock any IPs whose timeout has expired
                    self._check_and_unblock()
                    
                    # Check rates for active IPs
                    for ip in ips_to_check:
                        if ip in self.blocked_ips:
                            continue
                        rate = self._calculate_packet_rate(ip)
                        if rate > self.threshold:
                            self._block_ip(ip)
            except Exception as e:
                print(f"Error in rate calculation thread: {e}")

    def _check_and_unblock(self):
        """Checks for and unblocks IPs whose timeout has expired."""
        current_time = time.time()
        for ip, block_time in list(self.blocked_ips.items()):
            if current_time >= block_time:
                self._unblock_ip(ip)

    def packet_handler(self, packet):
        """This function is called by the sniffer for each packet."""
        if IP in packet:
            source_ip = packet[IP].src
            with self.lock:
                if source_ip not in self.blocked_ips:
                    self.packet_timestamps[source_ip].append(time.time())

    def start(self):
        print("--- Starting Network Traffic Monitor ---")
        print(f"Threshold: {self.threshold} packets/{self.window} sec")
        print(f"Block timeout: {self.timeout} sec")
        
        sniffer_thread = threading.Thread(
            target=sniff,
            kwargs={'filter': 'ip', 'prn': self.packet_handler, 'store': False, 'iface': None},
            daemon=True
        )
        sniffer_thread.start()
        
        try:
            while True:
                time.sleep(1) # Keep the main thread alive
        except KeyboardInterrupt:
            print("\n[!] Stopping monitor...")
        finally:
            self.stop()

    def stop(self):
        self.running = False
        print("[*] Monitor stopped.")

if __name__ == "__main__":
    sentry = NetSentry(
        threshold=PACKET_THRESHOLD,
        window=TIME_WINDOW,
        timeout=BLOCKED_TIMEOUT
    )
    sentry.start()
