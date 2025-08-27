#!/usr/bin/env python3
"""
NetSentry: Network Traffic Monitor and DDoS Protection System

A network security tool that monitors incoming traffic and automatically blocks
IP addresses that exceed defined packet rate thresholds using iptables.
"""

import sys
import time
import threading
import subprocess
import signal
import os
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP

# --- Configuration ---
# Packets per second from a single IP to trigger a block
PACKET_THRESHOLD = 40

# How long an IP remains blocked in seconds before being unblocked
BLOCKED_TIMEOUT = 300  # 5 minutes

# The time window for packet rate calculation in seconds
TIME_WINDOW = 1.0

# Network interface to monitor (None for all interfaces)
MONITOR_INTERFACE = None

# Additional filters for packet capture
PACKET_FILTER = 'ip'

class NetSentry:
    """
    A network traffic monitor that detects and temporarily blocks
    IPs exceeding a packet rate threshold using iptables.
    
    Features:
    - Real-time packet monitoring using Scapy
    - Automatic IP blocking via iptables
    - Configurable thresholds and timeouts
    - Thread-safe operations
    - Graceful shutdown handling
    """
    
    def __init__(self, threshold=PACKET_THRESHOLD, window=TIME_WINDOW, timeout=BLOCKED_TIMEOUT):
        """
        Initialize NetSentry with configuration parameters.
        
        Args:
            threshold (int): Packets per second threshold for blocking
            window (float): Time window for rate calculation
            timeout (int): Duration to keep IPs blocked
        """
        self.threshold = threshold
        self.window = window
        self.timeout = timeout
        
        # Data structures for tracking packets and blocked IPs
        self.packet_counts = defaultdict(int)
        self.packet_timestamps = defaultdict(deque)
        self.blocked_ips = {}
        self.lock = threading.Lock()
        
        # Control flags
        self.running = True
        self.sniffer_thread = None
        self.rate_calc_thread = None
        
        # Check system requirements
        self._check_privileges()
        self._check_dependencies()
        
        # Set up signal handlers for graceful shutdown
        self._setup_signal_handlers()
        
        # Start background thread for rate calculation
        self.rate_calc_thread = threading.Thread(
            target=self._periodic_rate_calculation, 
            daemon=True,
            name="RateCalculator"
        )
        self.rate_calc_thread.start()

    def _check_privileges(self):
        """
        Checks if the script has root/administrator privileges.
        Required for iptables operations and packet sniffing.
        """
        try:
            if os.name == 'posix':  # Unix-like systems (Linux, macOS)
                if os.geteuid() != 0:
                    print("ERROR: This script requires root privileges.", file=sys.stderr)
                    print("Please run with: sudo python3 netsentry.py", file=sys.stderr)
                    sys.exit(1)
            elif os.name == 'nt':  # Windows
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    print("ERROR: This script requires Administrator privileges on Windows.", file=sys.stderr)
                    sys.exit(1)
        except Exception as e:
            print(f"ERROR: Could not check privileges: {e}", file=sys.stderr)
            print("Please ensure you're running as administrator/root.", file=sys.stderr)
            sys.exit(1)

    def _check_dependencies(self):
        """Check if required system tools are available."""
        try:
            # Check if iptables is available
            result = subprocess.run(['which', 'iptables'], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                print("ERROR: iptables not found. Please install iptables.", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"WARNING: Could not verify iptables installation: {e}")

    def _setup_signal_handlers(self):
        """Set up signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            print(f"\nReceived signal {signum}. Shutting down gracefully...")
            self.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def _block_ip(self, ip):
        """
        Blocks an IP address using iptables.
        
        Args:
            ip (str): IP address to block
        """
        if ip in self.blocked_ips:
            return  # Already blocked
            
        block_until = time.time() + self.timeout
        self.blocked_ips[ip] = block_until
        
        print(f"[BLOCK] {ip} - Exceeded {self.threshold} packets/sec threshold")
        
        try:
            # Add DROP rule for this IP
            cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            # Log the successful block
            with open("/var/log/netsentry.log", "a") as log:
                log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - BLOCKED: {ip}\n")
                
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to block IP {ip}: {e.stderr}")
        except FileNotFoundError:
            print("[ERROR] iptables command not found")
        except Exception as e:
            print(f"[ERROR] Unexpected error blocking IP {ip}: {e}")

    def _unblock_ip(self, ip):
        """
        Removes the block rule for a given IP.
        
        Args:
            ip (str): IP address to unblock
        """
        print(f"[UNBLOCK] {ip} - Block timeout expired")
        
        try:
            # Remove DROP rule for this IP
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            # Remove from blocked IPs tracking
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                
            # Log the unblock
            with open("/var/log/netsentry.log", "a") as log:
                log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - UNBLOCKED: {ip}\n")
                
        except subprocess.CalledProcessError as e:
            print(f"[WARNING] Failed to unblock IP {ip}: {e.stderr}")
            # Still remove from tracking even if iptables command failed
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
        except Exception as e:
            print(f"[ERROR] Unexpected error unblocking IP {ip}: {e}")

    def _calculate_packet_rate(self, ip):
        """
        Calculate the current packet rate for an IP within the time window.
        
        Args:
            ip (str): IP address to calculate rate for
            
        Returns:
            int: Number of packets received from IP in the time window
        """
        current_time = time.time()
        timestamps = self.packet_timestamps[ip]
        
        # Remove timestamps outside the current window
        while timestamps and timestamps[0] < current_time - self.window:
            timestamps.popleft()
            
        return len(timestamps)

    def _periodic_rate_calculation(self):
        """
        Periodic thread function to check packet rates and manage IP blocks.
        Runs continuously until self.running is False.
        """
        print("[INFO] Rate calculation thread started")
        
        while self.running:
            try:
                time.sleep(self.window / 2)  # Check more frequently than the window
                
                with self.lock:
                    current_time = time.time()
                    
                    # First, check and unblock expired IPs
                    self._check_and_unblock()
                    
                    # Then check rates for all monitored IPs
                    ips_to_check = list(self.packet_timestamps.keys())
                    
                    for ip in ips_to_check:
                        # Skip already blocked IPs
                        if ip in self.blocked_ips:
                            continue
                            
                        # Skip private/local IPs (optional)
                        if self._is_local_ip(ip):
                            continue
                            
                        rate = self._calculate_packet_rate(ip)
                        
                        # Block if threshold exceeded
                        if rate > self.threshold:
                            self._block_ip(ip)
                        
                        # Clean up old entries to prevent memory growth
                        if not self.packet_timestamps[ip]:
                            del self.packet_timestamps[ip]
                            
            except Exception as e:
                print(f"[ERROR] Rate calculation thread error: {e}")
                time.sleep(1)  # Brief pause before retrying

    def _is_local_ip(self, ip):
        """
        Check if an IP is a local/private address that shouldn't be blocked.
        
        Args:
            ip (str): IP address to check
            
        Returns:
            bool: True if IP is local/private
        """
        # Common private IP ranges
        private_ranges = [
            '127.',      # Loopback
            '10.',       # Private Class A
            '172.16.',   # Private Class B (partial check)
            '192.168.',  # Private Class C
            '169.254.'   # Link-local
        ]
        
        return any(ip.startswith(range_) for range_ in private_ranges)

    def _check_and_unblock(self):
        """
        Checks for and unblocks IPs whose timeout has expired.
        Should be called with self.lock held.
        """
        current_time = time.time()
        expired_ips = []
        
        for ip, block_time in self.blocked_ips.items():
            if current_time >= block_time:
                expired_ips.append(ip)
        
        # Unblock expired IPs
        for ip in expired_ips:
            self._unblock_ip(ip)

    def packet_handler(self, packet):
        """
        Packet handler function called by Scapy sniffer for each captured packet.
        Records timestamp for rate calculation.
        
        Args:
            packet: Scapy packet object
        """
        try:
            if IP in packet:
                source_ip = packet[IP].src
                current_time = time.time()
                
                with self.lock:
                    # Only track packets from non-blocked IPs
                    if source_ip not in self.blocked_ips:
                        self.packet_timestamps[source_ip].append(current_time)
                        
                        # Limit deque size to prevent memory issues
                        if len(self.packet_timestamps[source_ip]) > self.threshold * 2:
                            self.packet_timestamps[source_ip].popleft()
                            
        except Exception as e:
            # Don't print errors for every packet to avoid spam
            pass

    def print_status(self):
        """Print current monitoring status."""
        with self.lock:
            active_ips = len(self.packet_timestamps)
            blocked_count = len(self.blocked_ips)
            
        print(f"[STATUS] Monitoring {active_ips} IPs, {blocked_count} blocked")
        
        if self.blocked_ips:
            print("[BLOCKED IPs]:")
            current_time = time.time()
            for ip, block_time in self.blocked_ips.items():
                remaining = max(0, int(block_time - current_time))
                print(f"  {ip} - {remaining}s remaining")

    def start(self):
        """
        Start the network monitoring system.
        Begins packet capture and rate monitoring.
        """
        print("=" * 50)
        print("NetSentry Network Traffic Monitor Starting")
        print("=" * 50)
        print(f"Configuration:")
        print(f"  Threshold: {self.threshold} packets/{self.window}s")
        print(f"  Block timeout: {self.timeout}s ({self.timeout//60}m)")
        print(f"  Interface: {MONITOR_INTERFACE or 'All interfaces'}")
        print(f"  Filter: {PACKET_FILTER}")
        print("=" * 50)
        
        try:
            # Start packet sniffer in a separate thread
            print("[INFO] Starting packet capture...")
            self.sniffer_thread = threading.Thread(
                target=self._start_sniffer,
                daemon=True,
                name="PacketSniffer"
            )
            self.sniffer_thread.start()
            
            # Status reporting loop
            status_counter = 0
            while self.running:
                time.sleep(10)  # Status update every 10 seconds
                status_counter += 1
                
                if status_counter % 6 == 0:  # Every minute
                    self.print_status()
                    
        except KeyboardInterrupt:
            print("\n[INFO] Shutdown requested by user")
        except Exception as e:
            print(f"[ERROR] Unexpected error in main loop: {e}")
        finally:
            self.stop()

    def _start_sniffer(self):
        """Start the Scapy packet sniffer."""
        try:
            print("[INFO] Packet sniffer started")
            sniff(
                filter=PACKET_FILTER,
                prn=self.packet_handler,
                store=False,
                iface=MONITOR_INTERFACE,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"[ERROR] Packet sniffer error: {e}")
            self.running = False

    def stop(self):
        """
        Stop the monitoring system and clean up resources.
        Unblocks all currently blocked IPs.
        """
        if not self.running:
            return
            
        print("\n[INFO] Stopping NetSentry...")
        self.running = False
        
        # Unblock all currently blocked IPs
        with self.lock:
            blocked_ips_copy = list(self.blocked_ips.keys())
            
        for ip in blocked_ips_copy:
            self._unblock_ip(ip)
        
        print("[INFO] NetSentry stopped successfully")

def main():
    """Main function to start NetSentry with command line argument support."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="NetSentry - Network Traffic Monitor and DDoS Protection"
    )
    parser.add_argument(
        '--threshold', '-t', 
        type=int, 
        default=PACKET_THRESHOLD,
        help=f'Packets per second threshold (default: {PACKET_THRESHOLD})'
    )
    parser.add_argument(
        '--timeout', '-T',
        type=int,
        default=BLOCKED_TIMEOUT,
        help=f'Block timeout in seconds (default: {BLOCKED_TIMEOUT})'
    )
    parser.add_argument(
        '--window', '-w',
        type=float,
        default=TIME_WINDOW,
        help=f'Time window for rate calculation (default: {TIME_WINDOW})'
    )
    parser.add_argument(
        '--interface', '-i',
        type=str,
        default=MONITOR_INTERFACE,
        help='Network interface to monitor (default: all)'
    )
    
    args = parser.parse_args()
    
    # Create and start NetSentry
    sentry = NetSentry(
        threshold=args.threshold,
        window=args.window,
        timeout=args.timeout
    )
    
    sentry.start()

if __name__ == "__main__":
    main()
