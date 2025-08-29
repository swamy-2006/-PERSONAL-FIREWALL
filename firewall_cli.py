#!/usr/bin/env python3
"""
Advanced Personal Firewall - Command Line Interface
A CLI-based firewall management tool with packet inspection capabilities.
"""

import argparse
import json
import logging
import os
import platform
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Set, List, Dict, Any

try:
    import scapy.all as scapy
except ImportError:
    print("❌ Error: scapy library is required. Install with: pip install scapy")
    sys.exit(1)

# --- SETUP ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firewall_cli.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)


# --- UTILITY FUNCTIONS ---
def print_banner():
    """Display application banner."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                 🔥 ADVANCED PERSONAL FIREWALL 🔥              ║
║                      Command Line Interface                   ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def is_admin():
    """Checks for administrator/root privileges."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        try:
            from ctypes import windll
            return windll.shell32.IsUserAnAdmin()
        except:
            return False


def resolve_domain_to_ips(domain: str) -> Set[str]:
    """
    Resolves a domain and common subdomains to a set of IP addresses.
    """
    blocked_ips = set()
    try:
        hostname, aliases, ips = socket.gethostbyname_ex(domain)
        for ip in ips:
            blocked_ips.add(ip)
        logger.debug(f"Resolved {domain} to IPs: {ips}")
    except Exception as e:
        logger.error(f"Could not resolve main domain {domain}: {e}")

    # Try common subdomains
    for sub in ["www.", "m.", "api."]:
        try:
            hostname, aliases, ips = socket.gethostbyname_ex(sub + domain)
            for ip in ips:
                blocked_ips.add(ip)
        except Exception as e:
            logger.debug(f"Could not resolve subdomain {sub + domain}: {e}")

    return blocked_ips


# --- FIREWALL CORE ---
class FirewallEngine:
    def __init__(self, rules_file: str = 'r1.json'):
        self.rules_file = rules_file
        self.rules = []
        self.blocked_count = 0
        self.allowed_count = 0
        self.logged_count = 0
        self.is_running = False
        self.sniffer_thread = None
        self.blocked_ips = set()
        
    def load_rules(self) -> bool:
        """Load firewall rules from JSON file."""
        try:
            with open(self.rules_file, 'r') as f:
                data = json.load(f)
                self.rules = data.get('rules', [])
                
            # Build blocked IPs set for fast lookup
            self.blocked_ips.clear()
            for rule in self.rules:
                if 'domain' in rule and rule.get('action') == 'block':
                    self.blocked_ips.update(resolve_domain_to_ips(rule['domain']))
                elif 'src_ip' in rule and rule.get('action') == 'block':
                    self.blocked_ips.add(rule['src_ip'])
                    
            logger.info(f"✅ Loaded {len(self.rules)} rules from {self.rules_file}")
            return True
        except Exception as e:
            logger.error(f"❌ Could not load {self.rules_file}: {e}")
            return False

    def display_rules(self):
        """Display current firewall rules."""
        if not self.rules:
            print("⚠️  No rules loaded.")
            return

        allow_count = sum(1 for r in self.rules if r.get('action') == 'allow')
        block_count = sum(1 for r in self.rules if r.get('action') == 'block')
        log_count = sum(1 for r in self.rules if r.get('action') == 'log')

        print(f"\n📊 RULE SUMMARY: {len(self.rules)} total rules")
        print(f"   ✅ {allow_count} ALLOW | 🚫 {block_count} BLOCK | 📋 {log_count} LOG\n")

        print("🔧 ACTIVE RULES:")
        print("-" * 80)
        
        for i, rule in enumerate(self.rules, 1):
            action = rule.get('action', 'log')
            action_emoji = {"allow": "✅", "block": "🚫", "log": "📋"}.get(action, "❓")
            comment = rule.get('comment', 'No comment')

            rule_details = f"{i:2d}. {action_emoji} {action.upper()}: {comment}"
            
            if 'domain' in rule:
                rule_details += f" | Domain: {rule['domain']}"
            if 'protocol' in rule:
                rule_details += f" | Protocol: {rule['protocol']}"
            if 'dst_port' in rule:
                rule_details += f" | Port: {rule['dst_port']}"
            if 'src_ip' in rule:
                rule_details += f" | Source: {rule['src_ip']}"
            if 'dst_ip' in rule:
                rule_details += f" | Destination: {rule['dst_ip']}"

            print(rule_details)

    def apply_system_rules(self) -> bool:
        """Apply firewall rules based on the operating system."""
        system = platform.system()
        
        try:
            logger.info(f"Applying rules for {system}...")
            
            if system == "Linux":
                return self._apply_linux_rules()
            elif system == "Darwin":
                return self._apply_macos_rules()
            elif system == "Windows":
                return self._apply_windows_rules()
            else:
                logger.error(f"❌ Unsupported OS: {system}")
                return False
                
        except subprocess.CalledProcessError as e:
            error_output = e.stderr.decode() if e.stderr else "No error output."
            logger.error(f"❌ Failed to apply system rules: {e}\nDetails: {error_output}")
            return False
        except Exception as e:
            logger.error(f"❌ Unexpected error applying rules: {e}")
            return False

    def clear_system_rules(self) -> bool:
        """Remove all previously applied rules."""
        system = platform.system()
        try:
            logger.info("Clearing system firewall rules...")
            
            if system == "Linux":
                subprocess.run(["sudo", "iptables", "-F"], check=True)
                subprocess.run(["sudo", "iptables", "-P", "INPUT", "ACCEPT"], check=True)
                subprocess.run(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"], check=True)
                subprocess.run(["sudo", "iptables", "-P", "OUTPUT", "ACCEPT"], check=True)
                
            elif system == "Darwin":
                subprocess.run(["sudo", "pfctl", "-f", "/etc/pf.conf"], check=True)
                subprocess.run(["sudo", "pfctl", "-d"], check=True)
                
            elif system == "Windows":
                subprocess.run(
                    'netsh advfirewall firewall delete rule group="Python Firewall CLI"',
                    shell=True, check=False, capture_output=True, text=True, timeout=30
                )
                
            logger.info("✅ System firewall rules cleared")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Failed to clear system rules: {e}")
            return False
        except Exception as e:
            logger.error(f"❌ Unexpected error while clearing rules: {e}")
            return False

    def _apply_linux_rules(self) -> bool:
        """Linux implementation using iptables."""
        commands = [
            ["sudo", "iptables", "-F"],
            ["sudo", "iptables", "-P", "INPUT", "DROP"],
            ["sudo", "iptables", "-P", "FORWARD", "DROP"],
            ["sudo", "iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
            ["sudo", "iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
            ["sudo", "iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"]
        ]
        
        for cmd in commands:
            subprocess.run(cmd, check=True)

        for rule in self.rules:
            action = "ACCEPT" if rule.get('action') == 'allow' else "DROP"
            
            if 'domain' in rule:
                ips_to_block = resolve_domain_to_ips(rule['domain'])
                for ip in ips_to_block:
                    subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", action], check=True)
                continue

            command = ["sudo", "iptables", "-A", "INPUT"]
            
            if 'src_ip' in rule:
                command.extend(["-s", rule['src_ip']])
            if 'dst_port' in rule and 'protocol' in rule:
                command.extend(["-p", rule['protocol'].lower(), "--dport", str(rule['dst_port'])])
            if 'protocol' in rule and rule['protocol'].upper() == 'ICMP':
                command.extend(["-p", "icmp"])
                
            command.extend(["-j", action])
            subprocess.run(command, check=True)
            
        return True

    def _apply_macos_rules(self) -> bool:
        """macOS implementation using pfctl."""
        pf_rules = [
            "# Python Firewall CLI Rules",
            "set block-policy drop",
            "set skip on lo0",
            ""
        ]

        for rule in self.rules:
            action = "pass" if rule.get('action') == 'allow' else "block"

            if 'domain' in rule:
                ips_to_block = resolve_domain_to_ips(rule['domain'])
                for ip in ips_to_block:
                    pf_rules.append(f"block out from any to {ip}")
                continue

            rule_string = f"{action} in"
            if 'src_ip' in rule:
                rule_string += f" from {rule['src_ip']}"
            else:
                rule_string += " from any"

            if 'dst_port' in rule and 'protocol' in rule:
                rule_string += f" proto {rule['protocol'].lower()} to any port {rule['dst_port']}"
            elif 'protocol' in rule and rule['protocol'].upper() == 'ICMP':
                rule_string += " proto icmp to any"
            else:
                rule_string += " to any"

            pf_rules.append(rule_string)

        pf_rules.extend([
            "pass out keep state",
            "pass in proto tcp from any to any port 22"
        ])

        with open('/tmp/pf_firewall_cli_rules.conf', 'w') as f:
            f.write('\n'.join(pf_rules))
            
        subprocess.run(["sudo", "pfctl", "-f", "/tmp/pf_firewall_cli_rules.conf"], check=True)
        subprocess.run(["sudo", "pfctl", "-e"], check=True)
        return True

    def _apply_windows_rules(self) -> bool:
        """Windows implementation with proper ALLOW/BLOCK rules."""
        try:
            subprocess.run(
                'netsh advfirewall firewall delete rule group="Python Firewall CLI"',
                shell=True, check=False, capture_output=True, text=True, timeout=30
            )
        except Exception as e:
            logger.warning(f"Could not clear existing rules: {e}")

        try:
            subprocess.run(
                "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound",
                shell=True, check=True, timeout=30
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to set firewall policy: {e}")
            return False

        for i, rule in enumerate(self.rules):
            try:
                comment = rule.get("comment", f"CLI Firewall Rule {i + 1}")
                rule_name = f"CLI Firewall Rule {i + 1}"
                action_cmd = "allow" if rule.get('action') == 'allow' else "block"

                command_parts = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f'name="{rule_name}"',
                    f'group="Python Firewall CLI"',
                    f'description="{comment}"',
                    "dir=out",
                    f"action={action_cmd}"
                ]
                
                if 'domain' in rule:
                    ips_to_block = resolve_domain_to_ips(rule['domain'])
                    if ips_to_block:
                        command_parts.append(f"remoteip={','.join(ips_to_block)}")
                        
                elif 'protocol' in rule:
                    protocol = rule['protocol'].upper()
                    if protocol == 'ICMP':
                        command_parts.append("protocol=icmpv4")
                    else:
                        command_parts.append(f"protocol={protocol.lower()}")
                
                if 'src_ip' in rule:
                    command_parts.append(f"remoteip={rule['src_ip']}")

                if 'dst_port' in rule:
                    command_parts.append(f"localport={rule['dst_port']}")

                command = " ".join(command_parts)
                subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30, check=True)
                
            except Exception as e:
                logger.error(f"Failed to apply rule {i+1}: {e}")
                
        return True

    def inspect_packet(self, packet):
        """Inspect and log packets based on rules."""
        if not packet.haslayer(scapy.IP):
            return

        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        proto, dport = None, None

        if packet.haslayer(scapy.TCP):
            proto, dport = 'TCP', packet[scapy.TCP].dport
        elif packet.haslayer(scapy.UDP):
            proto, dport = 'UDP', packet[scapy.UDP].dport
        elif packet.haslayer(scapy.ICMP):
            proto = 'ICMP'

        # Check if packet should be blocked based on IP
        is_blocked = src_ip in self.blocked_ips or dst_ip in self.blocked_ips

        # Check rules
        for rule in self.rules:
            if self._match_rule(rule, src_ip, dst_ip, proto, dport):
                action = rule.get('action', 'log').upper()
                reason = rule.get('comment', 'No comment')

                if action == 'BLOCK' or is_blocked:
                    self.blocked_count += 1
                    status = "🚫 BLOCKED"
                elif action == 'ALLOW' and not is_blocked:
                    self.allowed_count += 1
                    status = "✅ ALLOWED"
                else:
                    self.logged_count += 1
                    status = "📋 LOGGED"
                
                timestamp = time.strftime("%H:%M:%S")
                log_message = (f"[{timestamp}] {status} | {proto or 'IP'} | "
                              f"{src_ip}→{dst_ip}{f':{dport}' if dport else ''} | {reason}")

                print(log_message)
                logger.info(log_message)
                return

    def _match_rule(self, rule: Dict[str, Any], src_ip: str, dst_ip: str, proto: str, dport: int) -> bool:
        """Check if packet matches rule criteria."""
        if 'src_ip' in rule and rule.get('src_ip') != src_ip:
            return False
        if 'dst_ip' in rule and rule.get('dst_ip') != dst_ip:
            return False
        if 'protocol' in rule and rule.get('protocol').upper() != proto:
            return False
        if 'dst_port' in rule and rule.get('dst_port') != dport:
            return False
        return True

    def start_monitoring(self):
        """Start packet monitoring in a separate thread."""
        if self.is_running:
            print("⚠️  Packet monitoring is already running.")
            return

        print("🚀 Starting packet monitoring...")
        self.is_running = True
        
        def packet_sniffer():
            try:
                print("👀 Monitoring network traffic... (Press Ctrl+C to stop)")
                scapy.sniff(prn=self.inspect_packet, stop_filter=lambda p: not self.is_running)
            except Exception as e:
                logger.error(f"❌ Packet sniffer error: {e}")
                self.is_running = False

        self.sniffer_thread = threading.Thread(target=packet_sniffer, daemon=True)
        self.sniffer_thread.start()

    def stop_monitoring(self):
        """Stop packet monitoring."""
        if self.is_running:
            print("🛑 Stopping packet monitoring...")
            self.is_running = False
            time.sleep(1)  # Give time for cleanup

    def get_stats(self) -> Dict[str, int]:
        """Get current statistics."""
        return {
            'blocked': self.blocked_count,
            'allowed': self.allowed_count,
            'logged': self.logged_count
        }


# --- CLI INTERFACE ---
class FirewallCLI:
    def __init__(self):
        self.engine = FirewallEngine()
        self.running = False
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print("\n🛑 Received shutdown signal...")
        self.stop_firewall()
        sys.exit(0)

    def start_firewall(self, monitor: bool = True):
        """Start the firewall with optional packet monitoring."""
        if not is_admin():
            print("❌ This firewall must be run as Administrator (Windows) or with sudo (Linux/Mac).")
            print("   This is required to modify system firewall rules.")
            return False

        print("🔥 === STARTING FIREWALL ===")
        
        if not self.engine.load_rules():
            return False

        if not self.engine.apply_system_rules():
            return False

        print("✅ System firewall rules applied successfully!")
        self.running = True

        if monitor:
            self.engine.start_monitoring()
            
        return True

    def stop_firewall(self):
        """Stop the firewall and clear rules."""
        if not self.running:
            print("⚠️  Firewall is not currently running.")
            return

        print("🛑 === STOPPING FIREWALL ===")
        
        self.engine.stop_monitoring()
        
        if self.engine.clear_system_rules():
            print("✅ System firewall rules cleared!")
            print("🔴 Firewall stopped - Network access restored to default")
        
        self.running = False

    def status(self):
        """Display firewall status and statistics."""
        print(f"\n🔥 FIREWALL STATUS: {'🟢 ACTIVE' if self.running else '🔴 STOPPED'}")
        print(f"📊 MONITORING: {'🟢 ACTIVE' if self.engine.is_running else '🔴 STOPPED'}")
        
        stats = self.engine.get_stats()
        print(f"📈 STATISTICS:")
        print(f"   🚫 Blocked: {stats['blocked']}")
        print(f"   ✅ Allowed: {stats['allowed']}")
        print(f"   📋 Logged: {stats['logged']}")

    def interactive_mode(self):
        """Run interactive command mode."""
        print("\n🎯 INTERACTIVE MODE - Type 'help' for commands")
        print("=" * 60)

        while True:
            try:
                cmd = input("\nfirewall> ").strip().lower()
                
                if cmd in ['exit', 'quit', 'q']:
                    break
                elif cmd in ['help', 'h']:
                    self._show_help()
                elif cmd in ['start']:
                    self.start_firewall()
                elif cmd in ['stop']:
                    self.stop_firewall()
                elif cmd in ['status', 'stat']:
                    self.status()
                elif cmd in ['rules', 'r']:
                    self.engine.display_rules()
                elif cmd in ['reload']:
                    if self.engine.load_rules():
                        print("✅ Rules reloaded successfully!")
                        if self.running:
                            print("⚠️  Restart firewall to apply new rules to system")
                elif cmd in ['monitor']:
                    if not self.engine.is_running:
                        self.engine.start_monitoring()
                    else:
                        print("⚠️  Monitoring is already active.")
                elif cmd in ['stopmon']:
                    self.engine.stop_monitoring()
                elif cmd == '':
                    continue
                else:
                    print(f"❌ Unknown command: '{cmd}'. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print("\n🛑 Interrupted...")
                break
            except Exception as e:
                logger.error(f"❌ Error processing command '{cmd}': {e}")

        print("\n👋 Exiting interactive mode...")

    def _show_help(self):
        """Display help information."""
        help_text = """
🎯 AVAILABLE COMMANDS:
   start      - Start the firewall and apply system rules
   stop       - Stop the firewall and clear all rules
   status     - Show firewall status and statistics
   rules      - Display current firewall rules
   reload     - Reload rules from JSON file
   monitor    - Start packet monitoring (if not already running)
   stopmon    - Stop packet monitoring
   help       - Show this help message
   exit/quit  - Exit the application

💡 TIP: Use Ctrl+C to interrupt monitoring or exit gracefully.
        """
        print(help_text)


def main():
    """Main application entry point."""
    parser = argparse.ArgumentParser(
        description="Advanced Personal Firewall - CLI Version",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-f', '--rules-file', default='r1.json', 
                       help='JSON file containing firewall rules (default: r1.json)')
    parser.add_argument('-s', '--start', action='store_true',
                       help='Start firewall immediately')
    parser.add_argument('-m', '--monitor', action='store_true',
                       help='Enable packet monitoring (requires --start)')
    parser.add_argument('--no-monitor', action='store_true',
                       help='Disable packet monitoring when starting')
    parser.add_argument('-i', '--interactive', action='store_true',
                       help='Run in interactive mode')
    parser.add_argument('--status', action='store_true',
                       help='Show current status and exit')
    parser.add_argument('--stop', action='store_true',
                       help='Stop firewall and exit')
    parser.add_argument('--rules', action='store_true',
                       help='Display rules and exit')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print_banner()

    # Initialize CLI
    firewall_cli = FirewallCLI()
    firewall_cli.engine.rules_file = args.rules_file

    # Handle single commands
    if args.stop:
        firewall_cli.stop_firewall()
        return

    if args.status:
        firewall_cli.status()
        return

    if args.rules:
        if firewall_cli.engine.load_rules():
            firewall_cli.engine.display_rules()
        return

    # Handle start command
    if args.start:
        monitor = not args.no_monitor if not args.monitor else args.monitor
        firewall_cli.start_firewall(monitor=monitor)
        
        if not args.interactive:
            try:
                print("\n🔥 Firewall is running. Press Ctrl+C to stop...")
                while firewall_cli.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n🛑 Stopping firewall...")
                firewall_cli.stop_firewall()
            return

    # Interactive mode (default or explicitly requested)
    if args.interactive or not any([args.start, args.stop, args.status, args.rules]):
        try:
            firewall_cli.interactive_mode()
        finally:
            if firewall_cli.running:
                firewall_cli.stop_firewall()


if __name__ == "__main__":
    main()
