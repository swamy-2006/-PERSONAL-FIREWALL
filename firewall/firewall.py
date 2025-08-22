import scapy.all as scapy
import json
import logging
import subprocess
import platform
import os
import sys

# --- SETUP ---
# This sets up the 'firewall.log' file for audit purposes.
logging.basicConfig(filename='firewall.log', level=logging.INFO, format='%(asctime)s - %(message)s')


def is_admin():
    """Checks for administrator/root privileges."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        from ctypes import windll
        return windll.shell32.IsUserAnAdmin()


def load_rules(rules_file='rules1.json'):
    """Loads firewall rules from the JSON file."""
    try:
        with open(rules_file, 'r') as f:
            return json.load(f)['rules']
    except Exception as e:
        print("Error loading rules:", e)
        return []


def check_packet(packet, rules):
    """The core logic to inspect a single packet against all rule conditions."""
    if not packet.haslayer(scapy.IP): return

    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    proto = None
    dport = None

    if packet.haslayer(scapy.TCP):
        proto = 'TCP'
        dport = packet.dport
    elif packet.haslayer(scapy.UDP):
        proto = 'UDP'
        dport = packet.dport
    elif packet.haslayer(scapy.ICMP):
        proto = 'ICMP'

    for rule in rules:
        is_match = True
        if 'src_ip' in rule and rule.get('src_ip') != src_ip: is_match = False
        if 'dst_ip' in rule and rule.get('dst_ip') != dst_ip: is_match = False
        if 'protocol' in rule and rule.get('protocol') != proto: is_match = False
        if 'dst_port' in rule and rule.get('dst_port') != dport: is_match = False

        if is_match:
            action = rule['action'].upper()
            reason = rule.get('comment', 'No comment')
            log_message = f"[{action}] SRC:{src_ip} DST:{dst_ip} PROTO:{proto} | Rule: {reason}"
            print(log_message)
            logging.info(log_message)
            return


def apply_system_rules(rules):
    """Applies 'block' rules based on the operating system."""
    system = platform.system()
    print(f"Detected OS: {system}")
    block_rules = [rule for rule in rules if rule.get('action') == 'block']
    if not block_rules:
        print("No 'block' rules to apply.")
        return
    print("Applying system-level blocking rules...")
    if system == "Linux":
        _apply_linux_rules(block_rules)
    elif system == "Darwin":
        _apply_macos_rules(block_rules)
    elif system == "Windows":
        _apply_windows_rules(block_rules)
    else:
        print("Warning: Blocking is not supported for this OS.")
        return
    print("System rules applied.")


def _apply_linux_rules(block_rules):
    """Linux implementation using iptables."""
    subprocess.run(["sudo", "iptables", "-F"], check=True)
    for rule in block_rules:
        command = ["sudo", "iptables", "-A", "INPUT", "-s", rule['src_ip'], "-j", "DROP"]
        subprocess.run(command, check=True)


def _apply_macos_rules(block_rules):
    """macOS implementation using pfctl."""
    temp_pf_rules = "/tmp/pf_rules.conf"
    with open(temp_pf_rules, "w") as f:
        f.write("scrub-anchor \"com.apple/\"\n")
        f.write("nat-anchor \"com.apple/\"\n")
        f.write("rdr-anchor \"com.apple/\"\n")
        f.write("dummynet-anchor \"com.apple/\"\n")
        f.write("anchor \"com.apple/\"\n")
        f.write("block-anchor \"com.apple/\"\n")
        f.write("block drop all\n")
        for rule in block_rules:
            if 'src_ip' in rule:
                f.write(
                    f"pass in quick proto {rule.get('protocol', 'all').lower()} from {rule['src_ip']} to any keep state\n")
    subprocess.run(["sudo", "pfctl", "-f", temp_pf_rules, "-e"], check=True)


def _apply_windows_rules(block_rules):
    """Windows implementation using netsh with a consistent rule name."""
    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=\"Python Firewall Block\""],
                   capture_output=True)
    for i, rule in enumerate(block_rules):
        rule_name = "Python Firewall Block"
        description = rule.get("comment", "Blocked by Python Firewall")
        command = ["netsh", "advfirewall", "firewall", "add", "rule", "name=", rule_name, "description=", description,
                   "dir=in", "action=block"]
        if 'src_ip' in rule:
            command.extend(["remoteip=", rule['src_ip']])
        if 'dst_port' in rule and 'protocol' in rule:
            command.extend(["protocol=", rule['protocol'].lower(), "localport=", str(rule['dst_port'])])
        subprocess.run(command, check=True, capture_output=True)


def start_firewall_monitoring(rules):
    """Starts the monitoring loop."""
    print("Firewall is ACTIVE. Monitoring traffic...")
    try:
        scapy.sniff(prn=lambda packet: check_packet(packet, rules), store=0)
    except KeyboardInterrupt:
        print("\nFirewall stopped.")


def main():
    if not is_admin():
        print("ERROR: This script must be run as Administrator or with sudo.")
        sys.exit(1)
    print("--- Cross-Platform Firewall ---")
    rules = load_rules()
    if not rules:
        print("No rules loaded. Exiting.")
        sys.exit(1)
    apply_system_rules(rules)
    start_firewall_monitoring(rules)


if __name__ == "__main__":
    main()
