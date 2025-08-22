import scapy.all as scapy
import json
import logging

# Safe version - only monitors, doesn't modify system firewall
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')


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
    if not packet.haslayer(scapy.IP):
        return

    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    proto = None
    dport = None

    if packet.haslayer(scapy.TCP):
        proto = 'TCP'
        dport = packet[scapy.TCP].dport
    elif packet.haslayer(scapy.UDP):
        proto = 'UDP'
        dport = packet[scapy.UDP].dport
    elif packet.haslayer(scapy.ICMP):
        proto = 'ICMP'

    for rule in rules:
        is_match = True
        if 'src_ip' in rule and rule.get('src_ip') != src_ip:
            is_match = False
        if 'dst_ip' in rule and rule.get('dst_ip') != dst_ip:
            is_match = False
        if 'protocol' in rule and rule.get('protocol') != proto:
            is_match = False
        if 'dst_port' in rule and rule.get('dst_port') != dport:
            is_match = False

        if is_match:
            action = rule['action'].upper()
            reason = rule.get('comment', 'No comment')
            log_message = f"[{action}] SRC:{src_ip} DST:{dst_ip} PROTO:{proto} PORT:{dport} | Rule: {reason}"
            print(log_message)
            logging.info(log_message)
            return


def start_monitoring(rules):
    """Starts the monitoring loop - SAFE VERSION (no system changes)."""
    print("=== SAFE FIREWALL MONITOR (No System Changes) ===")
    print("Monitoring traffic and showing what WOULD be blocked...")
    print("Press Ctrl+C to stop\n")

    try:
        # Monitor on all available interfaces
        scapy.sniff(prn=lambda packet: check_packet(packet, rules), store=0)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
    except Exception as e:
        print(f"Error: {e}")
        print("Try running with administrator/root privileges")


def main():
    print("--- Safe Firewall Monitor ---")
    rules = load_rules()

    if not rules:
        print("No rules loaded. Check if rules1.json exists.")
        return

    print(f"Loaded {len(rules)} rules:")
    for i, rule in enumerate(rules, 1):
        print(f"  {i}. {rule['action'].upper()}: {rule.get('comment', 'No comment')}")

    print()
    start_monitoring(rules)


if __name__ == "__main__":
    main()