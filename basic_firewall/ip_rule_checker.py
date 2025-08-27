import random
import socket
import json

def load_firewall_rules(filename="rules.json"):
    # in rules.json we can add or alter the rules
    """Loads firewall rules from the JSON file."""
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
            return data.get("rules", [])
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"Warning: {filename} not found or is invalid. Operating with no rules.")
        return []

def get_local_ip_prefix():
    """Finds the local machine's IP address and extracts the network prefix."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip.rsplit('.', 1)[0]
    except Exception:
        return "127.0.0"

def check_rules(packet, rules):
    """Checks a packet against the list of rules and returns the action."""
    for rule in rules:
        ip_host = int(packet['ip'].split('.')[-1])
        host_match = (rule['host'] == ip_host)
        protocol_match = (rule['protocol'] == packet['protocol'] or rule['protocol'] == 'ANY')
        port_match = (rule['port'] == packet['port'] or rule['port'] == 'ANY')
        
        if host_match and protocol_match and port_match:
            return rule['action']
    return "allow"

def main():
    """Main function to run the simulation with complex rules."""
    rules = load_firewall_rules()
    ip_prefix = get_local_ip_prefix()
    
    print(f"--- Running Simulation for Network: {ip_prefix}.0/24 ---")
    print(f"Loaded {len(rules)} rules from rules.json\n")
    
    for _ in range(15):
        packet = {
            "ip": f"{ip_prefix}.{random.randint(0, 25)}",
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "port": random.choice([80, 443, 53, 22])
        }
        
        action = check_rules(packet, rules)
        packet_info = f"IP: {packet['ip']:<15} Proto: {packet['protocol']:<4} Port: {packet['port']}"
        print(f"{packet_info} -> Action: {action.upper()}")

if __name__ == "__main__":
    main()
