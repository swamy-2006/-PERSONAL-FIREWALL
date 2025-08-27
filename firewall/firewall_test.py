import tkinter as tk
from tkinter import messagebox
import json
import socket
from scapy.all import sniff, IP, TCP, UDP, ICMP

# --- GUI Firewall with Domain + Subdomain Blocking ---

def resolve_domain(domain):
    """Resolve domain and all subdomains (basic)."""
    blocked_ips = set()

    try:
        # Get A records (main domain + aliases)
        hostname, aliases, ips = socket.gethostbyname_ex(domain)
        for ip in ips:
            blocked_ips.add(ip)
    except Exception as e:
        print(f"[!] Could not resolve {domain}: {e}")

    # Try www. and m. subdomains as common cases
    for sub in ["www.", "m.", "api."]:
        try:
            hostname, aliases, ips = socket.gethostbyname_ex(sub + domain)
            for ip in ips:
                blocked_ips.add(ip)
        except:
            pass

    return blocked_ips


def load_rules():
    try:
        with open("rules.json", "r") as f:
            return json.load(f)["rules"]
    except:
        return {"rules": []}


def save_rules(rules):
    with open("rules.json", "w") as f:
        json.dump({"rules": rules}, f, indent=4)


def add_rule(domain):
    rules = load_rules()["rules"]
    rules.append({"action": "block", "domain": domain})
    save_rules(rules)
    messagebox.showinfo("Rule Added", f"Blocked {domain} (and subdomains)")


def packet_filter(packet, blocked_ips):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if src_ip in blocked_ips or dst_ip in blocked_ips:
        proto = "OTHER"
        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        elif packet.haslayer(ICMP):
            proto = "ICMP"

        print(f"[BLOCKED] {src_ip} -> {dst_ip} ({proto})")


def start_firewall():
    rules = load_rules()["rules"]
    blocked_ips = set()

    for rule in rules:
        if rule["action"] == "block":
            blocked_ips.update(resolve_domain(rule["domain"]))

    if not blocked_ips:
        messagebox.showwarning("Firewall", "No rules found.")
        return

    messagebox.showinfo("Firewall", "Firewall started. Blocking traffic...")
    sniff(prn=lambda p: packet_filter(p, blocked_ips), store=0)


# --- GUI ---
root = tk.Tk()
root.title("Python Firewall")
root.geometry("400x250")

tk.Label(root, text="Enter domain to block:").pack(pady=5)
entry = tk.Entry(root, width=40)
entry.pack(pady=5)

def on_add():
    domain = entry.get().strip()
    if domain:
        add_rule(domain)

tk.Button(root, text="Add Rule", command=on_add).pack(pady=5)
tk.Button(root, text="Start Firewall", command=start_firewall).pack(pady=5)

root.mainloop()
