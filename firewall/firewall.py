import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import scapy.all as scapy
import json
import logging
import subprocess
import platform
import os
import sys
import time

# --- SETUP ---
logging.basicConfig(filename='firewall.log', level=logging.INFO, format='%(asctime)s - %(message)s')


# --- CORE FIREWALL ENGINE ---
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


def load_rules(rules_file='r1.json'):
    """Loads firewall rules from the JSON file."""
    try:
        with open(rules_file, 'r') as f:
            return json.load(f)['rules']
    except Exception as e:
        messagebox.showerror("Error", f"Could not load {rules_file}: {e}")
        return []


def apply_system_rules(rules):
    """Applies firewall rules based on the operating system."""
    system = platform.system()

    try:
        if system == "Linux":
            _apply_linux_rules(rules)
        elif system == "Darwin":
            _apply_macos_rules(rules)
        elif system == "Windows":
            _apply_windows_rules(rules)
        else:
            messagebox.showwarning("Warning", f"Unsupported OS: {system}. Rules cannot be applied at the system level.")
    except subprocess.CalledProcessError as e:
        error_output = e.stderr.decode() if e.stderr else "No error output."
        messagebox.showerror("Error", f"Failed to apply system rules: {e}\nDetails: {error_output}")
    except Exception as e:
        messagebox.showerror("Error", f"Unexpected error applying rules: {e}")


def clear_system_rules():
    """Removes all previously applied rules."""
    system = platform.system()
    try:
        if system == "Linux":
            subprocess.run(["sudo", "iptables", "-F"], check=True)
            subprocess.run(["sudo", "iptables", "-P", "INPUT", "ACCEPT"], check=True)
            subprocess.run(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"], check=True)
            subprocess.run(["sudo", "iptables", "-P", "OUTPUT", "ACCEPT"], check=True)
        elif system == "Darwin":
            subprocess.run(["sudo", "pfctl", "-f", "/etc/pf.conf"], check=True)
            subprocess.run(["sudo", "pfctl", "-d"], check=True)
        elif system == "Windows":
            try:
                subprocess.run(
                    'netsh advfirewall firewall delete rule group="Python Firewall"',
                    shell=True, check=False, capture_output=True, text=True, timeout=30
                )
            except subprocess.TimeoutExpired:
                logging.warning("Clear rules command timed out.")
            except Exception as e:
                logging.warning(f"Could not clear existing rules: {e}")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to clear system rules: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"Unexpected error while clearing rules: {e}")


def _apply_linux_rules(rules):
    """Linux implementation using iptables with proper ALLOW/BLOCK logic."""
    subprocess.run(["sudo", "iptables", "-F"], check=True)
    subprocess.run(["sudo", "iptables", "-P", "INPUT", "DROP"], check=True)
    subprocess.run(["sudo", "iptables", "-P", "FORWARD", "DROP"], check=True)
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
    subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], check=True)
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                   check=True)

    for rule in rules:
        action = "ACCEPT" if rule.get('action') == 'allow' else "DROP"
        command = ["sudo", "iptables", "-A", "INPUT"]

        if 'src_ip' in rule:
            command.extend(["-s", rule['src_ip']])
        if 'dst_port' in rule and 'protocol' in rule:
            command.extend(["-p", rule['protocol'].lower(), "--dport", str(rule['dst_port'])])
        if 'protocol' in rule and rule['protocol'].upper() == 'ICMP':
            command.extend(["-p", "icmp"])
        
        command.extend(["-j", action])
        subprocess.run(command, check=True)


def _apply_macos_rules(rules):
    """macOS implementation using pfctl."""
    pf_rules = [
        "# Python Firewall Rules",
        "set block-policy drop",
        "set skip on lo0",
        ""
    ]

    for rule in rules:
        action = "pass" if rule.get('action') == 'allow' else "block"
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

    pf_rules.append("pass out keep state")
    pf_rules.append("pass in proto tcp from any to any port 22")

    with open('/tmp/pf_firewall_rules.conf', 'w') as f:
        f.write('\n'.join(pf_rules))
    subprocess.run(["sudo", "pfctl", "-f", "/tmp/pf_firewall_rules.conf"], check=True)
    subprocess.run(["sudo", "pfctl", "-e"], check=True)


def _apply_windows_rules(rules):
    """Windows implementation with proper ALLOW/BLOCK rules."""
    try:
        subprocess.run(
            'netsh advfirewall firewall delete rule group="Python Firewall"',
            shell=True, check=False, capture_output=True, text=True, timeout=30
        )
    except Exception as e:
        logging.warning(f"Could not clear existing rules: {e}")

    try:
        subprocess.run(
            "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound",
            shell=True, check=True, timeout=30
        )
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to set firewall policy: {e}")
        return

    for i, rule in enumerate(rules):
        try:
            comment = rule.get("comment", f"Python Firewall Rule {i + 1}")
            rule_name = f"Python Firewall Rule {i + 1}"
            action_cmd = "allow" if rule.get('action') == 'allow' else "block"

            command_parts = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f'name="{rule_name}"',
                f'group="Python Firewall"',
                f'description="{comment}"',
                "dir=in",
                f"action={action_cmd}"
            ]

            if 'protocol' in rule:
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
            
            subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=30,
                check=True
            )
            
        except subprocess.TimeoutExpired:
            logging.warning(f"Rule {i+1} command timed out.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to apply rule {i+1}: {e.stderr}")
        except Exception as e:
            logging.error(f"Unexpected error with rule {i+1}: {e}")


# --- PACKET INSPECTION ENGINE ---
class PacketInspector:
    def __init__(self, rules, log_queue):
        self.rules = rules
        self.log_queue = log_queue
        self.blocked_count = 0
        self.allowed_count = 0

    def inspect_packet(self, packet):
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

        for rule in self.rules:
            if self._match_rule(rule, src_ip, dst_ip, proto, dport):
                action = rule.get('action', 'log').upper()
                reason = rule.get('comment', 'No comment')

                status = "📋 LOGGED"
                if action == 'BLOCK':
                    self.blocked_count += 1
                    status = "🚫 BLOCKED"
                elif action == 'ALLOW':
                    self.allowed_count += 1
                    status = "✅ ALLOWED"
                
                log_message = (f"{status} | {proto or 'IP'} | {src_ip}→{dst_ip}"
                               f"{f':{dport}' if dport else ''} | {reason}")

                self.log_queue.put(log_message)
                logging.info(log_message)
                return

    def _match_rule(self, rule, src_ip, dst_ip, proto, dport):
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


# --- GUI APPLICATION CLASS ---
class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Personal Firewall Control Panel")
        self.root.geometry("950x750")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.log_queue = queue.Queue()
        self.rules = load_rules()
        self.is_running = False
        self.sniffer_thread = None
        self.packet_inspector = PacketInspector(self.rules, self.log_queue)

        self.create_widgets()
        self.display_rules()
        self.root.after(100, self.process_log_queue)
        self.root.after(1000, self.update_stats)

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=5)

        self.start_button = ttk.Button(control_frame, text="🔥 START FIREWALL", command=self.start_firewall)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(control_frame, text="⏹ STOP FIREWALL", command=self.stop_firewall,
                                     state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.reload_button = ttk.Button(control_frame, text="🔄 RELOAD RULES", command=self.reload_rules)
        self.reload_button.pack(side=tk.LEFT, padx=5)

        status_frame = ttk.LabelFrame(main_frame, text="Firewall Status", padding="10")
        status_frame.pack(fill=tk.X, pady=5)

        self.status_label = ttk.Label(status_frame, text="🔴 FIREWALL STOPPED", font=("Arial", 12, "bold"))
        self.status_label.pack(side=tk.LEFT)

        self.stats_label = ttk.Label(status_frame, text="Blocked: 0 | Allowed: 0")
        self.stats_label.pack(side=tk.RIGHT)

        rules_frame = ttk.LabelFrame(main_frame, text="Active Firewall Rules", padding="10")
        rules_frame.pack(fill=tk.BOTH, expand=False, pady=10)

        self.rules_text = scrolledtext.ScrolledText(rules_frame, wrap=tk.WORD, height=10, state=tk.DISABLED)
        self.rules_text.pack(fill=tk.BOTH, expand=True)

        log_frame = ttk.LabelFrame(main_frame, text="Live Network Traffic Monitor", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.log_text = scrolledtext.ScrolledText(
            log_frame, wrap=tk.WORD, state=tk.DISABLED,
            bg="black", fg="lime green", font=("Consolas", 9)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def display_rules(self):
        self.rules_text.config(state=tk.NORMAL)
        self.rules_text.delete('1.0', tk.END)

        if not self.rules:
            self.rules_text.insert(tk.END, "⚠️ No rules found in rules.json\n")
        else:
            allow_count = sum(1 for r in self.rules if r.get('action') == 'allow')
            block_count = sum(1 for r in self.rules if r.get('action') == 'block')
            log_count = sum(1 for r in self.rules if r.get('action') == 'log')

            self.rules_text.insert(tk.END, f"📊 RULE SUMMARY: {len(self.rules)} total rules | ")
            self.rules_text.insert(tk.END, f"✅ {allow_count} ALLOW | 🚫 {block_count} BLOCK | 📋 {log_count} LOG\n\n")

            for i, rule in enumerate(self.rules, 1):
                action = rule.get('action', 'log')
                action_emoji = {"allow": "✅", "block": "🚫", "log": "📋"}.get(action, "❓")
                comment = rule.get('comment', 'No comment')

                rule_details = f"{i:2d}. {action_emoji} {action.upper()}: {comment}"

                if 'protocol' in rule:
                    rule_details += f" | Protocol: {rule['protocol']}"
                if 'dst_port' in rule:
                    rule_details += f" | Port: {rule['dst_port']}"
                if 'src_ip' in rule:
                    rule_details += f" | Source: {rule['src_ip']}"
                if 'dst_ip' in rule:
                    rule_details += f" | Destination: {rule['dst_ip']}"

                self.rules_text.insert(tk.END, rule_details + "\n")

        self.rules_text.config(state=tk.DISABLED)

    def reload_rules(self):
        self.rules = load_rules()
        self.packet_inspector = PacketInspector(self.rules, self.log_queue)
        self.display_rules()
        self.log_queue.put("🔄 Rules reloaded from rules.json")

        if self.is_running:
            self.log_queue.put("⚠️ Restart firewall to apply new rules to system")

    def start_firewall(self):
        if self.is_running:
            return

        self.log_queue.put("🔥 === FIREWALL STARTING ===")
        self.log_queue.put("📋 Applying system-level firewall rules...")

        def apply_rules_thread():
            try:
                apply_system_rules(self.rules)
                self.log_queue.put("✅ System firewall rules applied successfully!")
                self.log_queue.put("👀 Starting packet monitoring...")
                self.sniffer_thread = threading.Thread(target=self.packet_sniffer_worker, daemon=True)
                self.sniffer_thread.start()
            except Exception as e:
                self.log_queue.put(f"❌ Error applying rules: {e}")
                self.is_running = False
                self.root.after(0, self.reset_buttons_after_error)
                return

        self.is_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="🟢 FIREWALL ACTIVE", foreground="green")

        threading.Thread(target=apply_rules_thread, daemon=True).start()

    def reset_buttons_after_error(self):
        """Reset button states after an error occurs."""
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="🔴 FIREWALL STOPPED", foreground="red")

    def stop_firewall(self):
        if not self.is_running:
            return

        self.is_running = False
        self.log_queue.put("🛑 === FIREWALL STOPPING ===")
        self.log_queue.put("🧹 Clearing system firewall rules...")

        def clear_rules_thread():
            try:
                clear_system_rules()
                self.log_queue.put("✅ System firewall rules cleared!")
                self.log_queue.put("🔴 Firewall stopped - Network access restored to default")
            except Exception as e:
                self.log_queue.put(f"⚠️ Error clearing rules: {e}")

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="🔴 FIREWALL STOPPED", foreground="red")

        threading.Thread(target=clear_rules_thread, daemon=True).start()

    def packet_sniffer_worker(self):
        try:
            self.log_queue.put("🚀 Packet sniffer started - Monitoring network traffic...")
            scapy.sniff(prn=self.packet_inspector.inspect_packet, stop_filter=lambda p: not self.is_running)
        except Exception as e:
            self.log_queue.put(f"❌ Packet sniffer error: {e}")

    def update_stats(self):
        """Update statistics display."""
        if hasattr(self, 'packet_inspector'):
            blocked = self.packet_inspector.blocked_count
            allowed = self.packet_inspector.allowed_count
            self.stats_label.config(text=f"🚫 Blocked: {blocked} | ✅ Allowed: {allowed}")
        self.root.after(1000, self.update_stats)

    def process_log_queue(self):
        try:
            while True:
                message = self.log_queue.get_nowait()
                timestamp = time.strftime("%H:%M:%S")
                formatted_message = f"[{timestamp}] {message}"

                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, formatted_message + "\n")
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_log_queue)

    def on_closing(self):
        if self.is_running:
            self.stop_firewall()
            time.sleep(1)
        self.root.destroy()


# --- SCRIPT ENTRY POINT ---
if __name__ == "__main__":
    if not is_admin():
        messagebox.showerror("Permission Denied",
                             "🚨 This firewall must be run as Administrator (Windows) or with sudo (Linux/Mac).\n\n"
                             "This is required to modify system firewall rules.")
        sys.exit(1)

    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()
