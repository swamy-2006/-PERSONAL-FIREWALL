# PERSONAL-FIREWALL

# *Personal Firewall Setup Guide*

## Prerequisites

### 1. System Requirements
- **Linux**: Full functionality including iptables integration
- **Windows**: Limited functionality (packet inspection only)
- **macOS**: Limited functionality (packet inspection only)

### 2. Install Required Dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip python3-tk

# Install Python packages
pip3 install scapy

# For iptables functionality (Linux only)
sudo apt install iptables

# Optional: Install additional tools
pip3 install psutil  # For system info
```


*Here Two types of firewall are demonstrated*

## **1. BASIC FIREWALL**
 
  This is basic IP rule checker and also ip scanner is inluded
 
 [ip_rule_checker.py](https://github.com/swamy-2006/-PERSONAL-FIREWALL/blob/55c2dfa477feff8cce18110e67ec43e2958c39c2/basic_firewall/ip_rule_checker.py)
*THIS CAN ALSO BE CALLED AS firewall_simulator*

This Python script provides a simple, extensible firewall simulation. It demonstrates how network packets can be filtered based on a set of predefined rules. The simulation reads its configuration from an external JSON file, allowing for easy rule modification without altering the core code.

-----

### **How It Works**

The script operates in three main phases:

1.  **Rule Loading:** It begins by loading firewall rules from `rules.json`. Each rule is an object that specifies criteria (`host`, `protocol`, `port`) and an `action` (`allow` or `deny`). If the file is not found or is malformed, the script will run with no active rules, allowing all packets by default.
2.  **IP Prefix Detection:** The script uses the `socket` library to automatically determine the local machine's IP address and extracts the network prefix (e.g., `192.168.1`). This ensures the simulated traffic is relevant to your local network.
3.  **Packet Simulation & Filtering:** A loop generates 15 simulated network packets. Each packet has a randomly generated IP address, protocol (TCP, UDP, or ICMP), and port number. The `check_rules` function then iterates through the loaded rules to find the first match for a packet. If a match is found, the specified action (`allow` or `deny`) is taken. If no rules match, the packet is allowed by default.

-----

### **Getting Started**

#### **Prerequisites**

You'll need a working Python environment. No special libraries are required beyond the standard library.

#### **Setup**

1.  Save the provided Python code as `firewall_simulation.py`.
2.  Create a file named `rules.json` in the same directory.
3.  Add your desired rules to `rules.json` following the format below.

#### **Sample `rules.json`**

```json
{
  "rules": [
    {
      "host": 2,
      "protocol": "TCP",
      "port": 80,
      "action": "deny"
    },
    {
      "host": 10,
      "protocol": "ANY",
      "port": "ANY",
      "action": "deny"
    }
  ]
}
```

  * **`host`**: The last octet of the IP address (e.g., `10` for `192.168.1.10`).
  * **`protocol`**: Can be "TCP", "UDP", "ICMP", or "ANY".
  * **`port`**: A specific port number (e.g., `80`) or "ANY".
  * **`action`**: The action to take: "allow" or "deny".

*[like this the rules can be added more on our desire/work]*

#### **Running the Script**

To start the simulation, simply run the Python file from your terminal:

```bash
python ip_rule_checker.py
```

The output will display each simulated packet and the action taken by the firewall, providing a clear log of its behavior.
  
-----------------------
  
  [ip_scanner.py](https://github.com/swamy-2006/-PERSONAL-FIREWALL/blob/55c2dfa477feff8cce18110e67ec43e2958c39c2/ip_scanner.py)
*[this can also be called as network scanner]*

 

# Network Scanner - IPv4 Device Discovery Tool

A powerful and easy-to-use Python script for discovering active devices on your local network. This tool performs a fast ARP scan and then enriches the results by gathering additional information such as hostname and device manufacturer.

## Features

  - **Fast Network Scanning:** Uses the ARP protocol via `scapy` for quick and efficient discovery of all active devices on the local network.
  - **Auto-Detection:** Automatically detects your local IP address and network range, simplifying usage.
  - **Detailed Device Information:** For each discovered device, the script retrieves its IP address, MAC address, hostname, and manufacturer.
  - **Concurrent Processing:** Uses threading to perform lookups for multiple devices simultaneously, significantly reducing scan time.
  - **Cross-Platform Support:** Works on Windows, Linux, and macOS.
  - **Formatted Output:** Displays results in a clean, readable table and can also save them to a file.

-----

## Requirements & Installation

The script requires elevated privileges to perform raw packet operations.

### Prerequisites

  - **Python 3.x**
  - **Administrator/Root Privileges:** The script must be run as **Administrator** on Windows or with **sudo** on Linux/macOS.
  - **Npcap (Windows Only):** Required for Scapy to function correctly on Windows. Download and install it from the [Npcap website](https://nmap.org/npcap/).

### How to Run

1.  **Clone or download** the script.
2.  **Open a terminal or command prompt** with administrator privileges.
3.  **Navigate** to the script's directory.
4.  **Execute** the script:

<!-- end list -->

```bash
python3 ip_scanner.py
```

The script will automatically install the necessary Python libraries (`scapy`, `requests`, `psutil`) if they are not already installed.

-----

 
 


# A Combined Basic Firewall Toolkit

This document outlines two complementary Python scripts that form a **basic firewall toolkit**. Together, these tools demonstrate fundamental concepts in network security, including how to filter network traffic and how to discover devices on a network.

***

## 1. Firewall Simulator (`ip_rule_checker.py`)

This script acts as a simple firewall, showing how to apply rules to network traffic. It reads its rules from a `rules.json` file, letting you easily configure which packets to **allow** or **deny** based on criteria like IP address, protocol, and port. The simulation generates random packets and checks them against your custom rules.

### Features
* **Customizable Rules:** Add or modify rules easily in a JSON file.
* **Packet Simulation:** Generates simulated network traffic to test your rules.
* **Clear Logging:** Provides a log of the firewall's actions for each packet.

***

## 2. Network Scanner (`ip_scanner.py`)

This script is a powerful tool for finding active devices on your local network. It performs a fast **ARP scan** and then gathers additional information about each device, such as its hostname and manufacturer. This tool is cross-platform and automates the process of network discovery.

### Features
* **Auto-Detection:** Automatically finds your local IP and network range.
* **Detailed Information:** Retrieves IP address, MAC address, hostname, and manufacturer for each device.
* **Fast Scanning:** Uses efficient methods and multi-threading to speed up the process.

***

## General Requirements and Disclaimer

Both scripts require **elevated privileges** (Administrator on Windows, `sudo` on Linux/macOS) to function. On Windows, the **Npcap** driver is also needed for the network scanner.

## Disclaimer

This tool is intended for **educational and ethical use only**. It should only be used on networks you have explicit permission to scan. Unauthorized network scanning may be illegal and is a violation of the terms of service of many network providers. Be a responsible network user.

-----------------------------------------------




## **2.FIREWALL(advanced than 1st)**

# *Python Personal Firewall*

[firewall.py](https://github.com/swamy-2006/-PERSONAL-FIREWALL/blob/8bda1effda81bb7241c9087b5c87c7c29ed35af9/firewall/firewall.py)


A cross-platform personal firewall application with a graphical user interface (GUI) built using Python's tkinter library. This tool allows you to apply system-level firewall rules and monitor network traffic in real-time based on a configurable set of rules.
Features
Cross-Platform Rule Application: Dynamically applies firewall rules using native system tools:

Linux:
```iptables```

macOS:
```pfctl```

Windows: 
```netsh advfirewall```

Real-time Traffic Monitoring: Uses scapy to sniff network packets and display a live log of network activity.

Configurable Rules: Loads firewall rules from a simple JSON file (r1.json), allowing for easy customization.

Live Statistics: Tracks and displays the number of blocked and allowed packets.

User-friendly GUI: A clean and simple interface for starting/stopping the firewall, reloading rules, and viewing logs.

Requirements
To run this application, you need to have the following Python libraries installed.

```bash
pip install scapy
```


Additionally, you must have administrative or root privileges to apply system-level firewall rules.
How to Run
Save the files: Ensure both the Python script (firewall.py) and the rules file (r1.json) are in the same directory.
Edit the Rules (Optional): Open r1.json in a text editor to define your own firewall rules. See the section below for an example.
Run with Administrator/Root Privileges:
Linux/macOS: Open a terminal and run the script using sudo.

```bash
sudo python3 firewall.py
```


Windows: Open a Command Prompt or PowerShell as an Administrator, navigate to the script's directory, and run the command:
```
python firewall.py
```


Failing to run with these privileges will result in a "Permission Denied" error.
Rule Configuration
The rules are defined in the r1.json file. Each rule is an object within a JSON array.
Example r1.json file:*(change the rules accordingly like mentioned in rules1.json and rules2.json)*

```json

{
    "rules": [
        {
            "action": "allow",
            "protocol": "TCP",
            "dst_port": 80,
            "comment": "Allow all inbound HTTP traffic"
        },
        {
            "action": "block",
            "src_ip": "192.168.1.100",
            "comment": "Block all traffic from a specific IP address"
        },
        {
            "action": "log",
            "protocol": "ICMP",
            "comment": "Log all ping requests"
        }
    ]
}
```


Rule Fields:
action: The action to take on a matching packet. Can be allow, block, or log.

protocol: The network protocol. Can be TCP, UDP, or ICMP. (Optional)

src_ip: A specific source IP address. (Optional)

dst_port: The destination port. (Optional)

comment: A descriptive comment for the rule. (Optional, but recommended)


-------

# Python Firewall (Proof of Concept)

[firewall_test.py](https://github.com/swamy-2006/-PERSONAL-FIREWALL/blob/8fb842cc40781df57c16bce7af7d5b53d5ffb08b/firewall/firewall_test.py)

This project demonstrates the core concepts of a firewall using a graphical user interface (GUI). It is a passive tool designed for educational purposes and is **not a functional firewall**. It can manage a list of rules to detect and log network packets, but it does not actively block or prevent them at the system level.

### Features

* **GUI-based Rule Management**: A simple interface to add domain-based blocking rules.
* **Domain Resolution**: Resolves a domain (e.g., `google.com`) and common subdomains (e.g., `www.google.com`) to their corresponding IP addresses.
* **Passive Packet Detection**: Monitors network traffic and logs packets that match the configured rules to the console.

### How to Use

1.  **Save the file**: Save the Python script and the empty `rules.json` file in the same directory.
2.  **Install dependencies**: This script requires the `scapy` library.
    ```
    pip install scapy
    ```
3.  **Run the script**: Execute the Python file from your terminal.
    ```
    python your_file_name.py
    ```
4.  **Add Rules**: Use the GUI to enter a domain you want to monitor.
5.  **Start Monitoring**: Click "Start Firewall" to begin watching network traffic. All detected packets matching your rules will be printed to your console.

### Limitations

* **Not a Real Firewall**: This tool does not actively block traffic. It is for passive detection and demonstration only.
* **Limited Domain Resolution**: The `resolve_domain` function only checks for a few common subdomains and may not detect all IPs associated with a large website or content delivery network.
* **No Active Rule Display**: The GUI cannot display or manage the rules you have added after they are saved.

  -------------------------

 .

***

### Project Summary

This project has evolved from a basic concept into a robust, cross-platform personal firewall. We began with a simple idea: creating a GUI to apply pre-defined firewall rules. The initial prototype established a solid foundation by using **system-level commands** (`iptables`, `pfctl`, `netsh`) to enforce rules, a crucial step for any functional firewall. It also introduced **multithreading** and a **message queue** to maintain a responsive user interface while monitoring network traffic.

---

### Key Innovations and Final Product

The project's evolution was defined by two major enhancements that transformed it into a more powerful and practical tool:

1.  **Domain and Subdomain Blocking**: We successfully integrated domain-based blocking by dynamically resolving domain names (like `example.com`) to their corresponding IP addresses. This feature allows for more intuitive and flexible rule creation, moving beyond static IP addresses.
2.  **User-Driven Functionality**: The final version of the code is not just a passive monitor but an active defender. It combines the passive packet inspection from your earlier code with the core system-level blocking, providing both security and visibility. The accompanying `README.md` file clearly documents the tool's capabilities and its proper, ethical use.

The final product is a complete and functional firewall. It is a powerful **educational tool** that demonstrates key concepts in cybersecurity, including network packet inspection, system-level rule enforcement, and safe, concurrent programming practices. This project serves as a strong foundation for future development, such as adding a GUI for real-time rule creation or advanced traffic analytics.


------------------------





# CLI VERSION

[firewall_cli.py](https://github.com/swamy-2006/-PERSONAL-FIREWALL/blob/1e802c489a969de0bdb0dbed6696a809c7c36610/firewall_cli.py)

This CLI version will maintain the core functionality while providing a terminal-based interface.I've created a comprehensive CLI version of your firewall application. Here are the key features and improvements:

##  **CLI Firewall Features**

### **Command Line Arguments**
- `--start` / `-s`: Start firewall immediately
- `--stop`: Stop firewall and clear rules
- `--status`: Show current status
- `--rules`: Display loaded rules
- `--interactive` / `-i`: Run in interactive mode
- `--monitor` / `-m`: Enable packet monitoring
- `--no-monitor`: Disable packet monitoring
- `--rules-file` / `-f`: Specify custom rules file
- `--verbose` / `-v`: Enable debug logging

### **Interactive Commands**
When running in interactive mode, you can use:
- `start` - Start firewall
- `stop` - Stop firewall  
- `status` - Show status and stats
- `rules` - Display current rules
- `reload` - Reload rules from file
- `monitor` - Start packet monitoring
- `stopmon` - Stop monitoring
- `help` - Show available commands
- `exit/quit` - Exit application

### **Usage Examples**

```bash
# Basic usage - start interactive mode
python firewall_cli.py

# Start firewall immediately with monitoring
python firewall_cli.py --start --monitor

# Start firewall without monitoring
python firewall_cli.py --start --no-monitor

# Quick status check
python firewall_cli.py --status

# Display rules and exit
python firewall_cli.py --rules

# Use custom rules file
python firewall_cli.py -f custom_rules.json --start

# Stop any running firewall
python firewall_cli.py --stop
```

### **Key Improvements Over GUI Version**

1. **Better Signal Handling**: Graceful shutdown with Ctrl+C
2. **Flexible Operation Modes**: Interactive, single-command, or daemon-like
3. **Enhanced Logging**: Both file and console output
4. **Command Line Arguments**: Full control without interaction
5. **Statistics Tracking**: Real-time packet counters
6. **Error Handling**: Robust error reporting and recovery

### **Prerequisites**
- Administrator/root privileges (required for system firewall modification)
- Python 3.6+
- scapy library: `pip install scapy`
- existing `rules.json` rules file(rules1.json/rules2.json)

The CLI version maintains all the core functionality of your GUI version while providing a more scriptable and automation-friendly interface. It's perfect for server environments, automation scripts, or users who prefer command-line tools.
