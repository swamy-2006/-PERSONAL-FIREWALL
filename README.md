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
