import os
import json
import re
import requests
from scapy.all import sniff, IP, TCP, UDP

# Constants
IPINFO_URL = "https://ipinfo.io/{ip}/json"
LOG_FOLDER = "ip_logs"
TV_IP = "192.168.1.36"  # 🔒 Hardcoded TV IP

# Globals
seen_ips = set()
discovery_counter = 1

def sanitize_filename(name):
    return re.sub(r'[^a-zA-Z0-9_\-]', '_', name.strip())

def get_org_from_ip(ip):
    try:
        response = requests.get(IPINFO_URL.format(ip=ip), timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("org", "Unknown_Org")
        else:
            return "Lookup_Failed"
    except Exception:
        return "Lookup_Error"

def save_ip_info(info, org, protocol):
    global discovery_counter

    safe_org = sanitize_filename(org)
    filename = f"{discovery_counter}_{safe_org}.json"
    filepath = os.path.join(LOG_FOLDER, filename)

    data = {
        "src_ip": info["src_ip"],
        "src_port": info["src_port"],
        "dst_ip": info["dst_ip"],
        "dst_port": info["dst_port"],
        "protocol": protocol,
        "org": org
    }

    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

    discovery_counter += 1

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Determine direction and ports
        if src_ip == TV_IP:
            other_ip = dst_ip
            src_port = packet.sport if hasattr(packet, 'sport') else None
            dst_port = packet.dport if hasattr(packet, 'dport') else None
        elif dst_ip == TV_IP:
            other_ip = src_ip
            src_port = packet.sport if hasattr(packet, 'sport') else None
            dst_port = packet.dport if hasattr(packet, 'dport') else None
        else:
            return

        if other_ip not in seen_ips:
            seen_ips.add(other_ip)

            org = get_org_from_ip(other_ip)

            # Detect simple protocol
            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            else:
                protocol = "Unknown"

            print(f"🌐 {other_ip} — {org} ({protocol})")

            info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port
            }

            save_ip_info(info, org, protocol)

def main():
    os.makedirs(LOG_FOLDER, exist_ok=True)
    print(f"\n📁 Logging to folder: {LOG_FOLDER}")
    print(f"🎯 Sniffing traffic involving {TV_IP}... Press Ctrl+C to stop.\n")

    sniff(filter=f"ip host {TV_IP}", prn=packet_callback, store=0)

if __name__ == "__main__":
    main()

