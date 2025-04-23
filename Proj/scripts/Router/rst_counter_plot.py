import sys
from scapy.all import rdpcap, TCP, IP
import matplotlib.pyplot as plt

# --- Step 1: Handle input ---
if len(sys.argv) != 3:
    print(f"Usage: sudo python3 {sys.argv[0]} <pcap_file>")
    sys.exit(1)

pcap_file = sys.argv[1]
pcap_file2 = sys.argv[2]
target_ip = "192.168.1.36"
rst_count = 0
rst_cnt = 0

# --- Step 2: Load packets from pcap ---
try:
    packets = rdpcap(pcap_file)
    packetsA = rdpcap(pcap_file2)
except Exception as e:
    print(f"Failed to read pcap: {e}")
    sys.exit(1)

# --- Step 3: Count RSTs from source IP ---
for pkt in packets:
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
#        if tcp_layer.flags == "R":
        if ip_layer.dst == target_ip and tcp_layer.flags == "R":
            rst_count += 1

for pkt in packetsA:
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        if ip_layer.dst == target_ip and tcp_layer.flags == "R":
            rst_cnt +=1


# --- Step 4: Plot result ---
print(f"[+] TCP RSTs from {target_ip}: {rst_count}")
print(f"TCP RSTs during attack {rst_cnt}")
plt.bar(["Before"], [rst_count])
plt.bar(["Under Attack"], [rst_cnt])
plt.title(f"TCP RST Packets to {target_ip}")
plt.ylabel("Count")
plt.xlabel("Condition")
plt.ylim(0, rst_cnt + 5)
plt.show()

