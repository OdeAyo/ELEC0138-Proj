from scapy.all import sniff, TCP
import matplotlib.pyplot as plt
import time

rst_count = 0

def count_rst(pkt):
    global rst_count
    if pkt.haslayer(TCP) and pkt[TCP].flags == "R":
        rst_count += 1

print("[*] Sniffing for TCP RST packets for 10 seconds...")
sniff(filter="tcp", prn=count_rst, timeout=30)

# Show result
print(f"[+] Total TCP RST packets received: {rst_count}")
plt.bar(["TCP RSTs"], [rst_count])
plt.title("TCP Reset Packets Received (Live)")
plt.ylabel("Count")
plt.ylim(0, 100)  # Adjust as needed
plt.show()
