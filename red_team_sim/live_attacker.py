import socket
import time
import threading

TARGET_IP = input("Enter Target IP (Laptop A): ")

def print_banner(attack_name):
    print(f"\n[!] Launching Live {attack_name} against {TARGET_IP}...")

def live_port_scan():
    print_banner("Reconnaissance (Port Scan)")
    # Probes 60 different ports sequentially
    for port in range(20, 81):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect((TARGET_IP, port))
            s.close()
        except: pass
    print("[+] Port scan complete.")

def live_brute_force():
    print_banner("SSH Brute-Force")
    # Sending 100 packets to ensure it clears the >80 threshold in analyzer.py
    for _ in range(100):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((TARGET_IP, 22))
            s.close()
        except: pass
        time.sleep(0.02)
    print("[+] Brute-force simulation complete.")

def live_dns_tunnel():
    print_banner("DNS Tunneling (C2)")
    # Sends 60 fake DNS (UDP) packets to port 53
    for _ in range(60):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            fake_dns_payload = b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
            s.sendto(fake_dns_payload, (TARGET_IP, 53))
        except: pass
        time.sleep(0.05)
    print("[+] DNS Tunneling complete.")

def live_dos_flood():
    print_banner("High-Volume DoS Flood")
    def flood():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b"X" * 1024  # 1KB packet
        for _ in range(500):
            try: s.sendto(payload, (TARGET_IP, 80))
            except: pass
    
    threads = [threading.Thread(target=flood) for _ in range(5)]
    for t in threads: t.start()
    for t in threads: t.join()
    print("[+] DoS Flood complete.")

while True:
    print("\n" + "="*50)
    print(" ☠️  LIVE RED TEAM SIMULATOR")
    print("="*50)
    print("1. Launch Port Scan")
    print("2. Launch SSH Brute-Force")
    print("3. Launch DNS Tunneling")
    print("4. Launch DoS Flood")
    print("5. Exit")
    
    choice = input("\nSelect attack (1-5): ")
    if choice == '1': live_port_scan()
    elif choice == '2': live_brute_force()
    elif choice == '3': live_dns_tunnel()
    elif choice == '4': live_dos_flood()
    elif choice == '5': break