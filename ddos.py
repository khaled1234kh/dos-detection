from scapy.all import sniff, conf, rdpcap
from collections import defaultdict
import time

# Parameters
THRESHOLD = 100  # Number of packets per time window
TIME_WINDOW = 10  # seconds

packet_counts = defaultdict(list)

def detect_dos(pkt):
    if pkt.haslayer('IP'):
        src_ip = pkt['IP'].src
        now = time.time()
        packet_counts[src_ip].append(now)
        # Remove timestamps outside the time window
        packet_counts[src_ip] = [t for t in packet_counts[src_ip] if now - t < TIME_WINDOW]
        if len(packet_counts[src_ip]) > THRESHOLD:
            print(f"[ALERT] Possible DOS attack from {src_ip} - {len(packet_counts[src_ip])} packets in {TIME_WINDOW} seconds.")

def main():
    print("Starting DOS detection... Press Ctrl+C to stop.")
    sniff(prn=detect_dos, store=0)

if __name__ == "__main__":
    main()
