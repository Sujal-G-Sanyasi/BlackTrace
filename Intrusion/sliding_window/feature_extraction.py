import time
import os
import threading
import pandas as pd
from collections import deque
from scapy.all import sniff
from Intrusion.scapy.packets import get_processed

WINDOW_SIZE = 10
EVALUATION_INTERVAL = 1

packet_window = deque()

def process_and_store(packet):
    data = get_processed(packet)
    if data:
        packet_window.append(data)
        clean_window()

def clean_window():
    now = time.time()
    while packet_window and now - packet_window[0]["timestamp"] > WINDOW_SIZE:
        packet_window.popleft()

def evaluate_window():
    file_path = "Data/Intrusion.csv"

    while True:
        time.sleep(EVALUATION_INTERVAL)

        window_snapshot = list(packet_window)
        total_packets = len(window_snapshot)
        if total_packets == 0:
            print("No Traffic")
            continue

        syn_count = sum(p["syn_flag"] for p in window_snapshot)
        avg_size = sum(p["size"] for p in window_snapshot) / total_packets
        unique_ips = len(set(p["src_ip"] for p in window_snapshot))
        unique_ports = len(set(p["dst_port"] for p in window_snapshot if p["dst_port"]))

        packets_per_sec = total_packets / WINDOW_SIZE
        syn_ratio = syn_count / total_packets

        feature_vector = pd.DataFrame([{
            "timestamp": time.time(),
            "packet_per_sec": packets_per_sec,
            "syn_ratio": syn_ratio,
            "avg_size": avg_size,
            "unique_ips": unique_ips,
            "unique_ports" : unique_ports
        }])
        
        global latest_feature_vector
        latest_feature_vector = feature_vector

        feature_vector.to_csv(
            file_path,
            mode="a",
            header=not os.path.exists(file_path),

            index=False
        )

        print("Packets:", total_packets,
              "Packets/sec:", round(packets_per_sec, 2),
              "SYN ratio:", round(syn_ratio, 2),
              "Unique IPs:", unique_ips)

threading.Thread(target=evaluate_window, daemon=True).start()

threading.Thread(
    target=lambda: sniff(prn=process_and_store, store=False),
    daemon=True
).start()



















