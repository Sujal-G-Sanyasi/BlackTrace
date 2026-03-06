from scapy.all import sniff, IP, TCP, get_if_list, UDP
import time

def get_processed(packet):
    if IP in packet:
        timestamp = time.time()
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        size = len(packet)

        protocol = 'Other'
        dst_port = None
        syn_flag = 0

        if TCP in packet:
            protocol = "TCP"
            dst_port = packet[TCP].dport
            if packet[TCP].flags == 'S':
                syn_flag = 1

        elif UDP in packet:
            protocol = "UDP"
            dst_port = packet[UDP].dport

        return dict(

            timestamp = timestamp,
            src_ip = src_ip,
            dest_ip = dest_ip,
            protocol = protocol,
            size = size,
            dst_port = dst_port,
            syn_flag = syn_flag

        )
    
    return None

