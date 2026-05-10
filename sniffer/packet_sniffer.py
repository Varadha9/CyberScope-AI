from scapy.all import sniff, IP, TCP, UDP, ICMP

captured_packets = []

def process_packet(packet):
    info = {"summary": packet.summary()}
    if IP in packet:
        info["src"] = packet[IP].src
        info["dst"] = packet[IP].dst
        info["proto"] = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "OTHER"
        if TCP in packet:
            info["sport"] = packet[TCP].sport
            info["dport"] = packet[TCP].dport
        elif UDP in packet:
            info["sport"] = packet[UDP].sport
            info["dport"] = packet[UDP].dport
    captured_packets.append(info)
    return info

def start_sniff(count=50, iface="wlan0"):
    captured_packets.clear()
    sniff(prn=process_packet, count=count, store=False, iface=iface)
    return captured_packets
