from scapy.all import sniff

captured_packets = []

def process_packet(packet):
    summary = packet.summary()
    captured_packets.append(summary)
    return summary

def start_sniff(count=50, iface=None):
    captured_packets.clear()
    sniff(prn=process_packet, count=count, store=False, iface=iface)
    return captured_packets
