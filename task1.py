from scapy.all import sniff, Ether, IP, TCP, UDP, Raw, Dot1Q
from scapy.layers.inet import ICMP

def analyze_packet(packet):
    print("=" * 80)

    # Ethernet layer
    if Ether in packet:
        eth = packet[Ether]
        print(f"[Ethernet] Src MAC: {eth.src}, Dst MAC: {eth.dst}, Type: {hex(eth.type)}")

    # VLAN tagging
    if Dot1Q in packet:
        vlan = packet[Dot1Q]
        print(f"[VLAN] VLAN ID: {vlan.vlan}, Priority: {vlan.prio}, EtherType: {hex(vlan.type)}")

    # IP layer
    if IP in packet:
        ip = packet[IP]
        print(f"[IP] Src IP: {ip.src}, Dst IP: {ip.dst}, Protocol: {ip.proto}")

    # TCP
    if TCP in packet:
        tcp = packet[TCP]
        print(f"[TCP] Src Port: {tcp.sport}, Dst Port: {tcp.dport}")

    # UDP
    elif UDP in packet:
        udp = packet[UDP]
        print(f"[UDP] Src Port: {udp.sport}, Dst Port: {udp.dport}")

    # ICMP
    elif ICMP in packet:
        print("[ICMP] ICMP packet detected")

    # Payload
    if Raw in packet:
        data = packet[Raw].load
        print(f"[Payload] {data[:50]}...")  # Print first 50 bytes of payload

    print("=" * 80)

# Capture packets
print("Starting packet capture... (Press Ctrl+C to stop)")
sniff(prn=analyze_packet, filter="ip", store=0)
