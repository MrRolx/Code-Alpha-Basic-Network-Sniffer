from scapy.all import sniff, Ether, IP

# Function to process each packet
def process_packet(packet):
    if Ether in packet:
        eth_layer = packet[Ether]
        print("\n" + "="*40)
        print("Ethernet Frame:")
        print(f"  Destination MAC : {eth_layer.dst}")
        print(f"  Source MAC      : {eth_layer.src}")
        print(f"  Type            : {eth_layer.type}")
        print("-" * 40)

        # Check if it's an IPv4 packet and print details
        if IP in packet:
            ip_layer = packet[IP]
            print("IPv4 Packet:")
            print(f"  Source IP       : {ip_layer.src}")
            print(f"  Destination IP  : {ip_layer.dst}")
            print(f"  Version         : {ip_layer.version}")
            print(f"  TTL             : {ip_layer.ttl}")
            print("=" * 40)

# Capture packets
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)