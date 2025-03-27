# Import necessary modules from Scapy
from scapy.all import sniff, IP, Ether, TCP, UDP, Raw

# Function to process captured packets
def packet_callback(packet):
    print("\n---------------- Packet Captured ----------------")

    # Display MAC addresses
    if Ether in packet:
        print(f"Source MAC: {packet[Ether].src} --> Destination MAC: {packet[Ether].dst}")

    # Display IP addresses
    if IP in packet:
        print(f"Source IP: {packet[IP].src} --> Destination IP: {packet[IP].dst}")

    # Display TCP details
    if TCP in packet:
        print(f"TCP Packet: {packet[IP].src}:{packet[TCP].sport} --> {packet[IP].dst}:{packet[TCP].dport}")

    # Display UDP details
    if UDP in packet:
        print(f"UDP Packet: {packet[IP].src}:{packet[UDP].sport} --> {packet[IP].dst}:{packet[UDP].dport}")

    # Display raw data (if available)
    if packet.haslayer(Raw):
        print(f"Payload Data: {packet[Raw].load}")

# Start sniffing packets (filtering only IP packets)
print("Starting real packet sniffing... (Press Ctrl+C to stop)")
sniff(filter="tcp port 80", count=10, prn=packet_callback)
