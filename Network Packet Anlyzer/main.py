from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        payload = ""

        if protocol == 6 and TCP in packet:  # TCP protocol
            payload = packet[TCP].payload
        elif protocol == 17 and UDP in packet:  # UDP protocol
            payload = packet[UDP].payload

        # Display packet information
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload}")
        print("-" * 50)

def start_sniffing(interface=None):
    print(f"Starting packet sniffing on interface: {interface or 'all interfaces'}")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    # Start sniffing on all interfaces by default
    start_sniffing()
