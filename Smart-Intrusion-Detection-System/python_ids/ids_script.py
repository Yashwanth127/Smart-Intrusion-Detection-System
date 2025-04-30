import pyshark

# Load PCAP file
cap = pyshark.FileCapture('sample_captures/test_traffic.pcap')

# Define suspicious ports or IPs for basic detection
suspicious_ports = ['23', '445', '3389']  # Telnet, SMB, RDP
suspicious_ips = ['192.168.1.100']  # Example attacker IP

print("Analyzing packets...\n")

for packet in cap:
    try:
        src = packet.ip.src
        dst = packet.ip.dst
        protocol = packet.transport_layer
        length = packet.length
        info = f"{protocol} | {src} -> {dst} | Length: {length}"

        if packet[protocol].dstport in suspicious_ports or src in suspicious_ips:
            print(f"[ALERT] Suspicious traffic detected: {info}")
    except AttributeError:
        continue  # Skip non-IP packets

print("\n✅ Analysis complete.")
cap.close()
