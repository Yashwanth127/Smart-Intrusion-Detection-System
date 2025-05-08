import pyshark
from collections import defaultdict

# Load the PCAP file
pcap_file = pcap_file = r'C:\Users\Tzzs\PycharmProjects\Smart-Intrusion-Detection-System\python_ids\sample_captures\test_traffic.pcap'
capture = pyshark.FileCapture(pcap_file, only_summaries=True)

# Counters
ip_counter = defaultdict(int)
port_counter = defaultdict(int)

# Suspicious ports to flag (common attack targets)
suspicious_ports = ['23', '445', '3389', '21', '22']

print("\n[+] Scanning traffic for suspicious activity...\n")

for packet in capture:
    try:
        # Extract basic fields
        protocol = packet.protocol
        info = packet.info

        # Extract IPs and Ports if present
        src = packet.source
        dst = packet.destination
        ip_counter[src] += 1

        # Check if suspicious port mentioned
        for port in suspicious_ports:
            if port in info:
                print(f"[!] Suspicious port activity detected: Port {port} in {info}")

        # Optional: Print port scan pattern
        if 'Flags [S]' in info and protocol == 'TCP':
            port_line = info.split('>')[-1].strip()
            port_counter[port_line] += 1

    except AttributeError:
        continue  # Skip non-IP packets

# Alert for IPs with high traffic
print("\n[+] IPs with high number of packets:")
for ip, count in ip_counter.items():
    if count > 20:  # Threshold can be adjusted
        print(f"[ALERT] {ip} sent {count} packets")

print("\n✅ Analysis complete.")
capture.close()
