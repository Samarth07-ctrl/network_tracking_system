from scapy.all import IP, TCP, UDP, Ether, DNS, DNSQR, wrpcap

def generate_synthetic_pcap():
    print("Generating synthetic network traffic...")
    packets = []

    # --- 1. Generate "Normal" Background Traffic ---
    print("Adding normal HTTP traffic...")
    normal_req = Ether()/IP(src="192.168.1.50", dst="8.8.8.8")/TCP(sport=54321, dport=80, flags="S")
    normal_res = Ether()/IP(src="8.8.8.8", dst="192.168.1.50")/TCP(sport=80, dport=54321, flags="SA")
    packets.extend([normal_req, normal_res])

    # --- 2. Generate the "Port Scan" Attack ---
    attacker_ip = "10.10.10.99"
    target_ip = "192.168.1.200"
    
    print(f"Injecting Port Scan from {attacker_ip}...")
    for target_port in range(1, 26):
        malicious_pkt = Ether()/IP(src=attacker_ip, dst=target_ip)/TCP(sport=44444, dport=target_port, flags="S")
        packets.append(malicious_pkt)

    # --- 3. Generate a "Prohibited Website" DNS query ---
    print("Injecting DNS request for a prohibited website...")
    bad_dns_pkt = Ether()/IP(src="192.168.1.50", dst="8.8.8.8")/UDP(sport=55555, dport=53)/DNS(rd=1, qd=DNSQR(qname="badwebsite.com"))
    packets.append(bad_dns_pkt)

    # --- 4. Save to a PCAP file ---
    filename = "perfect_demo_scan.pcap"
    wrpcap(filename, packets)
    print(f"Success! {len(packets)} packets written to {filename}")

if __name__ == "__main__":
    generate_synthetic_pcap()