# ============================================================
# pcap_analyzer.py
# Reads and analyzes an existing .pcap or .pcapng file
#
# Features:
# - Checks if file exists
# - Supports .pcap and .pcapng
# - Shows total packets
# - Shows protocol counts
# - Shows top source IPs
# - Shows top destination IPs
# - Shows top TCP destination ports
# - Shows top UDP destination ports
# - Shows average packet size
#
# Required:
#   pip install scapy
# ============================================================

import os
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, ICMP


def analyze_pcap(path: str):
    """
    Read a PCAP/PCAPNG file and print a traffic summary.
    """

    # --------------------------------------------------------
    # Step 1: Validate file path
    # --------------------------------------------------------
    if not path:
        print("Error: No file path provided.")
        return

    # Remove accidental quotes if user pasted path from Windows
    path = path.strip().strip('"')

    if not os.path.exists(path):
        print(f"Error: File not found -> {path}")
        return

    # --------------------------------------------------------
    # Step 2: Read packets
    # --------------------------------------------------------
    try:
        packets = rdpcap(path)
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # If file loads but contains no packets
    if len(packets) == 0:
        print("The file was opened, but it contains no packets.")
        return

    # --------------------------------------------------------
    # Step 3: Create counters
    # --------------------------------------------------------
    protocol_counter = Counter()
    source_ip_counter = Counter()
    destination_ip_counter = Counter()
    tcp_port_counter = Counter()
    udp_port_counter = Counter()
    packet_sizes = []

    # --------------------------------------------------------
    # Step 4: Process packets
    # --------------------------------------------------------
    for packet in packets:
        packet_sizes.append(len(packet))

        # If packet has an IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            source_ip_counter[src_ip] += 1
            destination_ip_counter[dst_ip] += 1

            # Detect TCP
            if TCP in packet:
                protocol_counter["TCP"] += 1
                tcp_port_counter[packet[TCP].dport] += 1

            # Detect UDP
            elif UDP in packet:
                protocol_counter["UDP"] += 1
                udp_port_counter[packet[UDP].dport] += 1

            # Detect ICMP
            elif ICMP in packet:
                protocol_counter["ICMP"] += 1

            # Other IP protocol
            else:
                protocol_counter["Other IP"] += 1

        # Non-IP packet
        else:
            protocol_counter["Non-IP"] += 1

    # --------------------------------------------------------
    # Step 5: Calculate statistics
    # --------------------------------------------------------
    average_packet_size = sum(packet_sizes) / len(packet_sizes)

    # --------------------------------------------------------
    # Step 6: Print report
    # --------------------------------------------------------
    print("=" * 60)
    print("PCAP ANALYSIS REPORT")
    print("=" * 60)

    print(f"\nFile: {path}")
    print(f"Total packets: {len(packets)}")
    print(f"Average packet size: {average_packet_size:.2f} bytes")

    print("\nProtocol Counts:")
    for proto, count in protocol_counter.most_common():
        print(f"  {proto}: {count}")

    print("\nTop 10 Source IP Addresses:")
    if source_ip_counter:
        for ip, count in source_ip_counter.most_common(10):
            print(f"  {ip}: {count}")
    else:
        print("  No source IP addresses found.")

    print("\nTop 10 Destination IP Addresses:")
    if destination_ip_counter:
        for ip, count in destination_ip_counter.most_common(10):
            print(f"  {ip}: {count}")
    else:
        print("  No destination IP addresses found.")

    print("\nTop 10 TCP Destination Ports:")
    if tcp_port_counter:
        for port, count in tcp_port_counter.most_common(10):
            print(f"  Port {port}: {count}")
    else:
        print("  No TCP packets found.")

    print("\nTop 10 UDP Destination Ports:")
    if udp_port_counter:
        for port, count in udp_port_counter.most_common(10):
            print(f"  Port {port}: {count}")
    else:
        print("  No UDP packets found.")

    print("\nAnalysis completed successfully.")


def main():
    """
    Main menu for user.
    """
    print("PCAP File Analyzer")
    print("-" * 30)
    print("1. Analyze an existing PCAP/PCAPNG file")
    print("2. Exit")

    choice = input("Enter your choice (1 or 2): ").strip()

    if choice == "1":
        file_path = input("Enter full path to your PCAP/PCAPNG file: ").strip()
        analyze_pcap(file_path)

    elif choice == "2":
        print("Program exited.")

    else:
        print("Invalid choice. Please run the program again.")


if __name__ == "__main__":
    main()