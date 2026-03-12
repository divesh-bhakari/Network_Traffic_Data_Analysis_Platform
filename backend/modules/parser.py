# parser.py
# This file reads a PCAP file and pulls out useful information from each packet.
# Think of it like opening a box of letters and reading the "From", "To", and "Subject" of each one.

from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import pandas as pd


def parse_pcap(file_path):
    """
    Read a PCAP file and return a table (DataFrame) of packet info.
    Each row = one packet. Each column = one feature of that packet.
    """

    # Step 1: Read all packets from the file
    packets = rdpcap(file_path)

    # Step 2: Go through each packet and extract information
    rows = []

    for i, packet in enumerate(packets):

        # Start with empty values for this packet
        row = {
            "packet_number":   i + 1,
            "timestamp":       float(packet.time),
            "packet_length":   len(packet),
            "protocol":        "OTHER",
            "src_ip":          None,
            "dst_ip":          None,
            "src_port":        None,
            "dst_port":        None,
            "ttl":             None,
            "tcp_flags":       None,
            "window_size":     None,
            "payload_length":  0,
            "icmp_type":       None,
        }

        # If the packet has an IP layer, read IP info
        if IP in packet:
            row["src_ip"]  = packet[IP].src    # Who sent it
            row["dst_ip"]  = packet[IP].dst    # Who it's going to
            row["ttl"]     = packet[IP].ttl    # Time To Live (how many hops it can take)

        # If the packet uses TCP (most web traffic)
        if TCP in packet:
            row["protocol"]     = "TCP"
            row["src_port"]     = packet[TCP].sport
            row["dst_port"]     = packet[TCP].dport
            row["tcp_flags"]    = str(packet[TCP].flags)
            row["window_size"]  = packet[TCP].window

            # Identify common TCP-based protocols by port number
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                row["protocol"] = "HTTP"
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                row["protocol"] = "HTTPS"
            elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                row["protocol"] = "SSH"

        # If the packet uses UDP
        elif UDP in packet:
            row["protocol"]  = "UDP"
            row["src_port"]  = packet[UDP].sport
            row["dst_port"]  = packet[UDP].dport

            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                row["protocol"] = "DNS"

        # If the packet is ICMP (ping messages)
        elif ICMP in packet:
            row["protocol"]   = "ICMP"
            row["icmp_type"]  = packet[ICMP].type

        # Try to get the payload (the actual data inside the packet)
        try:
            row["payload_length"] = len(packet.payload)
        except:
            row["payload_length"] = 0

        rows.append(row)

    # Step 3: Turn the list of rows into a Pandas DataFrame (like a spreadsheet)
    df = pd.DataFrame(rows)

    return df
