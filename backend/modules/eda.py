# eda.py
# EDA = Exploratory Data Analysis
# This file looks at the cleaned data and calculates useful statistics.
# It answers questions like:
#   - How many packets were there?
#   - Which protocol was used most?
#   - Who sent the most traffic?

def analyze(df):
    """
    Calculate basic statistics from the packet data.
    Returns a dictionary of stats we can show on the results page.
    """

    stats = {}

    # --- Basic counts ---
    stats["total_packets"] = len(df)
    stats["total_bytes"]   = int(df["packet_length"].sum())

    # --- Packet size info ---
    stats["avg_packet_size"] = round(float(df["packet_length"].mean()), 1)
    stats["min_packet_size"] = int(df["packet_length"].min())
    stats["max_packet_size"] = int(df["packet_length"].max())

    # --- How long was the capture? ---
    if "timestamp" in df.columns:
        duration = df["timestamp"].max() - df["timestamp"].min()
        stats["capture_duration_seconds"] = round(float(duration), 2)
    else:
        stats["capture_duration_seconds"] = 0

    # --- Protocol breakdown ---
    # Count how many packets used each protocol
    protocol_counts = df["protocol"].value_counts()
    stats["protocol_distribution"] = protocol_counts.to_dict()
    stats["most_common_protocol"]  = protocol_counts.index[0] if len(protocol_counts) > 0 else "Unknown"

    # --- Top source IPs (who sent the most packets) ---
    top_src = df["src_ip"].value_counts().head(5)
    stats["top_source_ips"] = top_src.to_dict()
    stats["most_active_src_ip"] = top_src.index[0] if len(top_src) > 0 else "Unknown"

    # --- Top destination IPs (who received the most packets) ---
    top_dst = df["dst_ip"].value_counts().head(5)
    stats["top_destination_ips"] = top_dst.to_dict()

    # --- Top destination ports (which services were used) ---
    top_ports = df["dst_port"].value_counts().head(5)
    stats["top_destination_ports"] = {str(int(k)): int(v) for k, v in top_ports.items()}

    return stats
