# interpreter.py
# This file takes the statistics and anomaly results and writes
# a plain-English explanation of what the network traffic looks like.
# No AI API needed — just simple logic and sentence building.


def interpret(stats, anomaly_results):
    """
    Build a human-readable description of the traffic.
    Returns a dictionary with different sections of the report.
    """

    report = {}

    # --- Summary ---
    total   = stats.get("total_packets", 0)
    proto   = stats.get("most_common_protocol", "Unknown")
    src_ip  = stats.get("most_active_src_ip", "Unknown")
    duration = stats.get("capture_duration_seconds", 0)

    report["summary"] = (
        f"The capture contains {total:,} packets recorded over {duration} seconds. "
        f"The most common protocol is {proto}. "
        f"The most active sender is {src_ip}."
    )

    # --- Traffic type ---
    protocols = stats.get("protocol_distribution", {})
    total_pkt = max(total, 1)

    lines = []
    for proto_name, count in protocols.items():
        pct = round(count / total_pkt * 100, 1)
        lines.append(f"{proto_name}: {count:,} packets ({pct}%)")

    report["protocol_breakdown"] = "Protocol usage breakdown: " + ", ".join(lines) + "."

    # --- Packet size analysis ---
    avg  = stats.get("avg_packet_size", 0)
    mini = stats.get("min_packet_size", 0)
    maxi = stats.get("max_packet_size", 0)

    if avg < 200:
        size_note = "Traffic consists mostly of small packets, typical of control traffic or acknowledgements."
    elif avg < 800:
        size_note = "Mixed packet sizes suggest a combination of interactive and data transfer traffic."
    else:
        size_note = "Large average packet size suggests bulk file transfers or streaming."

    report["packet_size_analysis"] = (
        f"Packet sizes range from {mini} to {maxi} bytes, with an average of {avg} bytes. "
        + size_note
    )

    # --- Anomaly analysis ---
    count   = anomaly_results.get("anomaly_count", 0)
    pct     = anomaly_results.get("anomaly_percentage", 0)
    normal  = anomaly_results.get("normal_count", 0)

    if count == 0:
        anomaly_text = "No anomalies were detected. Traffic appears normal."
    elif pct < 5:
        anomaly_text = (
            f"{count} anomalous packets detected ({pct}% of total). "
            "The anomaly rate is low — this is likely normal network noise."
        )
    elif pct < 15:
        anomaly_text = (
            f"{count} anomalous packets detected ({pct}% of total). "
            "The anomaly rate is moderate. These packets should be reviewed."
        )
    else:
        anomaly_text = (
            f"{count} anomalous packets detected ({pct}% of total). "
            "HIGH anomaly rate — this may indicate unusual or malicious activity."
        )

    report["anomaly_analysis"] = anomaly_text

    # --- Severity level (simple rule) ---
    if pct < 5:
        report["severity"] = "NORMAL"
    elif pct < 15:
        report["severity"] = "MEDIUM"
    else:
        report["severity"] = "HIGH"

    # --- Simple recommendation ---
    if pct > 10:
        report["recommendation"] = "Investigate the anomalous packets and check the flagged IP addresses."
    else:
        report["recommendation"] = "No immediate action required. Continue regular monitoring."

    return report
