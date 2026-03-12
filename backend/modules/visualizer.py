# visualizer.py
# This file creates charts (graphs) from the packet data.
# We use Matplotlib and Seaborn to draw the charts.
# Each chart is saved as a PNG image file.

import os
import matplotlib
matplotlib.use("Agg")   # Use non-interactive mode (no popup windows)
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np


def generate_charts(df, anomaly_results, output_folder):
    """
    Create all charts and save them to output_folder.
    Returns a dictionary of chart names and their file paths.
    """

    os.makedirs(output_folder, exist_ok=True)

    chart_paths = {}

    # Chart 1: Protocol Distribution (bar chart)
    path = _protocol_chart(df, output_folder)
    if path:
        chart_paths["protocol_distribution"] = path

    # Chart 2: Top Source IPs (horizontal bar chart)
    path = _top_ips_chart(df, output_folder)
    if path:
        chart_paths["top_source_ips"] = path

    # Chart 3: Packet Size Distribution (histogram)
    path = _packet_size_chart(df, output_folder)
    if path:
        chart_paths["packet_size"] = path

    # Chart 4: Traffic Over Time (line chart)
    path = _timeline_chart(df, output_folder)
    if path:
        chart_paths["traffic_timeline"] = path

    # Chart 5: Top Destination Ports (bar chart)
    path = _ports_chart(df, output_folder)
    if path:
        chart_paths["top_ports"] = path

    # Chart 6: Normal vs Anomaly (scatter plot)
    path = _anomaly_chart(df, anomaly_results, output_folder)
    if path:
        chart_paths["anomaly_scatter"] = path

    return chart_paths


# ─────────────────────────────────────────────
# Individual chart functions
# ─────────────────────────────────────────────

def _protocol_chart(df, folder):
    """Bar chart showing how many packets used each protocol."""
    counts = df["protocol"].value_counts()
    if len(counts) == 0:
        return None

    fig, ax = plt.subplots(figsize=(8, 5))
    counts.plot(kind="bar", ax=ax, color="steelblue", edgecolor="white")
    ax.set_title("Protocol Distribution")
    ax.set_xlabel("Protocol")
    ax.set_ylabel("Number of Packets")
    plt.xticks(rotation=45)
    plt.tight_layout()

    path = os.path.join(folder, "protocol_distribution.png")
    plt.savefig(path)
    plt.close()
    return path


def _top_ips_chart(df, folder):
    """Horizontal bar chart of top 10 source IP addresses."""
    top_ips = df["src_ip"].value_counts().head(10)
    if len(top_ips) == 0:
        return None

    fig, ax = plt.subplots(figsize=(9, 5))
    top_ips.plot(kind="barh", ax=ax, color="teal", edgecolor="white")
    ax.set_title("Top 10 Source IP Addresses")
    ax.set_xlabel("Packet Count")
    ax.invert_yaxis()   # Put the highest bar at the top
    plt.tight_layout()

    path = os.path.join(folder, "top_source_ips.png")
    plt.savefig(path)
    plt.close()
    return path


def _packet_size_chart(df, folder):
    """Histogram showing the distribution of packet sizes."""
    if "packet_length" not in df.columns:
        return None

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(df["packet_length"], bins=40, color="mediumorchid", edgecolor="white")
    ax.set_title("Packet Size Distribution")
    ax.set_xlabel("Packet Size (bytes)")
    ax.set_ylabel("Count")
    plt.tight_layout()

    path = os.path.join(folder, "packet_size.png")
    plt.savefig(path)
    plt.close()
    return path


def _timeline_chart(df, folder):
    """Line chart showing how many packets arrived over time."""
    if "timestamp" not in df.columns:
        return None

    # Divide time into 50 equal buckets and count packets in each
    timestamps = df["timestamp"]
    counts, edges = np.histogram(timestamps, bins=50)
    times = edges[:-1] - edges[0]   # Make times relative (start from 0)

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(times, counts, color="darkorange", linewidth=2)
    ax.fill_between(times, counts, alpha=0.3, color="darkorange")
    ax.set_title("Traffic Volume Over Time")
    ax.set_xlabel("Time (seconds)")
    ax.set_ylabel("Packets per Interval")
    plt.tight_layout()

    path = os.path.join(folder, "traffic_timeline.png")
    plt.savefig(path)
    plt.close()
    return path


def _ports_chart(df, folder):
    """Bar chart of the top destination ports used."""
    port_counts = df["dst_port"].value_counts().head(10)
    port_counts = port_counts[port_counts.index > 0]   # Remove port 0 (no port)
    if len(port_counts) == 0:
        return None

    fig, ax = plt.subplots(figsize=(9, 5))
    port_counts.index = port_counts.index.astype(int).astype(str)
    port_counts.plot(kind="bar", ax=ax, color="indianred", edgecolor="white")
    ax.set_title("Top Destination Ports")
    ax.set_xlabel("Port Number")
    ax.set_ylabel("Packet Count")
    plt.xticks(rotation=45)
    plt.tight_layout()

    path = os.path.join(folder, "top_ports.png")
    plt.savefig(path)
    plt.close()
    return path


def _anomaly_chart(df, anomaly_results, folder):
    """Scatter plot showing normal packets vs anomalous ones."""
    if "labels" not in anomaly_results:
        return None

    labels = anomaly_results["labels"]
    if len(labels) != len(df):
        return None

    sizes = df["packet_length"].fillna(0).values
    ttls  = df["ttl"].fillna(64).values

    colors = ["red" if l == -1 else "steelblue" for l in labels]

    fig, ax = plt.subplots(figsize=(9, 6))
    ax.scatter(sizes, ttls, c=colors, alpha=0.5, s=20)

    # Legend
    from matplotlib.patches import Patch
    legend = [
        Patch(color="steelblue", label="Normal"),
        Patch(color="red",       label="Anomaly"),
    ]
    ax.legend(handles=legend)
    ax.set_title("Anomaly Detection: Packet Size vs TTL")
    ax.set_xlabel("Packet Size (bytes)")
    ax.set_ylabel("TTL")
    plt.tight_layout()

    path = os.path.join(folder, "anomaly_scatter.png")
    plt.savefig(path)
    plt.close()
    return path
