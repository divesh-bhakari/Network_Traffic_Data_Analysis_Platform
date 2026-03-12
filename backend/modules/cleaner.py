# cleaner.py
# This file cleans up the packet data.
# Just like cleaning a dataset in any data science project:
# - Remove rows with missing important info
# - Remove duplicate rows
# - Make sure numbers are actually numbers

import pandas as pd


def clean_data(df):
    """
    Take the raw packet DataFrame and clean it up.
    Returns a cleaner version of the data.
    """

    # Save the original count so we can report how much we removed
    original_count = len(df)

    # Step 1: Remove duplicate packets
    # (Sometimes the same packet gets captured twice)
    df = df.drop_duplicates()

    # Step 2: Remove packets that have no source IP and no destination IP
    # These are broken/useless packets
    df = df.dropna(subset=["src_ip", "dst_ip"])

    # Step 3: Remove packets with zero length (they carry no data)
    df = df[df["packet_length"] > 0]

    # Step 4: Fill in missing numbers with 0
    # For example, if there's no port number, just use 0
    number_columns = ["src_port", "dst_port", "ttl", "window_size", "payload_length", "icmp_type"]
    for col in number_columns:
        df[col] = df[col].fillna(0)

    # Step 5: Make sure packet_length and payload_length are whole numbers
    df["packet_length"]  = df["packet_length"].astype(int)
    df["payload_length"] = df["payload_length"].astype(int)

    # Step 6: Reset the row numbers (index) so they start from 0 again
    df = df.reset_index(drop=True)

    # Print a simple summary of what was cleaned
    removed = original_count - len(df)
    print(f"Cleaning done. Removed {removed} bad packets. {len(df)} packets remaining.")

    return df
