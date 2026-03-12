# analyzer.py
# This file uses Machine Learning to find unusual (anomalous) packets.
#
# We use an algorithm called "Isolation Forest".
# The idea is simple:
#   - Normal packets behave similarly to each other
#   - Anomalous packets are "isolated" (different from the rest)
#   - The algorithm scores each packet: negative score = anomaly

from sklearn.ensemble import IsolationForest
import pandas as pd
import numpy as np


def detect_anomalies(df):
    """
    Use Isolation Forest to find anomalous packets.
    Returns a dictionary with anomaly results.
    """

    # Step 1: Pick the features (columns) we want the model to look at
    # We use packet size, payload size, and TTL — all numeric
    features = ["packet_length", "payload_length", "ttl"]

    # Only keep the columns that actually exist in our data
    features = [f for f in features if f in df.columns]

    # If we don't have enough data or features, skip ML
    if len(df) < 10 or len(features) == 0:
        return {
            "anomaly_count": 0,
            "anomaly_percentage": 0.0,
            "message": "Not enough data for anomaly detection."
        }

    # Step 2: Prepare the feature matrix (just the numbers)
    X = df[features].fillna(0)

    # Step 3: Create and train the Isolation Forest model
    # contamination=0.05 means we expect about 5% of traffic to be anomalous
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)

    # Step 4: Predict — returns 1 (normal) or -1 (anomaly) for each packet
    predictions = model.predict(X)

    # Step 5: Also get anomaly scores (lower = more anomalous)
    scores = model.decision_function(X)

    # Step 6: Count anomalies
    anomaly_count  = int((predictions == -1).sum())
    total          = len(predictions)
    anomaly_pct    = round(anomaly_count / total * 100, 1)

    # Step 7: Find which protocols had the most anomalies
    df_copy = df.copy()
    df_copy["is_anomaly"] = (predictions == -1)
    anomaly_protocols = df_copy[df_copy["is_anomaly"]]["protocol"].value_counts().to_dict()

    return {
        "anomaly_count":       anomaly_count,
        "normal_count":        total - anomaly_count,
        "total_packets":       total,
        "anomaly_percentage":  anomaly_pct,
        "anomaly_by_protocol": anomaly_protocols,
        "labels":              predictions.tolist(),   # used for charts
        "scores":              scores.tolist(),
    }
