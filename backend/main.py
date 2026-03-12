# main.py
# This is the main backend file. It runs a web server using Flask.
# It has two main jobs:
#   1. Receive a PCAP file from the frontend
#   2. Run the full analysis pipeline and return the results as JSON

import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Import our analysis modules
from modules.parser      import parse_pcap
from modules.cleaner     import clean_data
from modules.eda         import analyze
from modules.analyzer    import detect_anomalies
from modules.visualizer  import generate_charts
from modules.interpreter import interpret

# ─── App setup ────────────────────────────────────────────
app = Flask(__name__)
CORS(app)   # Allow the frontend (different port) to talk to this backend

# Folders for saving uploaded files and result charts
UPLOAD_FOLDER  = os.path.join(os.path.dirname(__file__), "uploads")
RESULTS_FOLDER = os.path.join(os.path.dirname(__file__), "results")

os.makedirs(UPLOAD_FOLDER,  exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

# ─── Route 1: Health check ────────────────────────────────
@app.route("/")
def home():
    """Simple check to confirm the server is running."""
    return jsonify({"status": "Server is running"})


# ─── Route 2: Upload and analyze ─────────────────────────
@app.route("/upload", methods=["POST"])
def upload():
    """
    Receive a PCAP file, run the full analysis pipeline,
    and return the results as a JSON object.
    """

    # Check that a file was actually sent
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    # Save the uploaded file to the uploads folder
    filename  = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)

    try:
        # ── Step 1: Parse the PCAP file ──────────────────
        print("Step 1: Parsing packets...")
        raw_df = parse_pcap(file_path)

        # ── Step 2: Clean the data ───────────────────────
        print("Step 2: Cleaning data...")
        clean_df = clean_data(raw_df)

        # ── Step 3: Exploratory Data Analysis ────────────
        print("Step 3: Analyzing data...")
        stats = analyze(clean_df)

        # ── Step 4: Detect anomalies with ML ─────────────
        print("Step 4: Detecting anomalies...")
        anomaly_results = detect_anomalies(clean_df)

        # ── Step 5: Generate charts ───────────────────────
        print("Step 5: Generating charts...")
        charts = generate_charts(clean_df, anomaly_results, RESULTS_FOLDER)

        # Convert chart file paths to URLs the frontend can use
        chart_urls = {
            name: f"/results/{os.path.basename(path)}"
            for name, path in charts.items()
        }

        # ── Step 6: Generate interpretation ──────────────
        print("Step 6: Writing interpretation...")
        report = interpret(stats, anomaly_results)

        # ── Step 7: Build and return the response ─────────
        response = {
            "success":      True,
            "filename":     filename,
            "statistics":   stats,
            "anomalies":    anomaly_results,
            "charts":       chart_urls,
            "interpretation": report,
        }

        # Clean up: remove large lists before sending (not needed by frontend)
        response["anomalies"].pop("labels", None)
        response["anomalies"].pop("scores", None)

        return jsonify(response)

    except Exception as e:
        # If anything goes wrong, return a clear error message
        print(f"Error during analysis: {e}")
        return jsonify({"error": str(e)}), 500


# ─── Route 3: Serve chart images ──────────────────────────
@app.route("/results/<filename>")
def get_chart(filename):
    """Send a chart image file to the frontend."""
    return send_from_directory(RESULTS_FOLDER, filename)


# ─── Start the server ─────────────────────────────────────
if __name__ == "__main__":
    print("Starting NTDAP backend on http://localhost:5000")
    app.run(debug=True, port=5000)
