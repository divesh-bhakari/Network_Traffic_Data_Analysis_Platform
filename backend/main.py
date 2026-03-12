# main.py
# This is the main backend file. It runs a web server using Flask.
# It has two main jobs:
#   1. Receive a PCAP file from the frontend
#   2. Run the full analysis pipeline and return the results as JSON
# Flask backend — receives PCAP, runs the pipeline, returns JSON.
# Structure is the same as before, no changes needed here.
 
import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
 
from modules.parser      import parse_pcap
from modules.cleaner     import clean_data
from modules.eda         import analyze
from modules.analyzer    import detect_anomalies
from modules.visualizer  import generate_charts
from modules.interpreter import interpret
 
app = Flask(__name__)
CORS(app)
 
UPLOAD_FOLDER  = os.path.join(os.path.dirname(__file__), "uploads")
RESULTS_FOLDER = os.path.join(os.path.dirname(__file__), "results")
 
os.makedirs(UPLOAD_FOLDER,  exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)
 
 
@app.route("/")
def home():
    return jsonify({"status": "Server is running"})
 
 
@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
 
    file = request.files["file"]
 
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
 
    filename  = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)
 
    try:
        print("Step 1: Parsing packets...")
        raw_df = parse_pcap(file_path)
 
        print("Step 2: Cleaning data...")
        clean_df = clean_data(raw_df)
 
        print("Step 3: Analyzing data...")
        stats = analyze(clean_df)
 
        print("Step 4: Detecting anomalies...")
        anomaly_results = detect_anomalies(clean_df)
 
        print("Step 5: Generating charts...")
        charts = generate_charts(clean_df, anomaly_results, RESULTS_FOLDER)
 
        chart_urls = {
            name: f"/results/{os.path.basename(path)}"
            for name, path in charts.items()
        }
 
        print("Step 6: Writing interpretation...")
        report = interpret(stats, anomaly_results)
 
        response = {
            "success":        True,
            "filename":       filename,
            "statistics":     stats,
            "anomalies":      anomaly_results,
            "charts":         chart_urls,
            "interpretation": report,
        }
 
        # Remove large raw lists — frontend doesn't need them
        response["anomalies"].pop("labels",  None)
        response["anomalies"].pop("scores",  None)
 
        return jsonify(response)
 
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": str(e)}), 500
 
 
@app.route("/results/<filename>")
def get_chart(filename):
    return send_from_directory(RESULTS_FOLDER, filename)
 
 
if __name__ == "__main__":
    print("Starting NTDAP on http://localhost:5000")
    app.run(debug=True, port=5000)