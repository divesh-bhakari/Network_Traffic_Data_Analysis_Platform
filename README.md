# Network Traffic Data Analysis Platform Using MachineLearning(NTDAP)

A web-based network traffic analysis tool. Upload a PCAP file and get packet statistics, visualizations, ML anomaly detection, and a plain simple security report.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Packet Parsing | Scapy |
| Data Processing | Pandas, NumPy |
| Machine Learning | Scikit-learn (Isolation Forest) |
| Visualization | Matplotlib |
| Frontend | HTML, CSS, JavaScript |

---

## Project Structure

```
NTDAP/
├── main.py                  ← Flask server (entry point)
├── modules/
│   ├── __init__.py          ← Empty file (required by Python)
│   ├── parser.py            ← Read PCAP, extract packet features
│   ├── cleaner.py           ← Remove duplicates, fix missing values
│   ├── eda.py               ← Calculate statistics
│   ├── analyzer.py          ← ML anomaly detection
│   ├── visualizer.py        ← Generate 6 charts
│   └── interpreter.py       ← Write plain-English report
├── uploads/                 ← Uploaded PCAP files stored here
├── results/                 ← Generated chart images stored here
├── index.html               ← Home page
├── upload.html              ← Upload page
├── results.html             ← Results dashboard
└── requirements.txt
```

---

## Installation & Setup

**1. Create and activate a virtual environment**
```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Make sure your folder structure is correct**

`main.py` and the `modules/` folder must be in the same directory. If all files are flat in one folder, run:
```bash
mkdir modules
move parser.py modules\
move cleaner.py modules\
move eda.py modules\
move analyzer.py modules\
move visualizer.py modules\
move interpreter.py modules\
type nul > modules\__init__.py
mkdir uploads
mkdir results
```

---

## Running the Project

**Start the backend:**
```bash
python main.py
```
Server runs at `http://localhost:5000`

**Open the frontend:**
Open `index.html` in your browser — or serve it:
```bash
python -m http.server 8080
```

---

## Analysis Pipeline

```
Upload PCAP → Parse Packets → Clean Data → EDA Stats
    → ML Anomaly Detection → Generate Charts → Text Report → Results Page
```

---

## API Endpoints

| Method | Route | Description |
|---|---|---|
| GET | `/` | Health check |
| POST | `/upload` | Upload PCAP and run full analysis |
| GET | `/results/<file>` | Serve a chart image |

---

## Common Errors

| Error | Fix |
|---|---|
| `No module named 'flask'` | Run `pip install -r requirements.txt` |
| `No module named 'modules'` | Move module files into a `modules/` folder (see setup above) |
| `Could not connect to backend` | Make sure `python main.py` is running in a terminal |
| Packet count lower than expected | You are using an old `cleaner.py` — update to the latest version |
| Port 5000 already in use | Change `port=5000` to `port=5001` in `main.py` and update the `API` variable in the HTML files |

---

## Test PCAP Files

- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) — good starting point
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net) — real-world captures
- Capture your own using **Wireshark** or `tcpdump`
