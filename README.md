# NTDAP — Network Traffic Data Analysis Platform
### Simple, readable version

---

## How to Run

### 1. Install dependencies
```
pip install -r requirements.txt
```

### 2. Start the backend
```
cd backend
python main.py
```
Backend runs at: http://localhost:5000

### 3. Open the frontend
Open `frontend/index.html` in your browser
(or serve with: `cd frontend && python -m http.server 8080`)

---

## Project Structure

```
NTDAP/
│
├── frontend/
│   ├── index.html      ← Home/landing page
│   ├── upload.html     ← Upload a PCAP file
│   └── results.html    ← View analysis results
│
├── backend/
│   ├── main.py         ← Flask server (runs the pipeline)
│   ├── modules/
│   │   ├── parser.py       ← Step 1: Read packets from PCAP
│   │   ├── cleaner.py      ← Step 2: Remove bad/missing data
│   │   ├── eda.py          ← Step 3: Calculate statistics
│   │   ├── analyzer.py     ← Step 4: ML anomaly detection
│   │   ├── visualizer.py   ← Step 5: Create charts
│   │   └── interpreter.py  ← Step 6: Write plain-English summary
│   ├── uploads/        ← Uploaded PCAP files are saved here
│   └── results/        ← Generated chart images saved here
│
└── requirements.txt
```

---

## What Each File Does

| File | What it does |
|------|-------------|
| `parser.py` | Uses Scapy to open the PCAP and extract info from each packet into a DataFrame |
| `cleaner.py` | Removes duplicates, fills missing values, drops empty packets |
| `eda.py` | Counts protocols, finds top IPs, calculates average packet sizes etc. |
| `analyzer.py` | Uses Isolation Forest (scikit-learn) to flag unusual packets |
| `visualizer.py` | Draws 6 charts with Matplotlib and saves them as PNG files |
| `interpreter.py` | Turns the stats into plain English sentences |
| `main.py` | Flask server — receives the file, runs all 6 steps, returns JSON |

---

## API Endpoints

| Method | URL | What it does |
|--------|-----|-------------|
| GET | `/` | Health check — confirms server is running |
| POST | `/upload` | Accepts PCAP file, runs full analysis, returns JSON |
| GET | `/results/<filename>` | Serves a chart image |

---

## Where to get test PCAP files
- https://wiki.wireshark.org/SampleCaptures
- Use Wireshark to capture your own traffic
