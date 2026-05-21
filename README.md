# MalScan — Static File Analyzer

A cybersecurity tool for **static malware analysis** — no sandboxing, no execution. Drop a file, get a full report.


---

## Features

### File Support
| Format | What's analyzed |
|--------|----------------|
| **EXE / DLL** | PE header, imports, exports, sections, security mitigations (ASLR/DEP/CFG), packer detection, overlay data |
| **PDF** | JavaScript presence, auto-actions, embedded files, XFA, dangerous keywords, external URLs |
| **Office (docx/xlsx)** | VBA macros, auto-executing macros, dangerous functions, DDE fields, external links, OLE objects |
| **Scripts (py/js/ps1/sh/bat/vbs)** | Language-specific dangerous patterns, obfuscation detection, network/execution indicators |

### Analysis Modules
- **Hash computation** — MD5, SHA1, SHA256
- **VirusTotal lookup** — real API v3 integration (optional, free key works)
- **Entropy analysis** — per-file and per-chunk, visualized on a chart
- **PE section entropy** — per-section breakdown for executables
- **String extraction** — ASCII + Unicode, filterable
- **IOC extraction** — IPs, URLs, domains, registry keys, file paths, mutexes
- **Risk scoring** — 0–100 score with detailed factor breakdown

---

## Stack

```
backend/   →  Python + Flask
frontend/  →  HTML + CSS + Vanilla JS (no framework)
```

---

## Installation

### Prerequisites
- Python 3.10+
- `libmagic` (for file type detection)

**Linux / macOS:**
```bash
sudo apt install libmagic1        # Debian/Ubuntu
brew install libmagic             # macOS
```

**Windows:**
```bash
pip install python-magic-bin      # bundles the DLL
```

### Backend

```bash
cd backend
pip install -r requirements.txt
python app.py
```

Backend runs on `http://localhost:5000`

### Frontend

No build step needed. Just open `frontend/index.html` in a browser.

Or serve it:
```bash
cd frontend
python -m http.server 8080
# Open http://localhost:8080
```

---

## Usage

1. Start the backend
2. Open the frontend in a browser
3. Drop a file (or click SELECT FILE)
4. Optionally paste a VirusTotal API key
5. Wait ~2–5 seconds for analysis
6. Browse tabs: Overview → Strings → IOCs → Entropy → Deep Analysis → VirusTotal

**Export**: click `EXPORT JSON` to save the full report.

---

## VirusTotal API

Get a free key at [virustotal.com](https://www.virustotal.com/gui/join-us).

Free tier: 4 requests/minute, 500/day. The key is **never stored** — it's sent once per analysis.

---

## Ethical Use

This tool performs **static analysis only**:
- Files are not executed
- Files are not stored on disk after analysis
- Files are not sent to any third party (except VT hash lookup if you provide a key)

Use responsibly. Do not analyze files you don't own or aren't authorized to test.

---

## Project Structure

```
malscan/
├── backend/
│   ├── app.py                    # Flask API + risk scoring
│   ├── requirements.txt
│   └── analyzers/
│       ├── file_identifier.py    # libmagic + extension mapping
│       ├── hash_analyzer.py      # MD5/SHA1/SHA256 + VT API
│       ├── entropy_analyzer.py   # Shannon entropy per chunk + PE sections
│       ├── pe_analyzer.py        # pefile — PE32/64 deep analysis
│       ├── pdf_analyzer.py       # Raw PDF keyword + metadata scan
│       ├── office_analyzer.py    # OOXML + OLE, VBA macro extraction
│       ├── script_analyzer.py    # Pattern matching per language
│       └── string_extractor.py  # ASCII/Unicode strings + IOC regex
└── frontend/
    ├── index.html
    └── static/
        ├── css/style.css
        └── js/app.js
```

---

## License

MIT
