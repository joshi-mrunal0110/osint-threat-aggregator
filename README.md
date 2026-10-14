
# OSINT Threat Intelligence Aggregator

A Python-based cybersecurity tool that collects Open-Source Intelligence (OSINT) from threat intelligence providers, analyzes indicators of compromise (IOCs), and generates structured reports with a preliminary risk score.

## Features

- **Indicator validation:** Supports IPv4, IPv6, domains, and file hashes (MD5, SHA-1, SHA-256).
- **VirusTotal integration:** Retrieves reputation and file or network indicator analysis statistics.
- **AbuseIPDB integration:** Retrieves abuse confidence scores and IP reporting information.
- **Multi-provider aggregation:** Combines provider results while preserving individual errors.
- **Risk scoring:** Calculates a heuristic risk score using available provider data.
- **JSON reporting:** Generates structured reports with timestamps, risk assessments, and provider results.
- **Error handling:** Handles invalid indicators, API failures, timeouts, and rate limits.
- **Automated tests:** Uses pytest and mocked API responses to test core functionality.

## Technology Stack

- Python
- Requests
- python-dotenv
- pytest
- VirusTotal API v3
- AbuseIPDB API

## Project Structure

```text
osint-threat-aggregator/
├── src/
│   ├── providers/
│   │   ├── virustotal.py
│   │   └── abuseipdb.py
│   ├── validator.py
│   ├── aggregator.py
│   ├── scoring.py
│   ├── report.py
│   └── main.py
├── tests/
├── docs/
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Installation

### 1. Clone the repository

```bash

git clone https://github.com/joshi-mrunal0110/osint-threat-aggregator.git
cd osint-threat-aggregator

```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Configure API keys

Create a local `.env` file in the project root:

```env
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

Obtain API keys from the official provider websites. Never commit your real API keys to GitHub.

## Usage

Run the application with a command-line argument:

```powershell
python -m src.main 8.8.8.8
```

Or launch interactive mode:

```powershell
python -m src.main
```

Enter an IP address, domain, or supported file hash when prompted.

The application prints a JSON report containing the indicator, risk assessment, provider results, and provider errors.

## Running Tests

Run the complete test suite:

```powershell
python -m pytest -v
```

Tests use mocked provider responses to verify core behavior without relying on live API requests.

## Risk Scoring

The application calculates a preliminary score from available provider data and assigns a risk level.

The score is a project-defined heuristic intended to assist initial triage. It is not an official provider classification or proof that an indicator is malicious.

Missing provider data may result in an `Unknown` risk level.

## Security and Limitations

- API access depends on provider permissions, quotas, and availability.
- AbuseIPDB checks IP addresses only.
- Public threat intelligence services may retain submitted indicators or incorporate submissions into their datasets. Use public, non-sensitive indicators for demonstrations.
- A low score does not guarantee that an indicator is safe.
- Verify findings with additional evidence before making incident-response decisions.

## Future Improvements

- Export reports to CSV and HTML.
- Add more threat intelligence providers.
- Introduce configurable scoring rules.
- Build a web dashboard for investigation and visualization.
- Add caching and duplicate-query prevention.

## Disclaimer

This project is intended for educational and defensive cybersecurity research. Use it responsibly and follow each provider's terms of service.
