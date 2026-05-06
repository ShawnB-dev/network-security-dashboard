# Network Health & Vulnerability Scanner

A comprehensive, modular network security auditing tool and dashboard. This project provides an automated engine to scan hosts for common vulnerabilities, misconfigurations, and exposure, featuring an interactive Streamlit dashboard for real-time analysis and reporting.

## Features

- **Multi-Vector Scanning**: Modular security engine covering:
  - SSL/TLS Audit (Deprecated versions and cipher checks)
  - HTTP Security Header Analysis
  - Open Port & Service Discovery
  - Cookie Security (Secure/HttpOnly flags)
  - Sensitive File Probing (`.env`, `.git`, etc.)
  - Service Fingerprinting with NVD CVE matching
  - IP Reputation & WHOIS lookups
- **Asynchronous Architecture**: Leverages **Celery** and **Redis** for non-blocking, background scan execution.
- **Interactive Dashboard**: A **Streamlit**-based UI for triggering scans and visualizing health scores.
- **Robust Reporting**: Generate and download detailed security reports in **PDF** (via `fpdf2`) and **JSON** formats.
- **Intelligent Caching**: Redis-backed caching (DB 1) for external API hits (NVD, WHOIS) to improve performance and respect rate limits.
- **Dual Interface**: Includes both a web-based Streamlit dashboard and a local **Tkinter** GUI.

## Project Structure

```text
network-security-dashboard/
├── modules/
│   ├── security_engine.py  # Core scanning logic & finding definitions
│   ├── elastic_client.py   # Elasticsearch log integration
│   ├── worker.py           # Celery task & broker configuration
│   ├── reporting.py        # PDF generation logic
│   └── enrichment.py       # Third-party data enrichment (WHOIS)
├── streamlit_app.py        # Main Dashboard entry point
├── gui_app.py              # Tkinter Desktop entry point
├── inspect_cache.py        # Utility to view Redis cache entries
└── requirements.txt        # Project dependencies
```

## Getting Started

### Prerequisites

- **Python 3.8+**
- **Redis**: Required for the Celery message broker and findings cache.
- **Elasticsearch** (Optional): Required if you wish to use the log fetching features.

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/network-security-dashboard.git
   cd network-security-dashboard
   ```

2. **Create a virtual environment and install dependencies**:
   ```bash
   # Create the environment (defaults to .venv folder)
   uv venv

   # On Windows: Allow script execution (run once per session if activation fails)
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

   # Activate on Windows (PowerShell) - Note the dot in .venv
   .\.venv\Scripts\Activate.ps1

   # Activate on Linux/macOS
   source .venv/bin/activate

   # Install dependencies
   uv pip install -r requirements.txt
   ```

3. **Start Redis**:
   Ensure Redis is running on `localhost:6379`.

### Running the Application

To use the full asynchronous capabilities, you must run the background worker and the dashboard simultaneously.

1. **Start the Celery Worker**:
   ```bash
   celery -A modules.security_engine worker --loglevel=info
   ```

2. **Launch the Streamlit Dashboard**:
   ```bash
   streamlit run streamlit_app.py
   ```

3. **(Optional) Run the Desktop GUI**:
   ```bash
   python gui_app.py
   ```

## Utilities

- **Test Connectivity**: Run `python test_redis.py` to verify your connection to Redis DB 0 (Celery) and DB 1 (Cache).
- **Inspect Cache**: Run `python inspect_cache.py` to see the current NVD and WHOIS data stored in your local cache.

### Security Modules

The Network Security Dashboard includes a variety of modules to assess different aspects of network security. Each module targets specific attack vectors and provides actionable findings.

*   **Ping Reachability**
    *   **Description:** Performs a basic ICMP ping to check if a host is reachable and measures the average latency. This helps in quickly determining host availability.
    *   **Attack Vector:** Network Reconnaissance, Host Availability.
*   **Traceroute Path**
    *   **Description:** Maps the network path (hops) from the scanner to the target host. This can reveal the routing infrastructure and potential points of latency or interception.
    *   **Attack Vector:** Network Reconnaissance, Path Analysis.


## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an Issue for any security vectors you'd like to see added to the engine.

---
**Disclaimer**: This tool is intended for authorized security testing only. Always ensure you have explicit permission before scanning any host.
