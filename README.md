# Ransomware Analyzer

A Python-based application to detect and analyze potential ransomware threats.

## Features

-   **File Analysis:** Scans files for known ransomware signatures (extensions, content patterns, hashes).
-   **Behavioral Analysis (Basic):** Monitors files for suspicious modification patterns.
-   **Command-Line Interface:** Provides tools to scan files and (now) monitor directories.
-   **Logging:** Detailed logging of analysis and actions to console and `analyzer.log`.

### Real-Time Monitoring & AI (New!)

-   **Background Scanning:** The application can monitor a specified directory for file creation and modification events in real-time.
-   **Automated Analysis Pipeline:** Detected events trigger a sequence of analyses:
    -   Standard file checks (hash, extension, content).
    -   Basic behavioral checks.
    -   (Future) Machine learning-based prediction (currently uses a placeholder).
-   **Threat Scoring:** Events are assigned a threat score based on the analysis results.
-   **Automated Isolation:** Files deemed highly threatening (based on hash match or high threat score) are automatically moved to a quarantine directory (`quarantine_zone` in the project root).
-   **ML Scaffolding:** Includes a foundational structure (`ransomware_analyzer/ml_model`) for integrating a machine learning model for advanced threat detection. The current ML prediction is a placeholder.

## Getting Started

### Prerequisites

-   Python 3.x
-   Required packages (see `requirements.txt`)

### Installation & Setup

1.  Clone the repository.
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

### Usage

-   **Analyze a single file:**
    Output will be color-coded for threats (Red) or clean status (Green) if not using JSON logs.
    ```bash
    python -m ransomware_analyzer.main --filepath /path/to/your/file.exe
    ```
-   **Analyze file modification (simulated behavioral check):**
    ```bash
    python -m ransomware_analyzer.main --monitor-file /path/to/file.dat --original-checksum <sha256_sum1> --current-checksum <sha256_sum2>
    ```
-   **Start Real-Time Monitoring:**
    ```bash
    python -m ransomware_analyzer.main --start-monitor /path/to/your/directory_to_watch
    ```
    (Press Ctrl+C to stop monitoring)

### Logging Configuration
-   By default, logs are output in a human-readable string format to console and `analyzer.log`.
-   To enable JSON formatted logs (useful for log management systems):
    ```bash
    python -m ransomware_analyzer.main --filepath /path/to/file --json-logs
    python -m ransomware_analyzer.main --start-monitor /path/to/watch --json-logs
    ```

## Dashboard Interface (Placeholder)

A basic web dashboard interface is under development. To run the placeholder:

1.  Navigate to the `dashboard_ui` directory: `cd dashboard_ui`
2.  Install dashboard-specific dependencies: `pip install -r requirements_dashboard.txt`
3.  Run the Flask app: `python app.py`
4.  Open your browser to `http://127.0.0.1:5001` (or the configured port).
