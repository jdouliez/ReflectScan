## ReflectScan — Reflected Parameters Scanner (v1.0)

Detect if HTTP request parameters are reflected in responses. Useful for quickly surfacing potential reflection-based issues (like XSS) across many URLs using fast, multi-threaded scanning.

### Features
- **GET/POST support** for testing parameters
- **Multiple payloads** (simple, special chars, XSS-like) with **risk assessment**
- **Multithreaded** scanning for speed
- **Colorized output** for readability (auto-disabled with `--json`)
- **JSON output** for machine-readable results

### Requirements
- Python 3.8+

Install dependencies:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Quick Start
Run against a single URL:

```bash
python main.py -u "https://example.com/?id=123&name=test"
```

Scan URLs from a file (one URL per line):

```bash
python main.py -f urls.txt
```

Pipe URLs via stdin:

```bash
echo "https://example.com/?q=test" | python main.py
cat urls.txt | python main.py
```

### CLI Usage

```bash
python main.py [-f FILE | -u URL] [--threads N] [-t SECONDS] [--no-color] [--json] [--help-detailed]
```

#### Options
- `-f, --file`      File containing URLs (one per line)
- `-u, --url`       Single URL to test
- `--threads`       Number of threads (default: 10)
- `-t, --timeout`   Request timeout in seconds (default: 10)
- `--no-color`      Disable colorized output
- `--json`          Output results as JSON (disables text output)
- `--help-detailed` Show extended help with examples

### Output

Text output example (grouped by risk levels):

```text
==================================================
ANALYSIS RESULTS
==================================================
[CONFIRM] - 1 result(s)
  URL: https://example.com/?q=test
  Method: GET
  Parameter: q
  Payload: ReflectedParamsScanner<>()="'123
  Status: 200
  Snippet: ...
------------------------------------------------------------
```

JSON output example:

```bash
python main.py -f urls.txt --json > results.json
```

JSON schema (array of results):

```json
[
  {
    "url": "https://example.com/?q=test",
    "method": "GET",
    "parameter": "q",
    "test_value": "ReflectedParamsScanner<()>=\"'123",
    "risk_level": "Confirm",
    "response_snippet": "...",
    "status_code": 200
  }
]
```

Risk levels:
- **Low**: Reflection with simple payload
- **Medium**: Reflection with special characters
- **Confirm**: Reflection with XSS-like payload

### Examples
- Increase threads and timeout:
  ```bash
  python main.py -f urls.txt --threads 20 -t 30
  ```
- Single URL, no color:
  ```bash
  python main.py -u "https://site.com/?id=123" --no-color
  ```
- Pipe and save JSON:
  ```bash
  cat urls.txt | python main.py --json > reflectscan.json
  ```

### Notes and Tips
- The scanner filters out URLs without query parameters.
- SSL verification is disabled for scanning convenience; use in trusted environments.
- Use responsible disclosure and only scan systems you are authorized to test.

### Development
- Run locally with a virtual environment (see Requirements).
- Code entrypoint: `main.py`
- Core class: `ReflectedParamsScanner`

### License
This project is provided as-is. Add a license if you intend to distribute.


