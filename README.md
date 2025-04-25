# Modular Web Vulnerability Scanner

This repository contains the implementation of a modular, reconnaissance-driven web vulnerability scanner developed for research and applied security testing purposes. The scanner is designed to detect modern web application vulnerabilities through automated subdomain enumeration, parameter extraction, contextual validation, and template-based security checks.

## Key Features

- **Modular Architecture**: Each scanning module (XSS, subdomain takeover, HTTP headers, cache poisoning) is implemented as an independent function.
- **Reconnaissance-Centric Workflow**: Actively enumerates subdomains and endpoints using open-source tools before scanning.
- **Two-Stage Deduplication**: Combines `urldedupe` and `p1radup` for reducing redundant URLs and improving signal-to-noise ratio.
- **Context-Aware XSS Detection**: Leverages Dalfox for accurate payload reflection analysis.
- **Nuclei Template Support**: Detects missing headers and takeover vectors using community-maintained templates.
- **Output-Driven Design**: Logs results in structured text files for post-processing or dashboard integration.

## Directory Structure

```
.
├── requirements.py          # Tool installer and environment preparation
├── scanner.py               # Main scanner script
├── output/                  # Stores scan results
└── scanner-templates/       # Nuclei templates (required structure)
    └── http/
        ├── takeovers/
        └── misconfiguration/
            └── http-missing-security-headers.yaml
```

## Prerequisites

- Python 3.7+
- Go (installed via script)
- Git, curl, wget, cmake
- Internet access for tool installation and enumeration

## Environment Setup

It is recommended to perform all setup and scanning within a Python virtual environment.

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-org/web-vuln-scanner.git
cd web-vuln-scanner
```

### Step 2: Create and Activate Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Run the Setup Script

```bash
python3 requirements.py
source ~/.bashrc
python3 requirements.py
```

## Scanner Execution

```bash
python3 scanner.py --target example.com
```

## Output Files

| File                        | Purpose                                         |
|-----------------------------|-------------------------------------------------|
| `subdomains.txt`           | Discovered subdomains                           |
| `parameters.txt`           | Crawled and archived URLs                       |
| `deduplicated_params_*.txt`| Clean URLs for payload-based testing            |
| `xss_results.txt`          | Reflected and stored XSS matches                |
| `missing_headers.txt`      | HTTP security header misconfiguration findings  |
| `subdomain_takeover.txt`   | Potential subdomain takeover entries            |
| `webcache_poisoning.txt`   | Cache behavior vulnerabilities                  |
| `censysshodan/*.txt`       | Optional fingerprinting using external APIs     |

## Template Paths

Templates are expected in:

```
./scanner-templates/http/takeovers/
./scanner-templates/http/misconfiguration/http-missing-security-headers.yaml
```

## Disclaimer

This tool is intended strictly for authorized testing and academic use. Users must ensure they have explicit permission to scan the specified targets.

## Acknowledgements

Includes or builds upon:
- Dalfox, Nuclei, Katana, Subdominator, AutoPoisoner
- urldedupe, p1radup, Shodan Python
