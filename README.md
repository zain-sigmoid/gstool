# 🔍 SigScan - Command Line Interface
### Unified analysis tool combining multiple security, quality, and compliance checkers.

## ✨ Features
- 🔐 Security Analysis: Secrets, vulnerabilities, injection attacks
- 🛡️ Privacy Compliance: PII/PHI detection, GDPR/HIPAA compliance
- 📊 Code Quality: Readability, maintainability, performance
- 🧪 Testing & Observability: Test coverage, logging analysis
- 🧰 Maintainability: Cyclomatic Complexity, Maintainability Index
- ⚙️ Performance: Inefficient code patterns, resource usage

## Additional Features & Changes

### Gitleaks Integration
- The CLI automatically ensures gitleaks is available:
- Downloads & sets up Gitleaks into /tmp if not found in PATH
- Falls back to system-installed gitleaks when available
- Uses pure Python (urllib + tarfile) — no wget/tar dependency
- Security analyzers call ensure_gitleaks() before scanning

### Input Modes
- **Project Directory:** Scan a local folder (recommended) as well as through provided Path
- Skips unwanted dirs (__MACOSX, hidden files)
- Guards against path traversal
- Auto-detects likely project root (folder with most .py files)
- **Single File:** Analyze a single .py file when provided instead of Path

## Installing
### From Source
```bash
pip install "git+https://github.com/zain-sigmoid/sigscan-cli.git@main#egg=sigscan"
```

## 🚀 Quick Start

**Scan current directory**
```bash
sigscan . -o output_file.json
```

**Scan any other directory**
```bash
sigscan path -o output_file.json
```

**Scan a single file**
```bash
sigscan file_path/file.py -o output.json
```

## CLI Usage
```bash
usage: sigscan [-h] [-a ANALYZER] [--all-analyzers] [--parallel] [--include-low-confidence] [--timeout TIMEOUT]
               [--max-findings MAX_FINDINGS] [-o FILE] [--compact] [--no-progress] [-v] [--list-analyzers]
               [path]

Run signature scanning/analysis over a path with a configurable setup.

positional arguments:
  path                  File or directory to analyze. By default scan the current folder from terminal

options:
  -h, --help            show this help message and exit
  -a ANALYZER, --analyzer ANALYZER
                        Enable only these analyzers (repeatable, by name).
  --all-analyzers       Enable all available analyzers.
  --parallel            For Parallel Execution of analyzers
  --include-low-confidence
  --timeout TIMEOUT
  --max-findings MAX_FINDINGS
  -o FILE, --out FILE   Write JSON result to FILE (no stdout on success).
  --compact             Minified JSON.
  --no-progress
  -v, --verbose
  --list-analyzers      List available analyzers and exit.
```

## 📤 Output
- JSON file saved in the current directory<br>
This file can be uploaded on the tool to view the result at <a href="https://code-quality.streamlit.app/" target="_blank">Sigscan Tool</a>

## 🧩 Troubleshooting
- **“gitleaks not found”**
<br>
The CLI will auto-download; ensure your environment allows network access and /tmp write permissions. You can also download on MacOS via brew
```bash
brew install gitleaks
```

## 🛠️ Local Development
```bash
git clone https://github.com/zain-sigmoid/sigscan-cli
cd sigscan-cli
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
# run from repo root:
sigscan --help
```

## 📄 License
This project is proprietary and intended for internal use only by authorized Sigmoid Analytics employees and contractors.
