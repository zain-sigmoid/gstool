# Code Quality and Security Check Tool
A single Streamlit homepage that links to focused code-quality apps (Maintainability, Readability, Robustness, Compliance, Hardcoded rules, etc.). Compact horizontal cards show issue counts; small tiles open each check.

## ✨ Features
- Homepage hub with compact severity cards (High/Medium/Low/Info) and horizontal nav tiles
- Maintainability (complexity, duplication, dead code)
- Readability (uses Pylint for conventions & clarity)
- Robustness (security, type safety, exception handling)
- Compliance (org/industry policies)
- Hardcoded Secrets (secrets/constants/insecure patterns)
- Dependency Risk (packages & CVEs)
- Injection Attacks (dangerous sinks & taint-like checks)
- Observability (metrics/logs/traces readiness)
- PII/PHI Leakage (data-loss patterns)
- Testability (structure, counts, mapping to tests, coverage)
- You can enable/disable sections by adding/removing tiles on the homepage.

## 🔧 Requirements
- python 3.10+
- streamlit
- ALl requirements from requirements.txt

## Packages
### Macos
- **gitleaks**  
  Install via Homebrew:
  ```bash
  brew install gitleaks

## Quick Start
### Clone the repository
```bash
git clone https://github.com/zain-sigmoid/gstool
cd gstool
```

### Create and activate virtual environment
```bash
python3 -m venv venv
source venv/bin/activate     # macOS/Linux
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Launch the app
```bash
streamlit run Home.py
```






