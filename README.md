# 🔍 Code Review Tool
### Unified analysis platform combining multiple security, quality, and compliance checkers.

## ✨ Features
- 🔐 Security Analysis: Secrets, vulnerabilities, injection attacks
- 🛡️ Privacy Compliance: PII/PHI detection, GDPR/HIPAA compliance
- 📊 Code Quality: Readability, maintainability, performance
- 🧪 Testing & Observability: Test coverage, logging analysis
- 🧰 Maintainability: Cyclomatic Complexity, Maintainability Index
- ⚙️ Performance: Inefficient code patterns, resource usage

## Additional Features & Changes
This repo includes extra functionality to make the tool work smoothly on Streamlit Community Cloud and in production environments:

### Gitleaks Integration
Added ensure_gitleaks() utility that:
- Downloads and sets up Gitleaks automatically in /tmp if it is not already available in the environment.
- Falls back to system-installed gitleaks if found in PATH.
- Uses pure Python (urllib + tarfile) to avoid dependency on wget/tar.
- Securtity analyzers now call ensure_gitleaks() to guarantee gitleaks is present before scanning.

### ZIP File Upload for Projects
- Added project upload support via st.file_uploader for .zip archives.
- Uploaded ZIPs are extracted into /tmp/user_project safely:
- Skips unwanted directories (like __MACOSX or hidden files).
- Protects against path traversal vulnerabilities.
- Automatically detects the likely project root (folder with the most .py files).
- This allows users to upload their entire codebase in one step for analysis.

### Single File Upload
- Added support for uploading and analyzing a single .py file.
- Uploaded files are stored in /tmp/single_file and analyzed directly

## 📦 Running the Tool

### Clone the repo:

```bash
git clone https://github.com/sanjeetarya001/CodeQualityShield
cd codequalityshield
```

### Set Up the Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### Install the dependencies
```bash
pip install -r requirements.txt
```

### Setup .env file same as .env.example

### Run the Application
```bash
streamlit run main_consolidated.py
```

## 🧪 Analysis

1. Put the zip file of the folder of which you want to code review.  
2. Press **Run Analysis** to start scanning.  
3. Wait for the analyzers (Maintainability, Injection, Performance, Privacy) to run.  
4. View the findings in the results panel:
   - Summary metrics (files analyzed, execution time, errors, etc.)
   - Detailed findings with severity, description, and remediation guidance.
