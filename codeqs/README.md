# 🔍 Code Review Tool
### Unified analysis platform combining multiple security, quality, and compliance checkers.

## ✨ Features
- 🔐 Security Analysis: Secrets, vulnerabilities, injection attacks
- 🛡️ Privacy Compliance: PII/PHI detection, GDPR/HIPAA compliance
- 📊 Code Quality: Readability, maintainability, performance
- 🧪 Testing & Observability: Test coverage, logging analysis
- 🧰 Maintainability: Cyclomatic Complexity, Maintainability Index
- ⚙️ Performance: Inefficient code patterns, resource usage

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

### Run the Application
```bash
streamlit run main_consolidated.py
```

## 🧪 Analysis

1. Put the folder path of the project you want to analyze into the text box.  
2. Press **Run Analysis** to start scanning.  
3. Wait for the analyzers (Maintainability, Injection, Performance, Privacy) to run.  
4. View the findings in the results panel:
   - Summary metrics (files analyzed, execution time, errors, etc.)
   - Detailed findings with severity, description, and remediation guidance.
