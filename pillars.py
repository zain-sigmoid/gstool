# --- Card Data ---
# A list of dictionaries to hold the information for each card.
# This makes it easy to add or modify cards in the future.
cards_data = [
    {
        "icon": "⚖️",
        "title": "Compliance",
        "text": "License Compliance, Data Privacy and Copyright Issues.",
        "page": "pages/Compliance.py",
    },
    {
        "icon": "🔗",
        "title": "Dependency Risk",
        "text": "Ensuring the application is resilient to errors, failures, and unexpected inputs.",
        "page": "pages/Dependency_Risks.py",
    },
    {
        "icon": "🔑",
        "title": "Hardcoded Secrets",
        "text": "Scans hardcoded secrets, API keys, usernames, passwords, and credentials",
        "page": "pages/Hardcoded_Secrets.py",
    },
    {
        "icon": "💉",
        "title": "Injection Attacks",
        "text": "Scan Python files and folders for injection vulnerabilities",
        "page": "pages/Injection_Attacks.py",
    },
    {
        "icon": "🧰",
        "title": "Maintainability",
        "text": "Cyclometic Complexity and Maintainability Index.",
        "page": "pages/Maintainability.py",
    },
    {
        "icon": "🔭",
        "title": "Observability",
        "text": "Correlate metrics, logs, and traces to see system health.",
        "page": "pages/Observability.py",
    },
    {
        "icon": "⚡",
        "title": "Performance",
        "text": "Measuring Complexity, responsiveness, and efficiency of the application.",
        "page": "pages/Performance.py",
    },
    {
        "icon": "🔓",
        "title": "PII PHI Leakage",
        "text": " Scans Python code specifically for Personally Identifiable Information (PII) and Protected Health Information (PHI)",
        "page": "pages/PII_PHI_Leakage.py",
    },
    {
        "icon": "📘",
        "title": "Readability",
        "text": "Enforce naming, docstrings, and layout for clear, consistent code.",
        "page": "pages/Readability.py",
    },
    {
        "icon": "🛡️",
        "title": "Robustness",
        "text": "Analysis of Python code for security, type safety, and robustness issues",
        "page": "pages/Robustness.py",
    },
    {
        "icon": "🧪",
        "title": "Testability",
        "text": "Detects test structure and files. Reports coverage percentage.",
        "page": "pages/Testability.py",
    },
]
