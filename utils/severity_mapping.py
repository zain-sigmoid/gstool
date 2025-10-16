class Severity:
    @staticmethod
    def robustness():
        data = [
            {
                "Severity": "High",
                "Description": "Likely to break or misbehave at runtime",
                "Example Code": "Return value mismatch, invalid arguement type, invalid return statement",
            },
            {
                "Severity": "Medium",
                "Description": "Potentially unsafe or may cause incorrect behavior",
                "Example Code": "Wrong Operator, missing/invalid type argument",
            },
            {
                "Severity": "Low",
                "Description": "Style, maintainability, or type-coverage issues",
                "Example Code": "missing function annotations, call to untyped function",
            },
        ]
        return data
    
    @staticmethod
    def pii_phi():
        data = [
            {
                "Severity": "Critical",
                "Description": "Contains highly sensitive personal or financial identifiers that can lead to identity theft or fraud.",
                "Example Code": "Social Security Number (SSN), Credit Card Number",
            },
            {
                "Severity": "High",
                "Description": "Includes personal or government identifiers that can directly identify an individual.",
                "Example Code": "Email, Phone, Aadhaar, PAN, Passport, Driver’s License, Date of Birth, Medical Record Number (MRN)",
            },
            {
                "Severity": "Medium",
                "Description": "Contains indirect identifiers or network information that can be linked to an individual or patient.",
                "Example Code": "IP Address, Patient Name or ID",
            },
        ]
        return data
    
    @staticmethod
    def hardcoded_secret():
        data = [
            {
                "Severity": "Critical",
                "Description": "Contains highly sensitive credentials or private keys that can grant full unauthorized access to systems or data.",
                "Example Code": "private-key, secret-key, aws-secret, rsa-private-key",
            },
            {
                "Severity": "High",
                "Description": "Includes authentication tokens or API keys that expose access to services, repositories, or user accounts.",
                "Example Code": "password, token, api-key, oauth, github-pat",
            },
            {
                "Severity": "Medium",
                "Description": "May contain connection details or URLs that could reveal internal endpoints or partial access credentials.",
                "Example Code": "url, connection-string",
            },
        ]
        return data
    
    @staticmethod
    def testability():
        data = [
            {
                "Severity": "High",
                "Description": "Low overall test coverage indicates high risk of undetected bugs and regressions in production.",
                "Example Code": "Low test coverage across modules (<50%)",
            },
            {
                "Severity": "Medium Overall Files",
                "Description": "No test files or missing test modules reduce confidence in code quality and maintainability.",
                "Example Code": "Missing test files, No test files found",
            },
            {
                "Severity": "Medium Per Functions",
                "Description": "Functions remain untested beyond acceptable thresholds, increasing maintenance and integration risk.",
                "Example Code": "Untested functions (>2)",
            },
            {
                "Severity": "Low",
                "Description": "Few untested functions are acceptable but should be monitored to ensure complete coverage over time.",
                "Example Code": "Untested functions (<=2)",
            },
        ]
        return data
    
    @staticmethod
    def observability():
        data = [
            {
                "Severity": "High",
                "Description": "Critical observability gaps that can hide production failures or block debugging. These include missing logs in critical functions or overall observability score below threshold.",
                "Example Code": "Overall observability score < 30, critical function without logging",
            },
            {
                "Severity": "Medium",
                "Description": "Files or modules with insufficient logging or limited instrumentation, reducing the ability to trace system behavior during incidents.",
                "Example Code": "Files with Poor Observability",
            },
            {
                "Severity": "Low",
                "Description": "Logging present but not structured or standardized, making log analysis and correlation difficult.",
                "Example Code": "Missing Structured Logging",
            },
            {
                "Severity": "Info",
                "Description": "Files with fair observability levels that meet minimum standards but may benefit from richer contextual logs.",
                "Example Code": "Files with Fair Observability",
            },
        ]
        return data
    
    @staticmethod
    def injection():
        data = [
            {
                "Severity": "Critical",
                "Description": "Command or code injection vulnerabilities allow attackers to execute arbitrary system commands or inject malicious code, leading to full system compromise.",
                "Example Code": "Command Injection (CWE-78), Code Injection (CWE-94)",
            },
            {
                "Severity": "High",
                "Description": "Severe injection flaws that can alter program logic, exfiltrate data, or execute malicious scripts on users or servers.",
                "Example Code": "SQL Injection (CWE-89), Cross-Site Scripting (CWE-79), LDAP Injection (CWE-90), XPATH Injection (CWE-643)",
            },
            {
                "Severity": "Medium",
                "Description": "File or path traversal vulnerabilities that allow unauthorized access to system files or directories.",
                "Example Code": "Path Traversal (CWE-22)",
            },
        ]
        return data
    
    @staticmethod
    def maintainability():
        data = [
            {
                "Severity": "High",
                "Description": (
                    "Indicates poor maintainability and high technical debt. "
                    "Typically caused by extremely low Maintainability Index (MI ≤ 10) "
                    "or high cyclomatic complexity (>20). Code at this level is difficult "
                    "to extend, debug, or reuse."
                ),
                "Example Code": "Maintainability Index ≤ 10, Cyclomatic Complexity > 20",
            },
            {
                "Severity": "Medium",
                "Description": (
                    "Moderate maintainability issues that require refactoring or cleanup. "
                    "Caused by MI between 10–20, moderate complexity (>10), or code/function duplication. "
                    "Such code is maintainable but may lead to higher future maintenance cost."
                ),
                "Example Code": "Maintainability Index 10–20, Cyclomatic Complexity 10–20, Function/Code Duplication",
            },
            {
                "Severity": "Info",
                "Description": (
                    "Codebase is generally maintainable with low complexity and a high Maintainability Index. "
                    "No immediate action required, but continuous monitoring is advised."
                ),
                "Example Code": "Maintainability Index > 20, System Rank: Highly/Fairly Maintainable",
            },
        ]
        return data
    
    @staticmethod
    def readability():
        data = [
            {
                "Severity": "Medium",
                "Description": (
                    "Moderate readability issues such as missing documentation or poor formatting "
                    "make code harder to understand and maintain. These do not break functionality "
                    "but reduce clarity for collaborators and future reviewers."
                ),
                "Example Code": (
                    "Missing Module/Class Docstring, Bad or Mixed Indentation, "
                    "Too Many Local Variables, Too Many Arguments, Redefined Outer Name"
                ),
            },
            {
                "Severity": "Low",
                "Description": (
                    "Minor naming, style, or clarity issues that impact consistency or cause minor confusion. "
                    "These include invalid naming conventions, unused imports or variables, and style inconsistencies."
                ),
                "Example Code": (
                    "Invalid Naming Convention, Missing Function Docstring, "
                    "Trailing Whitespace, Missing Final Newline, Line Too Long, "
                    "Unused Import, Unused Variable"
                ),
            },
            {
                "Severity": "Info",
                "Description": (
                    "Code generally follows good readability and documentation practices. "
                    "No major formatting or clarity concerns detected."
                ),
                "Example Code": "Well-documented and consistently formatted codebase",
            },
        ]
        return data
    
    @staticmethod
    def performance():
        data = [
            {
                "Severity": "High",
                "Description": (
                    "Severe performance bottlenecks that can lead to major slowdowns or scalability issues. "
                    "These patterns often result in excessive computational complexity or nested iterations."
                ),
                "Example Code": "High algorithmic complexity (O(n^2)), Deeply nested loops",
            },
            {
                "Severity": "Medium",
                "Description": (
                    "Moderate inefficiencies that can degrade performance on large datasets or in repeated operations. "
                    "Common cases include recursive logic without memoization or inefficient sorting algorithms."
                ),
                "Example Code": "Naive Sorting, Recursive Function Without Memoization",
            },
            {
                "Severity": "Low",
                "Description": (
                    "Minor inefficiencies that typically impact performance only under heavy load. "
                    "These include suboptimal data handling, regex misuse, or frequent string concatenation in loops."
                ),
                "Example Code": "String Concatenation in Loops, Inefficient Data Structures, Inefficient Regex Patterns",
            },
        ]
        return data
    
    @staticmethod
    def compliance():
        data = [
            {
                "Severity": "Medium",
                "Description": (
                    "Moderate compliance issues related to unclear or incomplete licensing and copyright information. "
                    "Such findings can pose legal risks if code ownership or license terms are ambiguous."
                ),
                "Example Code": "License Detections, Copyrights, Holders",
            },
            {
                "Severity": "Low",
                "Description": (
                    "Minor compliance observations such as missing attribution metadata or unverified contact details. "
                    "These do not pose immediate risk but should be corrected for proper documentation."
                ),
                "Example Code": "License Clues, Authors, Emails, URLs",
            },
            {
                "Severity": "Info",
                "Description": (
                    "Informational findings indicating detected license metadata or text coverage. "
                    "These confirm license presence and documentation completeness."
                ),
                "Example Code": "Detected License Expression, Percentage of License Text",
            },
        ]
        return data
