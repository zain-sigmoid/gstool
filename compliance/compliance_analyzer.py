"""
Compliance Analysis Module
Analyzes code for licensing and data-privacy compliance issues.
"""

import os
import subprocess
import json
from pathlib import Path
from collections import defaultdict

# from termcolor import colored
# from file_utils import find_python_files


class ComplianceAnalyzer:
    """Analyzer for code licensing and data privacy compliance issues."""

    def __init__(self, config=None):
        self.config = config or {}
        self.findings = []
        self.score = 100
        # Paths to external tools; adjust as needed
        self.fossology_path = self.config.get("fossology_path", "fossology")
        self.scan_code_toolkit_path = self.config.get(
            "scan_code_toolkit_path", "scancode-toolkit"
        )
        self.semgrep_path = self.config.get("semgrep_path", "semgrep")
        self.codeql_path = self.config.get("codeql_path", "codeql")

    def run_fossology_scan(self, target_path):
        """Runs Fossology to detect licensing issues in the given path."""
        try:
            subprocess.run([self.fossology_path, "analyze", target_path], check=True)
        except subprocess.CalledProcessError:
            # Handle scan failure
            pass

    def run_scancode_toolkit(self, target_path):
        """Runs ScanCode Toolkit to collect licensing metadata."""
        try:
            result = subprocess.run(
                [
                    "scancode",
                    "--license",
                    "--json",
                    "-",
                    target_path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
            return result.stdout
        except subprocess.CalledProcessError:
            pass

    def run_semgrep_rules(
        self, target_path, rules_path="compliance/custom_rules/privacy_rules.yml"
    ):
        """Runs semgrep with custom rules for data privacy checks."""
        try:
            subprocess.run(
                [
                    "semgrep",
                    "scan",
                    target_path,
                    "--config",
                    rules_path,
                    "--json-output=semgrep_output.json",
                ],
                check=True,
            )
        except subprocess.CalledProcessError:
            pass

    def run_codeql_scan(self, database, query_suite):
        """Runs CodeQL queries for data privacy compliance."""
        try:
            subprocess.run(
                [
                    self.codeql_path,
                    "database",
                    "analyze",
                    database,
                    query_suite,
                    "--format=csv",
                    "--output=codeql_results.csv",
                ],
                check=True,
            )
        except subprocess.CalledProcessError:
            pass

    def check_license_compliance(self, codebase_path):
        """Checks for licensing compliance violations using ScanCode Toolkit output."""

        # Run ScanCode with output to file
        output_file = "scancode_report.json"
        try:
            subprocess.run(
                ["scancode", "-clpeui", "--json-pp", output_file, codebase_path],
                check=True,
            )
        except subprocess.CalledProcessError as e:
            self.findings.append(
                {
                    "type": "scancode_error",
                    "severity": "high",
                    "description": f"ScanCode failed to run: {e.stderr if hasattr(e, 'stderr') else str(e)}",
                    "suggestion": "Ensure ScanCode is correctly installed and the path is valid",
                }
            )
            return

        report_file = Path(output_file)
        if not report_file.exists():
            self.findings.append(
                {
                    "type": "report_missing",
                    "severity": "high",
                    "description": "scancode_report.json was not generated.",
                    "suggestion": "Check ScanCode output path or rerun the scan.",
                }
            )
            return

        data = json.loads(report_file.read_text())

        for file_info in data.get("files", []):
            path = file_info.get("path")

            # Check each field and add finding if not empty
            if file_info.get("detected_license_expression"):
                self.findings.append(
                    {
                        "type": "license_compliance",
                        "severity": "info",
                        "file": path,
                        "description": f"Detected license: {file_info['detected_license_expression']}",
                        "suggestion": "Review license for compatibility.",
                    }
                )

            if file_info.get("license_detections"):
                self.findings.append(
                    {
                        "type": "license_compliance",
                        "severity": "medium",
                        "file": path,
                        "description": f"{len(file_info['license_detections'])} license detection(s) found.",
                        "suggestion": "Inspect the license matches and verify usage rights.",
                    }
                )

            if file_info.get("license_clues"):
                self.findings.append(
                    {
                        "type": "license_compliance",
                        "severity": "low",
                        "file": path,
                        "description": "Potential license clues found in file.",
                        "suggestion": "Verify and clarify license references.",
                    }
                )

            if file_info.get("percentage_of_license_text", 0) > 0:
                self.findings.append(
                    {
                        "type": "license_compliance",
                        "severity": "info",
                        "file": path,
                        "description": f"{file_info['percentage_of_license_text']}% license text detected.",
                        "suggestion": "Confirm if this file is a license or contains embedded license.",
                    }
                )

            if file_info.get("copyrights"):
                self.findings.append(
                    {
                        "type": "copyright",
                        "severity": "medium",
                        "file": path,
                        "description": "Copyright statement(s) found.",
                        "suggestion": "Check if attribution is required.",
                    }
                )

            if file_info.get("holders"):
                self.findings.append(
                    {
                        "type": "copyright",
                        "severity": "medium",
                        "file": path,
                        "description": "Copyright holder(s) listed.",
                        "suggestion": "Ensure holder rights are acknowledged properly.",
                    }
                )

            if file_info.get("authors"):
                self.findings.append(
                    {
                        "type": "copyright",
                        "severity": "low",
                        "file": path,
                        "description": "Author(s) found in file.",
                        "suggestion": "Review author obligations if any.",
                    }
                )

            if file_info.get("emails"):
                self.findings.append(
                    {
                        "type": "copyright",
                        "severity": "low",
                        "file": path,
                        "description": f"{len(file_info['emails'])} email(s) found.",
                        "suggestion": "Ensure these do not leak personal data or violate compliance.",
                    }
                )

            if file_info.get("urls"):
                self.findings.append(
                    {
                        "type": "copyright",
                        "severity": "low",
                        "file": path,
                        "description": f"{len(file_info['urls'])} URL(s) found.",
                        "suggestion": "Verify these URLs do not point to prohibited or unverified sources.",
                    }
                )

    def process_semgrep_findings(self, json_path="semgrep_output.json"):
        """Parses Semgrep JSON output and appends structured findings."""
        SEVERITY_MAP = {
            "insecure-transmission": "high",
            "sensitive-data-logging": "high",
            "missing-data-anonymization": "medium",
            "retention-policy-violation": "medium",
            "missing-deletion-mechanism": "low",
        }

        try:
            with open(json_path, "r") as f:
                data = json.load(f)
        except Exception as e:
            self.findings.append(
                {
                    "type": "semgrep_parse_error",
                    "severity": "high",
                    "description": f"Failed to read Semgrep output: {str(e)}",
                    "suggestion": "Ensure semgrep_output.json exists and is valid JSON.",
                }
            )
            return

        grouped_findings = defaultdict(
            lambda: {
                "check_id": "",
                "path": "",
                "lines": [],
                "message": "",
                "severity": "",
                "category": "",
                "compliance": "",
            }
        )

        violation_counter = defaultdict(int)

        for result in data.get("results", []):
            check_id = result.get("check_id", "")
            path = result.get("path", "")
            start_line = result.get("start", {}).get("line")
            msg = result.get("extra", {}).get("message", "")
            sev = result.get("extra", {}).get("severity", "")
            meta = result.get("extra", {}).get("metadata", {})

            key = (path, check_id)
            grouped = grouped_findings[key]

            grouped["check_id"] = check_id
            grouped["path"] = path
            grouped["message"] = msg
            grouped["severity"] = sev
            grouped["category"] = meta.get("category", "")
            grouped["compliance"] = meta.get("compliance", "")
            if start_line:
                grouped["lines"].append(start_line)

            violation_counter[path] += 1

        # Store per-file violation summary
        self.violation_summary = {
            path: f"{count} violation(s)" for path, count in violation_counter.items()
        }
        # Append findings with merged lines
        for (path, check_id), details in grouped_findings.items():
            lines_str = ", ".join(str(ln) for ln in sorted(set(details["lines"])))
            total_violations = violation_counter[details["path"]]
            type_ = details["check_id"].split(".")[-1]
            severity = SEVERITY_MAP.get(type_, "info")
            title = type_.replace("-", " ").title()
            description = ""
            if type_ == "missing-data-anonymization":
                description = (
                    f"{title}: {details['message']} Total in file {total_violations}"
                )
            else:

                description = f"{title}: {details['message']}"
            self.findings.append(
                {
                    "type": "data_privacy",
                    "severity": severity,
                    "file": details["path"],
                    "rule": details["check_id"],
                    "lines": lines_str,
                    "description": (description),
                    "category": details["category"],
                    "compliance": details["compliance"],
                    "suggestion": "Review this code for potential privacy/security issues.",
                }
            )

    def check_data_privacy_compliance(self, codebase_path):
        """Checks for data privacy compliance violations (GDPR, CCPA)."""
        # Run semgrep rules defined for privacy
        self.run_semgrep_rules(codebase_path)
        self.process_semgrep_findings()
        # output = json.loads(semres)
        # print(colored("output", "yellow"), output)
        # Run CodeQL suite for data-handling checks
        # codeql_db = self.config.get("codeql_database", "codeql_db")
        # codeql_queries = self.config.get("codeql_queries", "privacy.qls")
        # self.run_codeql_scan(codeql_db, codeql_queries)

    def analyze(self, codebase_path):
        """Run all compliance checks on provided codebase path."""
        # Discover all files including non-Python for license scans
        # python_files = find_python_files(codebase_path)
        self.check_license_compliance(codebase_path)
        self.check_data_privacy_compliance(codebase_path)
        return {"score": self.score, "findings": self.findings}


# if __name__ == "__main__":
#     import argparse

#     parser = argparse.ArgumentParser(description="Compliance Analyzer Tool")
#     parser.add_argument("path", help="Path to codebase to analyze")
#     args = parser.parse_args()

#     analyzer = ComplianceAnalyzer()
#     results = analyzer.analyze(args.path)
#     print(results)
