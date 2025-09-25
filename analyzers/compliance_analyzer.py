"""
Compliance Analysis Module
Analyzes code for licensing and data-privacy compliance issues.
"""

import os
import subprocess
import json
import asyncio
import logging
import traceback
from typing import List, Dict, Any
from pathlib import Path
from collections import defaultdict
from termcolor import colored
from core.file_utils import find_python_files
from core.interfaces import ComplianceAnalyzer
from core.models import (
    AnalysisConfiguration,
    AnalysisResult,
    AnalysisMetrics,
    UnifiedFinding,
    FindingCategory,
    SeverityLevel,
    ComplexityLevel,
    CodeLocation,
)

logger = logging.getLogger(__name__)


class ComplianceAnalyzer(ComplianceAnalyzer):
    """Analyzer for code licensing and data privacy compliance issues."""

    def __init__(self):
        self.findings = []
        super().__init__("compliance", "1.0.0")
        self.supported_tools = ["ScanCode", "Semgrep"]
        self.quality_categories = [
            "License Compliance",
            "Data Privacy",
            "Copyright Issues",
        ]

    def get_supported_file_types(self) -> List[str]:
        """Return supported file types."""
        return [".py"]

    def get_quality_categories(self) -> List[str]:
        """Get quality categories this analyzer covers."""
        return self.quality_categories

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for this analyzer."""
        return {""}

    def _find_python_files(self, path: str) -> List[str]:
        """Find all Python files under the given path, excluding virtual environments."""
        return find_python_files(path, exclude_test_files=False)

    def check_compliance(self, config: AnalysisConfiguration) -> Dict[str, bool]:
        """Check compliance based on the provided configuration."""
        # Placeholder implementation
        return {"GDPR": True, "CCPA": True}

    async def analyze(self, config: AnalysisConfiguration) -> AnalysisResult:
        """Run all compliance checks on provided codebase path."""
        # Discover all files including non-Python for license scans
        # python_files = find_python_files(codebase_path)
        error_count = 0
        start_time = asyncio.get_event_loop().time()
        python_files = self._find_python_files(config.target_path)
        if not python_files:
            logger.warning(f"No Python files found in {config.target_path}")
            return self._create_empty_result()

        await self.check_license_compliance(config.target_path)
        await self.check_data_privacy_compliance(config.target_path)

        execution_time = asyncio.get_event_loop().time() - start_time
        metrics = AnalysisMetrics(
            analyzer_name=self.name,
            execution_time_seconds=execution_time,
            files_analyzed=len(python_files),
            findings_count=len(self.findings),
            error_count=error_count,
            success=True,
        )
        logger.info(
            f"Compliance analysis completed: {len(self.findings)} findings in {execution_time:.2f}s"
        )
        findings = self._generate_findings(self.findings)
        return AnalysisResult(
            findings=findings,
            metrics=metrics,
            metadata={
                "python_files_count": len(python_files),
            },
        )

    def _generate_findings(
        self,
        results,
    ) -> List[UnifiedFinding]:
        """Generate findings asynchronously."""
        findings = []
        for finding in results:
            unified_finding = UnifiedFinding(
                title=f"Compliance Issue: {finding['type'].replace('_', ' ').title()}",
                severity=finding.get("severity", SeverityLevel.INFO),
                category=FindingCategory.COMPLIANCE,
                description=finding.get("description", ""),
                confidence_score=0.8,
                location=CodeLocation(
                    file_path=finding.get("file", ""),
                    line_number=finding.get("line", 0),
                ),
                remediation_guidance=finding.get("suggestion", ""),
                remediation_complexity=ComplexityLevel.MODERATE,
                source_analyzer=self.name,
                tags={"test_files", "econ_files"},
            )
            findings.append(unified_finding)
        return findings

    def run_semgrep_rules(self, target_path, rules_path="utils/privacy_rules.yml"):
        """Runs semgrep with custom rules for data privacy checks."""
        try:
            subprocess.run(
                [
                    "semgrep",
                    "scan",
                    target_path,
                    "--config",
                    rules_path,
                    "--no-git-ignore",
                    "--json-output=semgrep_output.json",
                ],
                check=True,
            )
        except subprocess.CalledProcessError:
            traceback.print_exc()

    async def check_license_compliance(self, codebase_path):
        """Checks for licensing compliance violations using ScanCode Toolkit output."""

        # Run ScanCode with output to file
        output_file = "scancode_report.json"
        try:
            print(
                colored(f"Scanning codebase scancode at {codebase_path}...", "yellow")
            )
            subprocess.run(
                ["scancode", "-clpeui", "--json-pp", output_file, codebase_path],
                check=True,
            )
        except subprocess.CalledProcessError as e:
            traceback.print_exc()
            self.findings.append(
                {
                    "type": "scancode_error",
                    "severity": SeverityLevel.INFO,
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
                    "severity": SeverityLevel.INFO,
                    "description": "scancode_report.json was not generated.",
                    "suggestion": "Check ScanCode output path or rerun the scan.",
                }
            )
            logger.error("ScanCode report file not found.")
            return

        data = json.loads(report_file.read_text())

        for file_info in data.get("files", []):
            path = file_info.get("path")

            # Check each field and add finding if not empty
            if file_info.get("detected_license_expression"):
                self.findings.append(
                    {
                        "type": "license_compliance",
                        "severity": SeverityLevel.INFO,
                        "file": path,
                        "description": f"Detected license: {file_info['detected_license_expression']}",
                        "suggestion": "Review license for compatibility.",
                    }
                )

            if file_info.get("license_detections"):
                self.findings.append(
                    {
                        "type": "license_compliance",
                        "severity": SeverityLevel.MEDIUM,
                        "file": path,
                        "description": f"{len(file_info['license_detections'])} license detection(s) found.",
                        "suggestion": "Inspect the license matches and verify usage rights.",
                    }
                )

            if file_info.get("license_clues"):
                self.findings.append(
                    {
                        "type": "license_compliance",
                        "severity": SeverityLevel.LOW,
                        "file": path,
                        "description": "Potential license clues found in file.",
                        "suggestion": "Verify and clarify license references.",
                    }
                )

            if file_info.get("percentage_of_license_text", 0) > 0:
                self.findings.append(
                    {
                        "type": "license_compliance",
                        "severity": SeverityLevel.INFO,
                        "file": path,
                        "description": f"{file_info['percentage_of_license_text']}% license text detected.",
                        "suggestion": "Confirm if this file is a license or contains embedded license.",
                    }
                )

            if file_info.get("copyrights"):
                self.findings.append(
                    {
                        "type": "copyright",
                        "severity": SeverityLevel.MEDIUM,
                        "file": path,
                        "description": "Copyright statement(s) found.",
                        "suggestion": "Check if attribution is required.",
                        "line": next(
                            (e["start_line"] for e in file_info.get("copyrights", [])),
                            None,
                        ),
                    }
                )

            if file_info.get("holders"):
                self.findings.append(
                    {
                        "type": "copyright",
                        "severity": SeverityLevel.MEDIUM,
                        "file": path,
                        "description": "Copyright holder(s) listed.",
                        "suggestion": "Ensure holder rights are acknowledged properly.",
                        "line": next(
                            (e["start_line"] for e in file_info.get("holders", [])),
                            None,
                        ),
                    }
                )

            if file_info.get("authors"):
                self.findings.append(
                    {
                        "type": "copyright",
                        "severity": SeverityLevel.LOW,
                        "file": path,
                        "description": "Author(s) found in file.",
                        "suggestion": "Review author obligations if any.",
                        "line": next(
                            (e["start_line"] for e in file_info.get("authors", [])),
                            None,
                        ),
                    }
                )

            if file_info.get("emails"):
                self.findings.append(
                    {
                        "type": "copyright",
                        "severity": SeverityLevel.LOW,
                        "file": path,
                        "description": f"{len(file_info['emails'])} email(s) found.",
                        "line": next(
                            (e["start_line"] for e in file_info.get("emails", [])), None
                        ),
                        "suggestion": "Ensure these do not leak personal data or violate compliance.",
                    }
                )

            if file_info.get("urls"):
                self.findings.append(
                    {
                        "type": "copyright",
                        "severity": SeverityLevel.LOW,
                        "file": path,
                        "description": f"{len(file_info['urls'])} URL(s) found.",
                        "suggestion": "Verify these URLs do not point to prohibited or unverified sources.",
                        "line": next(
                            (e["start_line"] for e in file_info.get("urls", [])),
                            None,
                        ),
                    }
                )

    def process_semgrep_findings(self, json_path="semgrep_output.json"):
        """Parses Semgrep JSON output and appends structured findings."""
        SEVERITY_MAP = {
            "insecure-transmission": SeverityLevel.HIGH,
            "sensitive-data-logging": SeverityLevel.HIGH,
            "missing-data-anonymization": SeverityLevel.MEDIUM,
            "retention-policy-violation": SeverityLevel.MEDIUM,
            "missing-deletion-mechanism": SeverityLevel.LOW,
        }

        try:
            with open(json_path, "r") as f:
                data = json.load(f)
        except Exception as e:
            traceback.print_exc()
            self.findings.append(
                {
                    "type": "semgrep_parse_error",
                    "severity": SeverityLevel.HIGH,
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
            line_number = min(details["lines"])
            total_violations = violation_counter[details["path"]]
            type_ = details["check_id"].split(".")[-1]
            severity = SEVERITY_MAP.get(type_, SeverityLevel.INFO)
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
                    "line": line_number,
                    "description": (description),
                    "category": details["category"],
                    "compliance": details["compliance"],
                    "suggestion": "Review this code for potential privacy/security issues.",
                }
            )

    async def check_data_privacy_compliance(self, codebase_path):
        """Checks for data privacy compliance violations (GDPR, CCPA)."""
        # Run semgrep rules defined for privacy
        self.run_semgrep_rules(codebase_path)
        self.process_semgrep_findings()
