# Flake8: noqa: E501
"""
Observability Analyzer for evaluating logging coverage and observability practices.
Analyzes logging patterns, monitoring coverage, and provides observability recommendations.
"""

import os
import ast
import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from textwrap import shorten
import asyncio
from core.interfaces import QualityAnalyzer
from core.file_utils import find_python_files
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


class ObservabilityAnalyzer(QualityAnalyzer):
    """
    Analyzer for evaluating code observability through logging and monitoring patterns.
    """

    def __init__(self):
        super().__init__("observability", "1.0.0")
        self.quality_categories = ["logging_coverage", "monitoring", "observability"]
        self._initialize_patterns()

    def get_supported_file_types(self) -> List[str]:
        """Return supported file types."""
        return [".py"]

    def get_quality_categories(self) -> List[str]:
        """Get quality categories this analyzer covers."""
        return self.quality_categories

    def get_quality_metrics(self) -> List[str]:
        """Get quality metrics this analyzer can provide."""
        return [
            "logging_coverage_percentage",
            "total_functions_count",
            "functions_with_logging_count",
            "functions_without_logging_count",
            "observability_score",
            "logging_patterns_used",
        ]

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for this analyzer."""
        return {
            "minimum_logging_coverage": 60.0,  # Percentage
            "check_error_handling": True,
            "check_critical_functions": True,
            "exclude_private_methods": True,
            "exclude_test_files": True,
            "require_structured_logging": False,
        }

    async def analyze(self, config: AnalysisConfiguration) -> AnalysisResult:
        """
        Perform observability analysis on the target files.

        Args:
            config: Analysis configuration

        Returns:
            Analysis result with findings and metrics
        """
        findings = []
        error_count = 0
        start_time = asyncio.get_event_loop().time()

        try:
            logger.info(f"Starting observability analysis of {config.target_path}")

            # Find Python files
            python_files = self._find_python_files(config.target_path)
            if not python_files:
                logger.warning(f"No Python files found in {config.target_path}")
                return self._create_empty_result()

            logger.info(f"Found {len(python_files)} Python files to analyze")

            # Get analyzer configuration
            analyzer_config = config.analyzer_configs.get(
                self.name, self.get_default_config()
            )

            # Perform observability analysis
            analysis_results = await self._perform_observability_analysis(
                python_files, analyzer_config
            )

            # Generate findings based on analysis
            findings = await self._generate_findings(
                analysis_results, config.target_path, analyzer_config
            )

            execution_time = asyncio.get_event_loop().time() - start_time

            metrics = AnalysisMetrics(
                analyzer_name=self.name,
                execution_time_seconds=execution_time,
                files_analyzed=len(python_files),
                findings_count=len(findings),
                error_count=error_count,
                success=True,
            )

            logger.info(
                f"Observability analysis completed: {len(findings)} findings in {execution_time:.2f}s"
            )

            return AnalysisResult(
                findings=findings,
                metrics=metrics,
                metadata={
                    "python_files_count": len(python_files),
                    "overall_observability_score": analysis_results.get(
                        "overall_score", 0.0
                    ),
                    "total_functions": analysis_results.get("total_functions", 0),
                    "functions_with_logging": analysis_results.get(
                        "functions_with_logging", 0
                    ),
                    "logging_patterns_found": analysis_results.get(
                        "logging_patterns_found", []
                    ),
                },
            )

        except Exception as e:
            logger.error(f"Observability analysis failed: {str(e)}")
            error_count += 1
            execution_time = asyncio.get_event_loop().time() - start_time

            metrics = AnalysisMetrics(
                analyzer_name=self.name,
                execution_time_seconds=execution_time,
                files_analyzed=0,
                findings_count=0,
                error_count=error_count,
                success=False,
                error_message=str(e),
            )

            return AnalysisResult(
                findings=[], metrics=metrics, metadata={"error": str(e)}
            )

    def _initialize_patterns(self):
        """Initialize logging and observability patterns."""
        # Common logging patterns to detect
        self.logging_patterns = [
            r"logger\.\w+\(",
            r"log\.\w+\(",
            r"logging\.\w+\(",
            r"print\(",  # Basic print statements
            r"console\.\w+\(",
            r"_logger\.\w+\(",
            r"self\.logger\.\w+\(",
            r"self\.log\.\w+\(",
        ]

        # Logging method names
        self.logging_methods = [
            "debug",
            "info",
            "warning",
            "warn",
            "error",
            "critical",
            "exception",
            "log",
            "print",
        ]

        # Structured logging patterns (better observability)
        self.structured_logging_patterns = [
            r"logger\.\w+\([^)]*extra\s*=",  # Logger with extra parameter
            r"logger\.\w+\([^)]*\{.*\}",  # Logger with dictionary
            r"structlog\.",  # Structured logging library
        ]

        # Critical function patterns that should have logging
        self.critical_function_patterns = [
            r"def.*error.*\(",
            r"def.*exception.*\(",
            r"def.*validate.*\(",
            r"def.*authenticate.*\(",
            r"def.*authorize.*\(",
            r"def.*process.*\(",
            r"def.*handle.*\(",
        ]

    def _find_python_files(self, path: str) -> List[str]:
        """Find all Python files under the given path, excluding virtual environments."""
        return find_python_files(path, exclude_test_files=False)

    async def _perform_observability_analysis(
        self, python_files: List[str], config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform comprehensive observability analysis."""

        all_file_results = []
        total_functions = 0
        total_with_logging = 0
        all_logging_patterns = set()
        for file_path in python_files:
            # Skip test files if configured
            if config.get("exclude_test_files", True) and self._is_test_file(file_path):
                continue
            file_result = await self._analyze_file_observability(file_path, config)
            if file_result:
                all_file_results.append(file_result)
                total_functions += file_result["total_functions"]
                total_with_logging += file_result["functions_with_logging"]
                all_logging_patterns.update(
                    file_result.get("logging_patterns_found", [])
                )

        overall_score = (
            (total_with_logging / total_functions * 100) if total_functions > 0 else 0
        )

        return {
            "file_results": all_file_results,
            "total_functions": total_functions,
            "functions_with_logging": total_with_logging,
            "functions_without_logging": total_functions - total_with_logging,
            "overall_score": overall_score,
            "logging_patterns_found": list(all_logging_patterns),
        }

    async def _analyze_file_observability(
        self, file_path: str, config: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Analyze a single file for observability patterns."""
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = file.read()

            tree = ast.parse(content)
            functions = []
            # Extract functions with their details
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Skip private methods if configured
                    if config.get(
                        "exclude_private_methods", True
                    ) and node.name.startswith("_"):
                        continue

                    # Get function source code
                    try:
                        func_lines = content.split("\n")[
                            node.lineno
                            - 1 : (
                                node.end_lineno
                                if hasattr(node, "end_lineno")
                                else node.lineno
                            )
                        ]
                        func_code = "\n".join(func_lines)
                    except (IndexError, TypeError):
                        func_code = ""

                    # Check for logging in this function
                    has_logging, logging_patterns = self._has_logging(func_code)
                    is_critical = self._is_critical_function(node.name, func_code)

                    functions.append(
                        {
                            "path": file_path,
                            "name": node.name,
                            "line_number": node.lineno,
                            "code": func_code,
                            "has_logging": has_logging,
                            "logging_patterns": logging_patterns,
                            "is_critical": is_critical,
                        }
                    )

            total_functions = len(functions)
            functions_with_logging = sum(1 for f in functions if f["has_logging"])
            score = (
                (functions_with_logging / total_functions * 100)
                if total_functions > 0
                else 0
            )

            # Collect all unique logging patterns found
            all_patterns = set()
            for func in functions:
                all_patterns.update(func["logging_patterns"])
            return {
                "file_path": file_path,
                "total_functions": total_functions,
                "functions_with_logging": functions_with_logging,
                "score": score,
                "functions": functions,
                "logging_patterns_found": list(all_patterns),
            }

        except Exception as e:
            logger.warning(f"Could not analyze {file_path}: {str(e)}")
            return None

    def _has_logging(self, code: str) -> Tuple[bool, List[str]]:
        """Check if code contains logging statements."""
        found_patterns = []

        for pattern in self.logging_patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                found_patterns.extend(matches)

        return len(found_patterns) > 0, found_patterns

    def _is_critical_function(self, func_name: str, func_code: str) -> bool:
        """Check if a function is critical and should have logging."""
        # Check function name patterns
        for pattern in self.critical_function_patterns:
            if re.search(pattern, f"def {func_name}(", re.IGNORECASE):
                return True

        # Check for error handling patterns
        if any(
            keyword in func_code.lower()
            for keyword in ["try:", "except:", "raise", "error", "exception"]
        ):
            return True

        return False

    def _is_test_file(self, file_path: str) -> bool:
        """Check if a file is a test file."""
        filename = os.path.basename(file_path).lower()

        return (
            filename.startswith("test_")
            or filename.endswith("_test.py")
            or "test" in filename
            or "/test" in file_path.lower()
        )

    async def _generate_findings(
        self, analysis_results: Dict[str, Any], target_path: str, config: Dict[str, Any]
    ) -> List[UnifiedFinding]:
        """Generate findings based on observability analysis results."""
        findings = []

        # Check overall observability score
        overall_score = analysis_results["overall_score"]
        minimum_threshold = config.get("minimum_logging_coverage", 60.0)

        if overall_score < minimum_threshold:
            severity = (
                SeverityLevel.HIGH if overall_score < 30 else SeverityLevel.MEDIUM
            )
            finding = UnifiedFinding(
                title="Poor Observability Coverage",
                description=f"Logging coverage is {overall_score:.1f}%, below recommended {minimum_threshold}%",
                category=FindingCategory.OBSERVABILITY,
                severity=severity,
                confidence_score=0.9,
                location=CodeLocation(file_path=Path(target_path).name),
                rule_id="LOW_OBSERVABILITY_COVERAGE",
                remediation_guidance=f"Add logging statements to functions to reach {minimum_threshold}% coverage",
                remediation_complexity=ComplexityLevel.MODERATE,
                source_analyzer=self.name,
                tags={"logging", "observability", "monitoring"},
                extra_data={
                    "observability_score": overall_score,
                    "minimum_threshold": minimum_threshold,
                    "functions_without_logging": analysis_results[
                        "functions_without_logging"
                    ],
                },
            )
            findings.append(finding)

        # Check for missing logging in critical functions
        if config.get("check_critical_functions", True):
            for file_result in analysis_results["file_results"]:
                critical_functions_without_logging = [
                    f
                    for f in file_result["functions"]
                    if f["is_critical"] and not f["has_logging"]
                ]

                if critical_functions_without_logging:
                    names = ", ".join(
                        f["name"] for f in critical_functions_without_logging
                    )
                    description = (
                        f"Critical functions without logging: {len(critical_functions_without_logging)} "
                        f"{shorten(names, width=120, placeholder='...')}"
                    )
                    finding = UnifiedFinding(
                        title="Critical Functions Missing Logging",
                        description=description,
                        category=FindingCategory.OBSERVABILITY,
                        severity=SeverityLevel.HIGH,
                        confidence_score=0.8,
                        location=CodeLocation(file_path="/".join(str(file_result["file_path"]).split("/")[-2:])),
                        rule_id="CRITICAL_FUNCTIONS_NO_LOGGING",
                        remediation_guidance="Add logging to critical functions for better debugging and monitoring",
                        remediation_complexity=ComplexityLevel.SIMPLE,
                        source_analyzer=self.name,
                        tags={"critical_functions", "logging", "error_handling"},
                        extra_data={
                            "critical_functions": [
                                f["name"] for f in critical_functions_without_logging
                            ],
                            "critical_function_count": len(
                                critical_functions_without_logging
                            ),
                        },
                    )
                    findings.append(finding)

        # Check for files with very poor observability
        for file_result in analysis_results["file_results"]:
            if file_result["score"] < 25 and file_result["total_functions"] > 2:
                functions_without_logging = [
                    f for f in file_result["functions"] if not f["has_logging"]
                ]

                finding = UnifiedFinding(
                    title="File with Poor Observability",
                    description=f"File has very low logging coverage: {file_result['score']:.1f}%, less then 25%",
                    category=FindingCategory.OBSERVABILITY,
                    severity=SeverityLevel.MEDIUM,
                    confidence_score=0.7,
                    location=CodeLocation(file_path="/".join(str(file_result["file_path"]).split("/")[-2:])),
                    rule_id="FILE_POOR_OBSERVABILITY",
                    remediation_guidance="Add logging statements to improve observability",
                    remediation_complexity=ComplexityLevel.MODERATE,
                    source_analyzer=self.name,
                    tags={"file_observability", "logging_coverage"},
                    extra_data={
                        "file_score": file_result["score"],
                        "functions_without_logging": [
                            f["name"] for f in functions_without_logging
                        ],
                        "total_functions": file_result["total_functions"],
                    },
                )
                findings.append(finding)
            else:
                functions_without_logging = [
                    f for f in file_result["functions"] if not f["has_logging"]
                ]
                if file_result["total_functions"] > 0:
                    finding = UnifiedFinding(
                        title="File with Fair Observability",
                        description=f"File has fair logging coverage: {file_result['score']:.1f}%",
                        category=FindingCategory.OBSERVABILITY,
                        severity=SeverityLevel.INFO,
                        confidence_score=0.7,
                        location=CodeLocation(file_path="/".join(str(file_result["file_path"]).split("/")[-2:])),
                        rule_id="FILE_FAIR_OBSERVABILITY",
                        remediation_guidance="File has Fair amount of observability",
                        remediation_complexity=ComplexityLevel.MODERATE,
                        source_analyzer=self.name,
                        tags={"file_observability", "logging_coverage"},
                        extra_data={
                            "file_score": file_result["score"],
                            "functions_without_logging": [
                                f["name"] for f in functions_without_logging
                            ],
                            "total_functions": file_result["total_functions"],
                        },
                    )
                findings.append(finding)

        # Check for lack of structured logging if enabled
        if config.get("require_structured_logging", False):
            has_structured_logging = any(
                any(
                    re.search(pattern, pattern_found, re.IGNORECASE)
                    for pattern in self.structured_logging_patterns
                )
                for pattern_found in analysis_results["logging_patterns_found"]
            )

            if (
                not has_structured_logging
                and analysis_results["functions_with_logging"] > 0
            ):
                finding = UnifiedFinding(
                    title="Missing Structured Logging",
                    description="Code uses basic logging but lacks structured logging patterns",
                    category=FindingCategory.OBSERVABILITY,
                    severity=SeverityLevel.LOW,
                    confidence_score=0.6,
                    location=CodeLocation(file_path="/".join(str(target_path).split("/")[-2:])),
                    rule_id="MISSING_STRUCTURED_LOGGING",
                    remediation_guidance="Consider using structured logging with extra parameters or structured logging libraries",
                    remediation_complexity=ComplexityLevel.MODERATE,
                    source_analyzer=self.name,
                    tags={"structured_logging", "observability_best_practices"},
                    extra_data={
                        "logging_patterns_found": analysis_results[
                            "logging_patterns_found"
                        ],
                    },
                )
                findings.append(finding)

        return findings

    def _create_empty_result(self) -> AnalysisResult:
        """Create an empty analysis result."""
        metrics = AnalysisMetrics(
            analyzer_name=self.name,
            execution_time_seconds=0.0,
            files_analyzed=0,
            findings_count=0,
            error_count=0,
            success=True,
        )
        return AnalysisResult(findings=[], metrics=metrics, metadata={})
