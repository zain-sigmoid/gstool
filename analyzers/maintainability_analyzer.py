"""
Maintainability Analysis Module
Analyzes code maintainability including complexity, duplication, and coupling.
"""

import ast
import json
import asyncio
import logging
import traceback
from typing import List, Dict, Any
from collections import defaultdict, Counter
from core.tool_runner import ToolRunner
from core.file_utils import find_python_files
from core.interfaces import QualityAnalyzer
from termcolor import colored
from rich import print as rprint
from utils.mi import MIDiagnose
from utils.analyze import analyze_function_in_file
from utils.duplicate_code import run_jscpd_analysis
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


class MaintainabilityAnalyzer(QualityAnalyzer):
    """Analyzer for code maintainability metrics."""

    def __init__(
        self,
    ):
        """Initialize the maintainability analyzer."""
        super().__init__("maintainability", "1.0.0")
        self.supported_tools = ["radon", "jscpd"]
        self.quality_categories = [
            "cyclomatic_complexity",
            "complexity_risk_ranking",
            "maintainability_index",
            "code_duplication",
        ]
        self.tool_runner = ToolRunner()
        self.findings = []

    def get_supported_file_types(self) -> List[str]:
        """Return supported file types."""
        return [".py"]

    def get_quality_categories(self) -> List[str]:
        """Get quality categories this analyzer covers."""
        return self.quality_categories

    def get_quality_metrics(self) -> List[str]:
        """Get quality metrics this analyzer can provide."""
        return [
            "cyclomatic_complexity_score",
            "complexity_risk_ranking_score",
            "maintainability_index",
            "code_duplication_percentage",
        ]

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for this analyzer."""
        return {""}

    def _find_python_files(self, path: str) -> List[str]:
        """Find all Python files under the given path, excluding virtual environments."""
        return find_python_files(path, exclude_test_files=False)

    async def analyze(self, config: AnalysisConfiguration) -> AnalysisResult:
        """
        Analyze code maintainability.

        Args:
            path (str): Path to the code directory

        Returns:
            dict: Analysis results with score and findings
        """
        error_count = 0
        start_time = asyncio.get_event_loop().time()
        python_files = self._find_python_files(config.target_path)
        if not python_files:
            logger.warning(f"No Python files found in {config.target_path}")
            return self._create_empty_result()

        analyzer_config = config.analyzer_configs.get(
            self.name, self.get_default_config()
        )
        # Use radon for complexity analysis
        await self._run_radon_analysis(config.target_path)

        # Analyze code duplication
        # await self._analyze_code_duplication(config.target_path)

        # Analyze function duplication
        self._analyze_function_duplication(python_files)

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
            f"Maintainability analysis completed: {len(self.findings)} findings in {execution_time:.2f}s"
        )
        findings = await self._generate_findings(self.findings)
        return AnalysisResult(
            findings=findings,
            metrics=metrics,
            metadata={
                "python_files_count": len(python_files),
            },
        )

    async def _generate_findings(
        self,
        results,
    ) -> List[UnifiedFinding]:
        """Generate findings asynchronously."""
        findings = []
        for finding in results:
            unified_finding = UnifiedFinding(
                title=f"Maintainability Issue: {finding['type'].replace('_', ' ').title()}",
                severity=finding.get("severity", SeverityLevel.INFO),
                category=FindingCategory.MAINTAINABILITY,
                description=finding.get("description", ""),
                details=finding.get("details", None),
                confidence_score=0.8,
                location=CodeLocation(
                    file_path=f"/".join(finding.get("file", "").split("/")[-2:]),
                    line_number=finding.get("line", 0),
                ),
                remediation_guidance=finding.get("suggestion", ""),
                remediation_complexity=ComplexityLevel.MODERATE,
                source_analyzer=self.name,
                tags={"test_files", "econ_files"},
            )
            findings.append(unified_finding)
        return findings

    async def _run_radon_analysis(self, path):
        """Run radon for complexity and maintainability analysis."""
        try:
            # Cyclomatic Complexity
            cc_result = self.tool_runner.run_tool(
                "radon", ["cc", path, "--json"], capture_output=True
            )
            if cc_result.returncode == 0 and cc_result.stdout:
                await self._process_radon_cc(cc_result.stdout)
                cc_data = json.loads(cc_result.stdout)
                await self._calculate_complexity_rank(cc_data=cc_data)

            # Maintainability Index
            mi_result = self.tool_runner.run_tool(
                "radon", ["mi", path, "--json"], capture_output=True
            )
            if mi_result.returncode == 0 and mi_result.stdout:
                self._process_radon_mi(mi_result.stdout)

        except Exception as e:
            # Radon not available - use manual complexity analysis
            traceback.print_exc()
            self._manual_complexity_analysis(path)

    async def _process_radon_cc(self, cc_output):
        """Process radon cyclomatic complexity output."""
        try:
            cc_data = json.loads(cc_output)
            high_complexity_functions = 0
            total_functions = 0
            for file_path, functions in cc_data.items():
                for func in functions:
                    total_functions += 1
                    complexity = func.get("complexity", 0)
                    func_name = func.get("name", "unknown")
                    line = func.get("lineno", 0)

                    if complexity > 10:  # High complexity threshold
                        severity = (
                            SeverityLevel.HIGH
                            if complexity > 20
                            else SeverityLevel.MEDIUM
                        )
                        analysis = await analyze_function_in_file(
                            file_path, func_name, complexity
                        )
                        self.findings.append(
                            {
                                "type": "cyclomatic_complexity",
                                "severity": severity,
                                "file": file_path,
                                "line": line,
                                "function": func_name,
                                "complexity": complexity,
                                "details": analysis["metrics"],
                                "description": f"Function `{func_name}` has high cyclomatic complexity ({complexity})",
                                "suggestion": analysis["suggestions"],
                            }
                        )
                        high_complexity_functions += 1

        except json.JSONDecodeError:
            traceback.print_exc()
            print(colored("Error processing radon cyclomatic complexity output", "red"))
            pass

    def _get_file_loc(self, file_path):
        try:
            with open(file_path, "r") as f:
                return len(f.readlines())
        except Exception:
            return 1

    async def _calculate_complexity_rank(self, cc_data):
        """
        Calculates percentage of LOC in moderate, high, and very high complexity zones and assigns a rank (++ to --).
        """
        grade_to_risk = {
            "C": "moderate",
            "D": "high",
            "E": "very_high",
            "F": "very_high",
        }

        for file_path, functions in cc_data.items():
            risk_loc = {"moderate": 0, "high": 0, "very_high": 0}
            risk_funcs = {"moderate": [], "high": [], "very_high": []}
            total_loc = self._get_file_loc(file_path)
            for func in functions:
                grade = func.get("rank", "").upper()
                start = func.get("lineno", 0)
                end = func.get("endline", 0)
                loc = end - start + 1
                func_name = func.get("name", "unknown")
                if grade in grade_to_risk:
                    risk_type = grade_to_risk[grade]
                    risk_loc[risk_type] += loc
                    risk_funcs[risk_type].append(f"{func_name} (LOC: {loc})")

            # Calculate percentages
            percent = {
                k: round((v / total_loc) * 100, 2) if total_loc else 0.0
                for k, v in risk_loc.items()
            }

            # Determine system rank from the table
            system_rank = "Poorly Maintainable"
            if (
                percent["moderate"] <= 25
                and percent["high"] == 0
                and percent["very_high"] == 0
            ):
                system_rank = "Highly Maintainable"
            elif (
                percent["moderate"] <= 30
                and percent["high"] <= 5
                and percent["very_high"] == 0
            ):
                system_rank = "Fairly Maintainable"
            elif (
                percent["moderate"] <= 40
                and percent["high"] <= 10
                and percent["very_high"] == 0
            ):
                system_rank = "Moderately Maintainable"
            elif (
                percent["moderate"] <= 50
                and percent["high"] <= 15
                and percent["very_high"] <= 5
            ):
                system_rank = "Maintainable"

            severity = SeverityLevel.INFO
            if system_rank in ["Highly Maintainable", "Fairly Maintainable"]:
                severity = SeverityLevel.INFO
            elif system_rank == "Moderately Maintainable":
                severity = SeverityLevel.MEDIUM
            else:
                severity = SeverityLevel.HIGH

            details = {
                "percentages": percent,
                "functions_by_risk": {
                    k: risk_funcs[k] for k in risk_funcs if risk_funcs[k]
                },
                "total_loc": total_loc,
                "rank": system_rank,
            }
            desc = json.dumps(details, indent=2)
            # Add to findings
            self.findings.append(
                {
                    "type": "complexity_risk_ranking",
                    "severity": severity,
                    "description": """
                        - **Moderate**: Percent of LOC in functions rated C by Cyclomatic Complexity (CC)  
                        - **High**: Percent of LOC in functions rated D by CC  
                        - **Very High**: Percent of LOC in functions rated E by CC
                        """,
                    "file": file_path,
                    "details": details,
                    "rank": system_rank,
                    "suggestion": "Refactor high and very high complexity code to improve maintainability.",
                }
            )

    def _process_radon_mi(self, mi_output):
        """Process radon maintainability index output."""
        try:
            mi_data = json.loads(mi_output)
            total_files = 0

            for file_path, mi_info in mi_data.items():
                total_files += 1
                mi_score = mi_info.get("mi", 100)

                if mi_score <= 20 and mi_score > 10:
                    severity = SeverityLevel.MEDIUM
                    suggestion = (
                        "Maintainability is moderate and could be improved.<br>"
                        "🛠 Suggestions:<br>"
                        "- Review method lengths<br>"
                        "- Eliminate redundant logic<br>"
                        "- Aim for better modular design"
                    )
                elif mi_score <= 10:
                    severity = SeverityLevel.HIGH
                    response = MIDiagnose.analyze_file(file_path)
                else:
                    severity = SeverityLevel.INFO
                    continue
                file = file_path.split("/")[-1]
                self.findings.append(
                    {
                        "type": "maintainability_index",
                        "severity": severity,
                        "file": file_path,
                        "mi_score": mi_score,
                        "details": response["stats"],
                        "description": f'File "{file}" has maintainability index ({mi_score:.1f})',
                        "suggestion": response["suggestions"],
                    }
                )

        except Exception as e:
            print(colored(f"Error parsing MI output: {e}", "red"))

    def _manual_complexity_analysis(self, path):
        """Manual complexity analysis when radon is not available."""
        python_files = find_python_files(path)

        for file_path in python_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                tree = ast.parse(content)

                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        complexity = self._calculate_cyclomatic_complexity(node)

                        if complexity > 10:
                            severity = (
                                SeverityLevel.HIGH
                                if complexity > 20
                                else SeverityLevel.MEDIUM
                            )
                            score_penalty = 10 if complexity > 20 else 5

                            self.findings.append(
                                {
                                    "type": "cyclomatic_complexity",
                                    "severity": severity,
                                    "file": file_path,
                                    "line": node.lineno,
                                    "function": node.name,
                                    "complexity": complexity,
                                    "description": f"Function `{node.name}` has high cyclomatic complexity ({complexity})",
                                    "suggestion": "Consider breaking this function into smaller, simpler functions",
                                }
                            )

                            self.score -= score_penalty

            except Exception:
                continue

    def _calculate_cyclomatic_complexity(self, node):
        """Calculate cyclomatic complexity for a function node."""
        complexity = 1  # Base complexity

        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1

        return complexity

    def _analyze_coupling(self, python_files):
        """Analyze coupling and cohesion metrics."""
        # print(colored("analyzing coupling", "yellow"))
        self.usage_coupling = defaultdict(Counter)

        for file_path in python_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                tree = ast.parse(content)
                imports = {}

                # Step 1: Capture imported modules and their aliases
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imports[alias.asname or alias.name] = alias.name
                    elif isinstance(node, ast.ImportFrom):
                        module = node.module
                        for alias in node.names:
                            full_name = (
                                f"{module}.{alias.name}" if module else alias.name
                            )
                            imports[alias.asname or alias.name] = full_name

                # Step 2: Track actual usage of imports
                class ImportUsageVisitor(ast.NodeVisitor):
                    def __init__(self, imports, usage_counter):
                        self.imports = imports
                        self.usage_counter = usage_counter

                    def visit_Name(self, node):
                        if node.id in self.imports:
                            self.usage_counter[self.imports[node.id]] += 1

                    def visit_Attribute(self, node):
                        if isinstance(node.value, ast.Name):
                            base = node.value.id
                            if base in self.imports:
                                self.usage_counter[self.imports[base]] += 1

                usage_counter = Counter()
                ImportUsageVisitor(imports, usage_counter).visit(tree)
                self.usage_coupling[file_path] = usage_counter

                # Step 3: Add findings if coupling is high
                high_coupled_modules = [
                    mod for mod, count in usage_counter.items() if count >= 10
                ]
                # print(colored("high coupled modules: ", "yellow"), high_coupled_modules)
                if len(high_coupled_modules) > 3:
                    self.findings.append(
                        {
                            "type": "coupling",
                            "severity": SeverityLevel.LOW,
                            "file": file_path,
                            "coupled_modules": high_coupled_modules,
                            "description": f"High usage-based coupling with: {', '.join(high_coupled_modules)}",
                            "suggestion": "Consider decoupling responsibilities or introducing interfaces",
                        }
                    )

            except Exception:
                continue

    def _analyze_function_duplication(self, python_files):
        function_hashes = defaultdict(list)

        for file_path in python_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                tree = ast.parse(content)

                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        # Create a simple hash of the function structure
                        func_hash = self._hash_function_structure(node)
                        function_hashes[func_hash].append(
                            (file_path, node.name, node.lineno)
                        )

            except Exception:
                continue

        # Find duplicates (reported once per function name)
        for func_hash, occurrences in function_hashes.items():
            if len(occurrences) > 1:
                # Extract common function name (assuming it's the same across duplicates)
                _, func_name, _ = occurrences[0]
                file_locations = [
                    f"{file.split('/')[-1]}:{line}" for file, _, line in occurrences
                ]
                file_list = sorted({file.split("/")[-1] for file, _, _ in occurrences})
                self.findings.append(
                    {
                        "type": "code_duplication",
                        "severity": SeverityLevel.MEDIUM,
                        "function": func_name,
                        "description": f"Function `{func_name}` appears at multiple locations with similar structure.",
                        "file": ", ".join(file_locations),
                        "locations": file_locations,
                        "suggestion": (
                            f"Consider moving `{func_name}` into a shared module or utility file "
                            "to reduce duplication and improve maintainability."
                        ),
                    }
                )

    async def _analyze_code_duplication(self, path):
        """Analyze code duplication."""
        # Simple duplication detection based on function similarity
        result = run_jscpd_analysis(path, min_tokens=20)
        if "duplicates" in result:
            clones = result["duplicates"]
            for x in clones:
                lines = x["lines"] - 1
                ffile = x["firstFile"]
                sfile = x["secondFile"]
                fname = ffile["name"].split("/")[-1]
                sname = sfile["name"].split("/")[-1]
                fstart = ffile["start"]
                sstart = sfile["start"]
                fend = ffile["end"]
                send = sfile["end"]
                locations = [f"{sname}:{sstart}-{send}", f"{fname}:{fstart}-{fend}"]
                self.findings.append(
                    {
                        "type": "code_duplication",
                        "severity": SeverityLevel.MEDIUM,
                        "description": f"{lines} Duplicate Lines found in 2 files",
                        "file": ", ".join(locations),
                        "suggestion": "Refactor the repeated code into a single shared function to improve maintainability and reduce redundancy.",
                    }
                )
        # Fallback to summary if no detailed clones
        if "statistics" in result:
            stats = result["statistics"]["total"]
            percentage = stats.get("percentage", 0)
            severity = SeverityLevel.INFO

            self.findings.append(
                {
                    "type": "code_duplication",
                    "severity": severity,
                    "description": f"{stats['clones']} clones found; {stats['duplicatedLines']} duplicated lines ({percentage}%)",
                    "details": stats,
                    "file": path,
                    "suggestion": "Review for potential code reuse opportunities.",
                }
            )
        else:
            self.findings.append(
                {
                    "type": "code_duplication",
                    "severity": SeverityLevel.INFO,
                    "description": "No duplication info found.",
                    "file": path,
                }
            )

    def _hash_function_structure(self, node):
        """Create a simple hash of function structure for duplication detection."""
        # This is a simplified approach - count different node types
        node_counts = defaultdict(int)

        for child in ast.walk(node):
            node_counts[type(child).__name__] += 1

        # Create a simple hash from node counts
        hash_string = "".join(f"{k}:{v}" for k, v in sorted(node_counts.items()))
        return hash(hash_string)
