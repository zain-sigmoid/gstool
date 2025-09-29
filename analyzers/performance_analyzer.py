"""
Performance Analysis Module
Analyzes code performance issues including algorithmic complexity and inefficient patterns.
"""

import ast
import re
import os
import asyncio
import logging
import traceback
from typing import List, Dict, Any
from collections import defaultdict
from pathlib import Path
from termcolor import colored
from core.file_utils import find_python_files
from utils.time_space_analyzer import ComplexityEstimator
from core.interfaces import QualityAnalyzer
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


class PerformanceAnalyzer(QualityAnalyzer):
    """Analyzer for performance-related code issues."""

    def __init__(self):
        """Initialize the performance analyzer."""
        super().__init__("performance", "1.0.0")
        self.supported_tools = ["ast"]
        self.quality_categories = [
            "complexity",
            "nested_loops",
            "naive_sorting",
            "recursive_without_memoization",
            "string_concatenation",
            "inefficient_data_structure",
            "regex_patterns",
        ]
        self.findings = []
        print("running performance analyzer...")

    def get_supported_file_types(self) -> List[str]:
        """Return supported file types."""
        return [".py"]

    def get_quality_categories(self) -> List[str]:
        """Get quality categories this analyzer covers."""
        return self.quality_categories

    def get_quality_metrics(self) -> List[str]:
        """Get quality metrics this analyzer can provide."""
        return [
            "time_complexity",
            "naive_sorting",
            "recursive_without_memoization",
            "string_concatenation",
            "inefficient_data_structure",
            "regex_patterns",
            "naive_search",
        ]

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for this analyzer."""
        return {""}

    def _find_python_files(self, path: str) -> List[str]:
        """Find all Python files under the given path, excluding virtual environments."""
        return find_python_files(path, exclude_test_files=False)

    async def analyze(self, config: AnalysisConfiguration) -> AnalysisResult:
        """
        Analyze code for performance issues.

        Args:
            path (str): Path to the code directory

        Returns:
            dict: Analysis results with score and findings
        """
        self.findings = []
        error_count = 0
        start_time = asyncio.get_event_loop().time()
        python_files = self._find_python_files(config.target_path)
        if not python_files:
            logger.warning(f"No Python files found in {config.target_path}")
            return self._create_empty_result()

        # Analyze each file for performance issues
        for file_path in python_files:
            self._analyze_file_performance(file_path)
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
            f"Performance analysis completed: {len(self.findings)} findings in {execution_time:.2f}s"
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
                title=f"Performance Issue: {finding['type'].replace('_', ' ').title()}",
                severity=finding.get("severity", SeverityLevel.INFO),
                category=FindingCategory.PERFORMANCE,
                description=finding.get("description", ""),
                confidence_score=0.8,
                location=CodeLocation(
                    file_path="/".join(finding.get("file", "").split("/")[-2:]),
                    line_number=finding.get("line", 0),
                ),
                remediation_guidance=finding.get("suggestion", ""),
                remediation_complexity=ComplexityLevel.MODERATE,
                source_analyzer=self.name,
                tags={"test_files", "econ_files"},
            )
            findings.append(unified_finding)
        return findings

    def set_parents(self, node, parent=None):
        for child in ast.iter_child_nodes(node):
            child.parent = parent
            self.set_parents(child, child)

    def _analyze_file_performance(self, file_path):
        """Analyze individual file for performance issues."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content)
            self.set_parents(tree)

            # Check for various performance issues
            self._check_complexity(file_path)
            # self._check_nested_loops(tree, file_path)
            self._check_naive_sorting(tree, file_path)
            self._check_recursive_functions(tree, file_path)
            self._check_string_concatenation(tree, file_path)
            self._check_inefficient_data_structures(tree, file_path)
            self._check_regex_patterns(content, file_path)

        except Exception as e:
            traceback.print_exc()
            logger.error(f"Error analyzing {file_path}: {str(e)}")
            self.findings.append(
                {
                    "type": "analysis_error",
                    "severity": SeverityLevel.INFO,
                    "file": file_path,
                    "description": f"Could not analyze file: {str(e)}",
                    "suggestion": "Check file syntax and encoding",
                }
            )

    def _check_complexity(self, file_path):
        info_count = 0
        results = ComplexityEstimator.analyze_file(file_path)
        for r in results:
            time_complexity = r["time"]
            space_complexity = r["space"]
            if time_complexity in ["O(1)", "O(n)"]:
                info_count += 1
            else:
                self.findings.append(
                    {
                        "type": "time_complexity",
                        "severity": SeverityLevel.HIGH,
                        "function": r["function"],
                        "file": file_path,
                        "description": f'Function "{r["function"]}" has high time complexity: {time_complexity} and space complexity: {space_complexity}',
                        "suggestion": "Consider optimizing or breaking down the function.",
                    }
                )
        if info_count > 0:
            self.findings.append(
                {
                    "type": "time_complexity",
                    "severity": SeverityLevel.INFO,
                    "description": f'{info_count} functions have acceptable time complexity (O(1) or O(n)) in "{file_path.split("/")[-1]}"',
                    "file": file_path,
                    "suggestion": "These functions are good to go.",
                }
            )

    def _check_nested_loops(self, tree, file_path):
        """Check for nested loops that might cause performance issues."""

        def find_nested_loops(node, depth=0):
            if isinstance(node, (ast.For, ast.While)):
                depth += 1
                if depth >= 3:  # Triple nested or more
                    self.findings.append(
                        {
                            "type": "nested_loops",
                            "severity": SeverityLevel.HIGH,
                            "file": file_path,
                            "line": node.lineno,
                            "description": f"Deeply nested loops (depth: {depth}) detected",
                            "suggestion": "Consider optimizing algorithm or using more efficient data structures",
                        }
                    )
                elif depth == 2:  # Double nested
                    self.findings.append(
                        {
                            "type": "nested_loops",
                            "severity": SeverityLevel.MEDIUM,
                            "file": file_path,
                            "line": node.lineno,
                            "description": "Double nested loops detected - potential O(n²) complexity",
                            "suggestion": "Review if algorithm can be optimized to reduce time complexity",
                        }
                    )

            for child in ast.iter_child_nodes(node):
                find_nested_loops(child, depth)

        find_nested_loops(tree)

    def _check_naive_sorting(self, tree, file_path):
        """Check for naive sorting implementations."""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Look for bubble sort pattern
                if self._is_bubble_sort_pattern(node):
                    self.findings.append(
                        {
                            "type": "naive_sorting",
                            "severity": SeverityLevel.MEDIUM,
                            "file": file_path,
                            "line": node.lineno,
                            "function": node.name,
                            "description": "Potential bubble sort or naive sorting implementation",
                            "suggestion": "Use built-in sorted() function or list.sort() for better performance",
                        }
                    )

                # Look for inefficient search patterns
                if self._is_linear_search_pattern(node):
                    self.findings.append(
                        {
                            "type": "naive_search",
                            "severity": SeverityLevel.MEDIUM,
                            "file": file_path,
                            "line": node.lineno,
                            "function": node.name,
                            "description": f'Function "{node.name}" have linear search in potentially large dataset',
                            "suggestion": "Consider using sets, dictionaries, or binary search for better performance",
                        }
                    )

    def _is_bubble_sort_pattern(self, node):
        """Check if function contains bubble sort pattern."""
        # Simplified check for nested loops with swapping
        for outer in ast.iter_child_nodes(node):
            if isinstance(outer, ast.For):
                for inner in ast.iter_child_nodes(outer):
                    if isinstance(inner, ast.For):
                        # Check for if condition inside inner loop
                        for sub in ast.walk(inner):
                            if isinstance(sub, ast.If) and isinstance(
                                sub.test, ast.Compare
                            ):
                                if self._has_swap(sub.body):
                                    return True
        return False

    def _has_swap(self, body):
        for stmt in body:
            if isinstance(stmt, ast.Assign):
                # Detect arr[i], arr[i+1] = arr[i+1], arr[i] swap
                if (
                    len(stmt.targets) == 1
                    and isinstance(stmt.targets[0], ast.Tuple)
                    and isinstance(stmt.value, ast.Tuple)
                ):
                    return True
        return False

    def _is_linear_search_pattern(self, node):
        """Check if function contains linear search pattern."""
        # Look for loops with conditional breaks
        for child in ast.walk(node):
            if isinstance(child, ast.For) and isinstance(child.iter, ast.Name):
                loop_var = (
                    child.target.id if isinstance(child.target, ast.Name) else None
                )

                for subchild in ast.walk(child):
                    if isinstance(subchild, ast.If):
                        condition = subchild.test
                        if isinstance(condition, ast.Compare):
                            # Check if loop var is involved in comparison
                            involved = any(
                                isinstance(op, ast.Name) and op.id == loop_var
                                for op in [condition.left] + condition.comparators
                            )
                            if involved:
                                for inner in ast.walk(subchild):
                                    if isinstance(inner, (ast.Break, ast.Return)):
                                        return True
        return False

    def _check_recursive_functions(self, tree, file_path):
        """Check for recursive functions without memoization."""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if self._is_recursive_function(node):
                    if not self._has_memoization(node):
                        self.findings.append(
                            {
                                "type": "recursive_without_memoization",
                                "severity": SeverityLevel.MEDIUM,
                                "file": file_path,
                                "line": node.lineno,
                                "function": node.name,
                                "description": f'Function "{node.name}" has recursive function without memoization',
                                "suggestion": "Consider adding memoization or using iterative approach for better performance",
                            }
                        )

    def _is_recursive_function(self, node):
        """Check if function calls itself."""
        func_name = node.name
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id == func_name
            ):
                return True
        return False

    def _has_memoization(self, node):
        """Check if function uses memoization patterns."""
        # Look for common memoization patterns
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if "cache" in child.id.lower() or "memo" in child.id.lower():
                    return True
            elif isinstance(child, ast.Attribute):
                if "cache" in child.attr.lower() or "memo" in child.attr.lower():
                    return True
        return False

    def _check_string_concatenation(self, tree, file_path):
        """Check for inefficient string concatenation."""
        for node in ast.walk(tree):
            if isinstance(node, ast.For):
                # Look for string concatenation in loops
                for child in ast.walk(node):
                    if isinstance(child, ast.AugAssign) and isinstance(
                        child.op, ast.Add
                    ):
                        # Check if target is likely a string
                        self.findings.append(
                            {
                                "type": "string_concatenation",
                                "severity": SeverityLevel.MEDIUM,
                                "file": file_path,
                                "line": child.lineno,
                                "description": "String concatenation in loop - potential performance issue",
                                "suggestion": 'Use list.append() and "".join() or f-strings for better performance',
                            }
                        )

    def _check_inefficient_data_structures(self, tree, file_path):
        """Check for inefficient data structure usage."""

        def is_inside_loop(node):
            while hasattr(node, "parent"):
                node = node.parent
                if isinstance(node, (ast.For, ast.While)):
                    return True
            return False

        aggregated_findings = defaultdict(list)
        issue_suggestions = {
            "inefficient_list_building": "Use list comprehension instead of appending to a list inside a loop for better performance and cleaner code.",
            "inefficient_membership_check": "Convert the list to a set before performing membership checks to improve lookup performance.",
            "inefficient_list_concat": "Use `.extend()` or collect sublists and concatenate once, instead of using `+=` in a loop.",
            "inefficient_sorting": "Avoid sorting inside a loop; sort once outside the loop or use `heapq` for top-N items.",
            "inefficient_string_concat": "Avoid repeated string concatenation in a loop. Use a list to accumulate parts and join once at the end.",
        }

        for node in ast.walk(tree):

            # 1. 'in' used on list (inefficient membership)
            if isinstance(node, ast.Compare):
                if any(isinstance(op, ast.In) for op in node.ops):
                    target = node.comparators[0]
                    if isinstance(target, ast.Name):
                        key = ("inefficient_membership_check", file_path)
                        aggregated_findings[key].append(node.lineno)

            # 2. list.append() in loops
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "append" and is_inside_loop(node):
                    key = ("inefficient_list_building", file_path)
                    aggregated_findings[key].append(node.lineno)

            # 3. List growth via += or +
            if isinstance(node, ast.AugAssign):
                if isinstance(node.op, ast.Add) and is_inside_loop(node):
                    key = ("inefficient_list_concat", file_path)
                    aggregated_findings[key].append(node.lineno)

            # 4. List.sort() in loop
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "sort" and is_inside_loop(node):
                    key = ("inefficient_sorting", file_path)
                    aggregated_findings[key].append(node.lineno)

            # 5. String concatenation in loop
            if isinstance(node, ast.AugAssign):
                if isinstance(node.op, ast.Add) and isinstance(node.target, ast.Name):
                    if is_inside_loop(node):
                        key = ("inefficient_string_concat", file_path)
                        aggregated_findings[key].append(node.lineno)

        # Emit 1 finding per (issue_type, file_path)
        for (issue_type, path), lines in aggregated_findings.items():
            self.findings.append(
                {
                    "type": "inefficient_data_structure",
                    "file": path,
                    "severity": SeverityLevel.LOW,
                    "lines": sorted(set(lines)),
                    "count": len(lines),
                    "description": f'{issue_type.replace("_", " ").title()} detected at {len(lines)} locations in "{os.path.basename(path)}"',
                    "suggestion": issue_suggestions.get(
                        issue_type,
                        "Consider optimizing this pattern for better performance.",
                    ),
                }
            )

    def _check_regex_patterns(self, content, file_path):
        """Check for inefficient regex usage."""
        # Look for regex compilation in loops or repeated usage
        regex_compile_pattern = r"re\.compile\s*\("
        regex_usage_patterns = [
            r"re\.search\s*\(",
            r"re\.match\s*\(",
            r"re\.findall\s*\(",
        ]

        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            # Check for regex compilation not at module level
            if re.search(regex_compile_pattern, line):
                # Simple heuristic: if indented, might be in function/loop
                if line.startswith("    ") or line.startswith("\t"):
                    self.findings.append(
                        {
                            "type": "regex_compilation",
                            "severity": SeverityLevel.LOW,
                            "file": file_path,
                            "line": i,
                            "description": "Regex compilation inside function - consider module-level compilation",
                            "suggestion": "Compile regex patterns at module level for better performance",
                        }
                    )

            # Check for multiple regex operations that could be optimized
            regex_count = sum(
                1 for pattern in regex_usage_patterns if re.search(pattern, line)
            )
            if regex_count > 2:
                self.findings.append(
                    {
                        "type": "multiple_regex",
                        "severity": SeverityLevel.LOW,
                        "file": file_path,
                        "line": i,
                        "description": "Multiple regex operations on same line",
                        "suggestion": "Consider combining regex patterns or pre-compiling for efficiency",
                    }
                )
