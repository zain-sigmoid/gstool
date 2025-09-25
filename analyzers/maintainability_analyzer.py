"""
Maintainability Analysis Module
Analyzes code maintainability including complexity, duplication, and coupling.
"""

import ast
import json
from collections import defaultdict, Counter
from common.tool_runner import ToolRunner
from common.file_utils import find_python_files
from termcolor import colored
from utils.mi import MIDiagnose
from utils.analyze import analyze_function_in_file
from utils.duplicate_code import run_jscpd_analysis


class MaintainabilityAnalyzer:
    """Analyzer for code maintainability metrics."""

    def __init__(self, config):
        """Initialize the maintainability analyzer."""
        self.config = config
        self.tool_runner = ToolRunner()
        self.findings = []
        self.score = 100.0
        print('running maintainability analyzer...')

    def analyze(self, path):
        """
        Analyze code maintainability.

        Args:
            path (str): Path to the code directory

        Returns:
            dict: Analysis results with score and findings
        """
        self.findings = []
        self.score = 100.0

        python_files = find_python_files(path)

        if not python_files:
            return {
                "score": self.score,
                "findings": [],
                "message": "No Python files found",
            }

        # Use radon for complexity analysis
        self._run_radon_analysis(path)

        # Custom analysis for coupling and cohesion
        # self._analyze_coupling(python_files)

        # Analyze code duplication
        self._analyze_code_duplication(path)

        # Analyze function duplication
        self._analyze_function_duplication(python_files)

        return {
            "score": max(0, self.score),
            "findings": self.findings,
            "total_files_analyzed": len(python_files),
        }

    def _run_radon_analysis(self, path):
        """Run radon for complexity and maintainability analysis."""
        try:
            # Cyclomatic Complexity
            cc_result = self.tool_runner.run_tool(
                "radon", ["cc", path, "--json"], capture_output=True
            )
            if cc_result.returncode == 0 and cc_result.stdout:
                self._process_radon_cc(cc_result.stdout)
                cc_data = json.loads(cc_result.stdout)
                print(
                    colored("Processing cyclomatic complexity to get CC Rank", "green")
                )
                self._calculate_complexity_rank(cc_data=cc_data)

            # Maintainability Index
            mi_result = self.tool_runner.run_tool(
                "radon", ["mi", path, "--json"], capture_output=True
            )

            if mi_result.returncode == 0 and mi_result.stdout:
                self._process_radon_mi(mi_result.stdout)

            # Raw metrics (LOC)
            # raw_result = self.tool_runner.run_tool(
            #     "radon", ["raw", path, "--json"], capture_output=True
            # )

            # if raw_result.returncode == 0 and raw_result.stdout:
            #     self._process_radon_raw(raw_result.stdout)

            # print(
            #     colored("findings after running whole maintainability", "yellow"),
            #     self.findings,
            # )

        except Exception:
            # Radon not available - use manual complexity analysis
            self._manual_complexity_analysis(path)

    def _process_radon_cc(self, cc_output):
        """Process radon cyclomatic complexity output."""
        try:
            print(colored("Processing cyclomatic complexity...", "green"))
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
                        severity = "high" if complexity > 20 else "medium"
                        score_penalty = 10 if complexity > 20 else 5
                        analysis = analyze_function_in_file(
                            file_path, func_name, complexity
                        )
                        # print(colored(f"suggestion: {analysis['metrics']}", "yellow"))

                        self.findings.append(
                            {
                                "type": "cyclomatic_complexity",
                                "severity": severity,
                                "file": file_path,
                                "line": line,
                                "function": func_name,
                                "complexity": complexity,
                                "details": analysis["metrics"],
                                "description": f'Function "{func_name}" has high cyclomatic complexity ({complexity})',
                                "suggestion": analysis["suggestions"],
                            }
                        )

                        self.score -= score_penalty
                        high_complexity_functions += 1

            # Overall complexity assessment
            if total_functions > 0:
                complexity_ratio = high_complexity_functions / total_functions
                if complexity_ratio > 0.25:  # More than 25% functions are complex
                    self.findings.append(
                        {
                            "type": "overall_complexity",
                            "severity": "medium",
                            "description": f"{high_complexity_functions}/{total_functions} functions have high complexity",
                            "suggestion": "Consider refactoring to reduce overall code complexity",
                        }
                    )
                    self.score -= 10

        except json.JSONDecodeError:
            print(colored("Error processing radon cyclomatic complexity output", "red"))
            pass

    def _get_file_loc(self, file_path):
        try:
            with open(file_path, "r") as f:
                return len(f.readlines())
        except Exception:
            return 1

    def _calculate_complexity_rank(self, cc_data):
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

            severity = "info"
            if system_rank in ["Highly Maintainable", "Fairly Maintainable"]:
                severity = "info"
            elif system_rank == "Moderately Maintainable":
                severity = "medium"
            else:
                severity = "high"

            details = {
                "percentages": percent,
                "functions_by_risk": {
                    k: risk_funcs[k] for k in risk_funcs if risk_funcs[k]
                },
                "total_loc": total_loc,
                "rank": system_rank,
            }

            # Add to findings
            self.findings.append(
                {
                    "type": "complexity_risk_ranking",
                    "severity": severity,
                    "description": (
                        "Complexity LOC percentages:<br>"
                        "<strong>Moderate</strong>: % of LOC in functions rated C by Cyclomatic Complexity (CC); <br>"
                        "<strong>High</strong>: rated D by CC; <br>"
                        "<strong>Very High</strong>: rated E by CC."
                    ),
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
                    severity = "medium"
                    suggestion = (
                        "Maintainability is moderate and could be improved.<br>"
                        "🛠 Suggestions:<br>"
                        "- Review method lengths<br>"
                        "- Eliminate redundant logic<br>"
                        "- Aim for better modular design"
                    )
                elif mi_score <= 10:
                    severity = "high"
                    response = MIDiagnose.analyze_file(file_path)
                    # suggestion = (
                    #     "Maintainability is very low due to high complexity or excessive code length.<br>"
                    #     "🛠 Consider:<br>"
                    #     "- Refactoring long methods<br>"
                    #     "- Breaking logic into smaller functions<br>"
                    #     "- Reducing nested conditionals<br>"
                    #     "- Improving naming and removing dead code"
                    # )
                else:
                    severity = "info"
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
                            severity = "high" if complexity > 20 else "medium"
                            score_penalty = 10 if complexity > 20 else 5

                            self.findings.append(
                                {
                                    "type": "cyclomatic_complexity",
                                    "severity": severity,
                                    "file": file_path,
                                    "line": node.lineno,
                                    "function": node.name,
                                    "complexity": complexity,
                                    "description": f'Function "{node.name}" has high cyclomatic complexity ({complexity})',
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
                            "severity": "low",
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
                        "severity": "medium",
                        "function": func_name,
                        "description": f'Function "{func_name}" appears in multiple files with similar structure.',
                        "files": file_list,
                        "locations": file_locations,
                        "suggestion": (
                            f'Consider moving "{func_name}" into a shared module or utility file '
                            "to reduce duplication and improve maintainability."
                        ),
                    }
                )

    def _analyze_code_duplication(self, path):
        """Analyze code duplication."""
        # Simple duplication detection based on function similarity
        result = run_jscpd_analysis(path, min_tokens=20)
        if "duplicates" in result:
            clones = result["duplicates"]
            for x in clones:
                lines = x["lines"]
                ffile = x["firstFile"]
                sfile = x["secondFile"]
                fname = ffile["name"].split("/")[-1]
                sname = sfile["name"].split("/")[-1]
                fstart = ffile["start"]
                sstart = sfile["start"]
                self.findings.append(
                    {
                        "type": "code_duplication",
                        "severity": "medium",
                        "description": f"{lines} Duplicate Lines found in files",
                        "locations": [f"{sname}:{sstart}", f"{fname}:{fstart}"],
                        "suggestion": "Refactor the repeated code into a single shared function to improve maintainability and reduce redundancy.",
                    }
                )
        # Fallback to summary if no detailed clones
        if "statistics" in result:
            stats = result["statistics"]["total"]
            percentage = stats.get("percentage", 0)
            severity = "info"

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
                    "severity": "info",
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
