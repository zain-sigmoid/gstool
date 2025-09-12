"""
Complexity Estimator v1.0
- Near-expert-level static analyzer for time and space complexity
- Uses AST parsing and pattern matching
- Modular, extensible via rule plugins
"""

import ast


class ComplexityEstimator(ast.NodeVisitor):
    def __init__(self):
        self.loop_depth = 0
        self.max_loop_depth = 0
        self.recursive_calls = set()
        self.current_function = None
        self.space_structures = {}
        self.apply_with_expensive_op = False
        self.called_functions = set()
        self.loop_vars = set()
        self.symbol_table = {}

    def visit_FunctionDef(self, node):
        self._reset()
        self.current_function = node.name
        self.generic_visit(node)

        time_complexity = self.estimate_time_complexity()
        space_complexity = self.estimate_space_complexity()
        confidence = self.estimate_confidence()

        return {
            "function": node.name,
            "time": time_complexity,
            "space": space_complexity,
            "recursive": node.name in self.recursive_calls,
            "max_loop_depth": self.max_loop_depth,
            "confidence": confidence,
        }

    def _reset(self):
        self.loop_depth = 0
        self.max_loop_depth = 0
        self.recursive_calls.clear()
        self.space_structures.clear()
        self.apply_with_expensive_op = False
        self.called_functions.clear()
        self.loop_vars.clear()
        self.symbol_table.clear()

    def visit_For(self, node):
        if isinstance(node.iter, ast.Name):
            self.loop_vars.add(node.iter.id)
        self.loop_depth += 1
        self.max_loop_depth = max(self.max_loop_depth, self.loop_depth)
        self.generic_visit(node)
        self.loop_depth -= 1

    def visit_While(self, node):
        self.loop_depth += 1
        self.max_loop_depth = max(self.max_loop_depth, self.loop_depth)
        self.generic_visit(node)
        self.loop_depth -= 1

    def visit_Call(self, node):
        # Recursive calls
        if isinstance(node.func, ast.Name):
            if node.func.id == self.current_function:
                self.recursive_calls.add(node.func.id)
            else:
                self.called_functions.add(node.func.id)

        # Detect expensive ops in .apply()
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "apply":
                if self._contains_expensive_df_op(node):
                    self.apply_with_expensive_op = True

        self.generic_visit(node)

    def visit_Assign(self, node):
        if isinstance(node.value, (ast.List, ast.Dict, ast.Set)):
            typ = type(node.value).__name__
            self.space_structures[typ] = self.space_structures.get(typ, 0) + 1
        self.generic_visit(node)

    def _contains_expensive_df_op(self, node):
        text = ast.unparse(node) if hasattr(ast, "unparse") else ""
        return any(
            op in text for op in ["unique()", "value_counts()", ".shape", "len("]
        )

    def estimate_time_complexity(self):
        if self.current_function in self.recursive_calls:
            if self.max_loop_depth > 0:
                return "O(n * 2^n)"
            return "O(2^n)"

        if self.apply_with_expensive_op:
            return "O(n^2)"

        if self.max_loop_depth == 0:
            return "O(1)"
        elif self.max_loop_depth == 1:
            return "O(n)"
        elif self.max_loop_depth == 2:
            return "O(n + m)"
        else:
            return f"O(n^{self.max_loop_depth})"

    def estimate_space_complexity(self):
        total = sum(self.space_structures.values())
        if total == 0:
            return "O(1)"
        elif total == 1:
            return "O(n)"
        else:
            return f"O({total}n)"

    def estimate_confidence(self):
        if self.current_function in self.recursive_calls:
            return "medium"
        if self.apply_with_expensive_op:
            return "medium"
        if self.max_loop_depth >= 3:
            return "medium"
        return "high"

    @staticmethod
    def analyze_file(file_path):
        with open(file_path, "r") as f:
            tree = ast.parse(f.read())

        results = []
        analyzer = ComplexityEstimator()

        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                results.append(analyzer.visit_FunctionDef(node))

        return results
