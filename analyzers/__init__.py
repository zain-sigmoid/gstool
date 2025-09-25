from typing import Dict, Tuple
from analyzers.maintainability_analyzer import MaintainabilityAnalyzer
from analyzers.performance_analyzer import PerformanceAnalyzer

ANALYZERS: Dict[str, Tuple[str, callable]] = {
    # label -> (pretty name, function)
    # "security": ("Security", security_analyzer),
    # "dependency": ("Dependency", dependency_analyzer),
    # "robustness": ("Robustness", robustness_analyzer),
    "maintainability": ("Maintainability", MaintainabilityAnalyzer),
    # "readability": ("Readability", readability_analyzer),
    "performance": ("Performance", PerformanceAnalyzer),
}

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}