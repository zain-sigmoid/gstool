"""
Core data models for the unified code review tool.
Defines standardized data structures for findings, reports, and analysis results.
"""

# Flake8: noqa: E501
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any, Set
from datetime import datetime
import uuid


class SeverityLevel(Enum):
    """Standardized severity levels across all analysis modules."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(Enum):
    """Categories of findings from different analysis modules."""

    SECURITY = "security"
    PRIVACY = "privacy"
    QUALITY = "quality"
    PERFORMANCE = "performance"
    TESTABILITY = "testability"
    READABILITY = "readability"
    OBSERVABILITY = "observability"
    DEPENDENCY = "dependency"
    MAINTAINABILITY = "maintainability"
    COMPLIANCE = "compliance"


class ComplexityLevel(Enum):
    """Complexity level for remediation efforts."""

    TRIVIAL = "trivial"  # < 1 hour
    SIMPLE = "simple"  # 1-4 hours
    MODERATE = "moderate"  # 1-2 days
    COMPLEX = "complex"  # 3-5 days
    VERY_COMPLEX = "very_complex"  # > 1 week


@dataclass
class CodeLocation:
    """Standardized representation of code location."""

    file_path: str
    line_number: Optional[int] = None
    end_line_number: Optional[int] = None
    column: Optional[int] = None
    end_column: Optional[int] = None
    function_name: Optional[str] = None
    class_name: Optional[str] = None

    def __str__(self) -> str:
        location_str = self.file_path
        if self.line_number:
            location_str += f":{self.line_number}"
            if self.column:
                location_str += f":{self.column}"
        return location_str


@dataclass
class UnifiedFinding:
    """Standardized finding representation across all analysis modules."""

    # Core identification
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    details: Optional[Any] = None

    # Classification
    category: FindingCategory = FindingCategory.QUALITY
    severity: SeverityLevel = SeverityLevel.MEDIUM
    confidence_score: float = 1.0  # 0.0 to 1.0

    # Location information
    location: CodeLocation = field(default_factory=lambda: CodeLocation(""))

    # Technical details
    rule_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None

    # Context and remediation
    code_snippet: Optional[str] = None
    remediation_guidance: Optional[str] = None
    remediation_complexity: ComplexityLevel = ComplexityLevel.MODERATE

    # Compliance and standards
    compliance_frameworks: List[str] = field(default_factory=list)
    owasp_category: Optional[str] = None

    # Metadata
    source_analyzer: str = ""  # Which analyzer found this
    timestamp: datetime = field(default_factory=datetime.now)
    tags: Set[str] = field(default_factory=set)

    # Additional data for specific analyzers
    extra_data: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate and normalize data after initialization."""
        if not self.title and self.description:
            # Generate title from description if not provided
            self.title = (
                self.description[:50] + "..."
                if len(self.description) > 50
                else self.description
            )

        # Ensure confidence score is in valid range
        self.confidence_score = max(0.0, min(1.0, self.confidence_score))


@dataclass
class AnalysisMetrics:
    """Metrics for individual analysis modules."""

    analyzer_name: str
    execution_time_seconds: float
    files_analyzed: int
    findings_count: int
    error_count: int = 0
    warnings_count: int = 0
    success: bool = True
    error_message: Optional[str] = None


@dataclass
class AnalysisResult:
    """Result from an individual analyzer run."""

    findings: List["UnifiedFinding"]
    metrics: AnalysisMetrics
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceStatus:
    """Compliance status for different frameworks."""

    framework_name: str
    total_checks: int
    passed_checks: int
    failed_checks: int
    compliance_percentage: float
    critical_failures: List[str] = field(default_factory=list)


@dataclass
class TrendData:
    """Historical trend data for metrics."""

    timestamp: datetime
    metric_name: str
    value: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConsolidatedReport:
    """Unified report containing all analysis results."""

    # Report metadata
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    target_path: str = ""

    # Core findings
    findings: List[UnifiedFinding] = field(default_factory=list)

    # Analysis metrics
    analysis_metrics: List[AnalysisMetrics] = field(default_factory=list)
    total_execution_time: float = 0.0

    # Summary statistics
    summary: Dict[str, Any] = field(default_factory=dict)

    # Compliance information
    compliance_status: List[ComplianceStatus] = field(default_factory=list)

    # Trend analysis (for historical comparison)
    trend_data: List[TrendData] = field(default_factory=list)

    # Configuration used for analysis
    analysis_config: Dict[str, Any] = field(default_factory=dict)

    def get_findings_by_category(
        self, category: FindingCategory
    ) -> List[UnifiedFinding]:
        """Get all findings for a specific category."""
        return [f for f in self.findings if f.category == category]

    def get_findings_by_severity(self, severity: SeverityLevel) -> List[UnifiedFinding]:
        """Get all findings with specific severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_critical_findings(self) -> List[UnifiedFinding]:
        """Get all critical and high severity findings."""
        return [
            f
            for f in self.findings
            if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
        ]

    def get_summary_stats(self) -> Dict[str, int]:
        """Generate summary statistics."""
        stats = {
            "total_findings": len(self.findings),
            "critical_findings": len(
                [f for f in self.findings if f.severity == SeverityLevel.CRITICAL]
            ),
            "high_findings": len(
                [f for f in self.findings if f.severity == SeverityLevel.HIGH]
            ),
            "medium_findings": len(
                [f for f in self.findings if f.severity == SeverityLevel.MEDIUM]
            ),
            "low_findings": len(
                [f for f in self.findings if f.severity == SeverityLevel.LOW]
            ),
            "info_findings": len(
                [f for f in self.findings if f.severity == SeverityLevel.INFO]
            ),
        }

        # Add category-wise counts
        for category in FindingCategory:
            stats[f"{category.value}_findings"] = len(
                self.get_findings_by_category(category)
            )

        return stats

    def get_top_files_by_issues(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get files with most issues."""
        file_counts = {}
        for finding in self.findings:
            file_path = finding.location.file_path
            if file_path not in file_counts:
                file_counts[file_path] = {"count": 0, "critical": 0, "high": 0}
            file_counts[file_path]["count"] += 1
            if finding.severity == SeverityLevel.CRITICAL:
                file_counts[file_path]["critical"] += 1
            elif finding.severity == SeverityLevel.HIGH:
                file_counts[file_path]["high"] += 1

        # Sort by total count, then by critical, then by high
        sorted_files = sorted(
            file_counts.items(),
            key=lambda x: (x[1]["count"], x[1]["critical"], x[1]["high"]),
            reverse=True,
        )

        return [
            {"file_path": file_path, **counts}
            for file_path, counts in sorted_files[:limit]
        ]


@dataclass
class AnalysisConfiguration:
    """Configuration for analysis execution."""

    # Target configuration
    target_path: str = ""
    file_patterns: List[str] = field(default_factory=lambda: ["*.py"])
    exclude_patterns: List[str] = field(default_factory=list)

    # Analysis module selection
    enabled_analyzers: Set[str] = field(default_factory=set)
    analyzer_configs: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Output configuration
    severity_threshold: SeverityLevel = SeverityLevel.LOW
    max_findings_per_analyzer: int = 1000
    include_low_confidence: bool = False

    # Performance configuration
    parallel_execution: bool = True
    timeout_seconds: int = 300

    # Report configuration
    include_code_snippets: bool = True
    include_remediation: bool = True
    output_formats: List[str] = field(default_factory=lambda: ["json"])
