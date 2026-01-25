"""Data models for security scanning results."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class Vulnerability:
    """Represents a detected dependency vulnerability."""

    package_name: str
    installed_version: str
    severity: Severity
    description: str
    cve_id: str | None = None
    fixed_version: str | None = None
    remediation: str = ""
    vulnerable_range: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class DependencyScanResult:
    """Result of a dependency vulnerability scan."""

    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)
    total_dependencies: int = 0
    scan_duration_ms: int = 0
    error: str | None = None


@dataclass
class IaCFinding:
    """Represents a detected IaC security issue."""

    rule_id: str
    title: str
    file_path: str
    line_number: int
    severity: Severity
    description: str
    remediation: str
    resource_name: str | None = None
    resource_type: str | None = None
    code_snippet: str = ""


@dataclass
class IaCScanResult:
    """Result of an IaC security scan."""

    findings: list[IaCFinding] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)
    scan_duration_ms: int = 0
    error: str | None = None


@dataclass
class FixResult:
    """Result of applying a fix."""

    success: bool
    file_modified: str = ""
    old_version: str = ""
    new_version: str = ""
    diff: str = ""
    before: str = ""
    after: str = ""
    explanation: str = ""
    error: str | None = None
