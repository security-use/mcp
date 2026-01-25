"""Handler for dependency scanning and fixing tools."""

import asyncio
import os
from pathlib import Path
from typing import Any

from mcp.types import TextContent

from security_use.dependency_scanner import DependencyScanner
from security_use.models import ScanResult

from ..models import FixResult

# Initialize scanner
_scanner = DependencyScanner()


async def handle_scan_dependencies(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Scan for dependency vulnerabilities.

    Analyzes dependency files (requirements.txt, pyproject.toml, etc.) and checks
    each package against vulnerability databases (OSV, GitHub Advisory Database).

    Args:
        arguments: Tool arguments containing optional 'path' parameter

    Returns:
        List of TextContent with formatted vulnerability report
    """
    path = arguments.get("path", os.getcwd())

    # Validate path exists
    if not os.path.exists(path):
        return [TextContent(type="text", text=f"Error: Path does not exist: {path}")]

    try:
        # Run scanner in thread pool to avoid blocking
        result: ScanResult = await asyncio.to_thread(_scanner.scan_path, Path(path))

        if result.errors:
            error_msg = "; ".join(result.errors)
            return [TextContent(type="text", text=f"Scan error: {error_msg}")]

        if not result.vulnerabilities:
            summary = [
                "## Dependency Security Scan Results",
                "",
                "**Status**: No vulnerabilities found",
                "",
                f"- **Scanned files**: {', '.join(result.scanned_files) or 'None found'}",
                "",
                "Your project dependencies are secure.",
            ]
            return [TextContent(type="text", text="\n".join(summary))]

        # Format results for AI consumption
        output_lines = [
            "## Dependency Security Scan Results",
            "",
            f"**Found {len(result.vulnerabilities)} vulnerabilities**",
            "",
            f"- **Scanned files**: {', '.join(result.scanned_files)}",
            "",
            "---",
            "",
        ]

        # Group by severity
        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "UNKNOWN": []}
        for vuln in result.vulnerabilities:
            by_severity[vuln.severity.value].append(vuln)

        # Output in severity order
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            vulns = by_severity[severity]
            if not vulns:
                continue

            output_lines.append(f"### {severity} ({len(vulns)})")
            output_lines.append("")

            for vuln in vulns:
                output_lines.append(f"#### {vuln.package} ({vuln.installed_version})")
                output_lines.append(f"- **ID**: {vuln.id}")
                output_lines.append(f"- **Title**: {vuln.title}")
                output_lines.append(f"- **Affected versions**: {vuln.affected_versions or 'N/A'}")
                output_lines.append(
                    f"- **Fixed in**: {vuln.fixed_version or 'No fix available'}"
                )
                output_lines.append(f"- **Description**: {vuln.description}")
                if vuln.references:
                    output_lines.append(f"- **References**: {', '.join(vuln.references[:3])}")
                output_lines.append("")

        output_lines.extend(
            [
                "---",
                "",
                "### Recommended Actions",
                "",
                "To fix vulnerabilities, use the `fix_vulnerability` tool:",
                "```",
                'fix_vulnerability(package_name="<package>", target_version="<version>")',
                "```",
                "",
                "Or manually update your dependency files to the fixed versions listed above.",
            ]
        )

        return [TextContent(type="text", text="\n".join(output_lines))]

    except ImportError as e:
        return [
            TextContent(
                type="text",
                text=(
                    f"Error: security-use package not properly installed: {e}\n\n"
                    "Please install with: pip install security-use"
                ),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error scanning dependencies: {str(e)}")]


async def handle_fix_vulnerability(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Fix a dependency vulnerability by updating to a safe version.

    Modifies the appropriate dependency file (requirements.txt, pyproject.toml, etc.)
    to use a non-vulnerable version of the package.

    Args:
        arguments: Tool arguments containing:
            - package_name (required): Name of package to fix
            - target_version (optional): Specific version to update to
            - path (optional): Project directory path

    Returns:
        List of TextContent with fix results and diff
    """
    package_name = arguments.get("package_name")
    target_version = arguments.get("target_version")
    path = arguments.get("path", os.getcwd())

    if not package_name:
        return [TextContent(type="text", text="Error: `package_name` is required")]

    # Validate path exists
    if not os.path.exists(path):
        return [TextContent(type="text", text=f"Error: Path does not exist: {path}")]

    try:
        # Import fixer lazily
        from security_use.fixers.dependency_fixer import DependencyFixer
        _fixer = DependencyFixer()

        result: FixResult = await asyncio.to_thread(
            _fixer.fix,
            path=path,
            package_name=package_name,
            target_version=target_version,
        )

        if not result.success:
            error_msg = result.error or "Unknown error occurred"
            return [
                TextContent(
                    type="text",
                    text=f"## Fix Failed\n\n**Package**: {package_name}\n**Error**: {error_msg}",
                )
            ]

        # Format successful fix result
        output_lines = [
            "## Vulnerability Fix Applied",
            "",
            f"**Package**: {package_name}",
            f"**Previous version**: {result.old_version}",
            f"**New version**: {result.new_version}",
            f"**File modified**: {result.file_modified}",
            "",
            "### Changes",
            "",
            "```diff",
            result.diff,
            "```",
            "",
            "### Next Steps",
            "",
            "1. Review the changes above",
            "2. Run your test suite to verify compatibility",
            "3. Commit the updated dependency file",
            "",
            f"**Note**: The package was updated from {result.old_version} to {result.new_version}. "
            "Check the changelog for any breaking changes.",
        ]

        return [TextContent(type="text", text="\n".join(output_lines))]

    except ImportError as e:
        return [
            TextContent(
                type="text",
                text=(
                    f"Error: security-use package not properly installed: {e}\n\n"
                    "Please install with: pip install security-use"
                ),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error fixing vulnerability: {str(e)}")]
