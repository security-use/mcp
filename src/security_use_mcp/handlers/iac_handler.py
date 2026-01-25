"""Handler for IaC scanning and fixing tools."""

import asyncio
import os
from typing import Any

from mcp.types import TextContent

from security_use.scanners.iac_scanner import IaCScanner
from security_use.fixers.iac_fixer import IaCFixer

from ..models import IaCScanResult, FixResult

# Initialize scanner and fixer
_scanner = IaCScanner()
_fixer = IaCFixer()


async def handle_scan_iac(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Scan Infrastructure as Code files for security misconfigurations.

    Supports:
    - Terraform (.tf files)
    - CloudFormation (.yaml, .json templates)
    - Other IaC formats

    Detects issues like:
    - Open S3 buckets
    - Overly permissive IAM policies
    - Missing encryption
    - Public network exposure
    - Missing MFA requirements

    Args:
        arguments: Tool arguments containing optional 'path' parameter

    Returns:
        List of TextContent with formatted IaC security findings
    """
    path = arguments.get("path", os.getcwd())

    # Validate path exists
    if not os.path.exists(path):
        return [TextContent(type="text", text=f"Error: Path does not exist: {path}")]

    try:
        # Run scanner in thread pool to avoid blocking
        result: IaCScanResult = await asyncio.to_thread(_scanner.scan, path)

        if result.error:
            return [TextContent(type="text", text=f"Scan error: {result.error}")]

        if not result.findings:
            summary = [
                "## IaC Security Scan Results",
                "",
                "**Status**: No security issues found",
                "",
                f"- **Scanned files**: {len(result.scanned_files)}",
                f"- **Scan duration**: {result.scan_duration_ms}ms",
                "",
                "Your infrastructure code follows security best practices.",
            ]
            if result.scanned_files:
                summary.extend(["", "**Files scanned**:"])
                for f in result.scanned_files[:10]:
                    summary.append(f"- {f}")
                if len(result.scanned_files) > 10:
                    summary.append(f"- ... and {len(result.scanned_files) - 10} more")

            return [TextContent(type="text", text="\n".join(summary))]

        # Format results for AI consumption
        output_lines = [
            "## IaC Security Scan Results",
            "",
            f"**Found {len(result.findings)} security issues**",
            "",
            f"- **Scanned files**: {len(result.scanned_files)}",
            f"- **Scan duration**: {result.scan_duration_ms}ms",
            "",
            "---",
            "",
        ]

        # Group by severity
        by_severity = {"critical": [], "high": [], "medium": [], "low": [], "unknown": []}
        for finding in result.findings:
            by_severity[finding.severity.value].append(finding)

        # Output in severity order
        for severity in ["critical", "high", "medium", "low", "unknown"]:
            findings = by_severity[severity]
            if not findings:
                continue

            output_lines.append(f"### {severity.upper()} ({len(findings)})")
            output_lines.append("")

            for finding in findings:
                output_lines.append(f"#### {finding.rule_id}: {finding.title}")
                output_lines.append(f"- **File**: `{finding.file_path}:{finding.line_number}`")
                if finding.resource_name:
                    output_lines.append(
                        f"- **Resource**: {finding.resource_type or 'resource'}.{finding.resource_name}"
                    )
                output_lines.append(f"- **Description**: {finding.description}")
                output_lines.append(f"- **Remediation**: {finding.remediation}")
                if finding.code_snippet:
                    output_lines.extend(
                        [
                            "",
                            "**Problematic code**:",
                            "```",
                            finding.code_snippet,
                            "```",
                        ]
                    )
                output_lines.append("")

        output_lines.extend(
            [
                "---",
                "",
                "### Recommended Actions",
                "",
                "To fix issues, you can:",
                "",
                "1. **Use the fix_iac tool** to get suggested fixes:",
                "   ```",
                '   fix_iac(file_path="<file>", rule_id="<rule_id>", line_number=<line>)',
                "   ```",
                "",
                "2. **Apply fixes automatically**:",
                "   ```",
                '   fix_iac(file_path="<file>", rule_id="<rule_id>", auto_apply=true)',
                "   ```",
                "",
                "3. **Manually review** and fix based on the remediation guidance above.",
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
        return [TextContent(type="text", text=f"Error scanning IaC files: {str(e)}")]


async def handle_fix_iac(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Fix an IaC security misconfiguration.

    Can either:
    - Suggest a fix (default) - returns before/after code snippets
    - Apply the fix automatically (when auto_apply=true)

    Args:
        arguments: Tool arguments containing:
            - file_path (required): Path to IaC file
            - rule_id (required): ID of security rule violated
            - line_number (optional): Line where issue is located
            - auto_apply (optional): If true, apply fix automatically

    Returns:
        List of TextContent with fix suggestion or applied changes
    """
    file_path = arguments.get("file_path")
    rule_id = arguments.get("rule_id")
    line_number = arguments.get("line_number")
    auto_apply = arguments.get("auto_apply", False)

    if not file_path:
        return [TextContent(type="text", text="Error: `file_path` is required")]

    if not rule_id:
        return [TextContent(type="text", text="Error: `rule_id` is required")]

    # Validate file exists
    if not os.path.exists(file_path):
        return [TextContent(type="text", text=f"Error: File does not exist: {file_path}")]

    try:
        result: FixResult = await asyncio.to_thread(
            _fixer.fix,
            file_path=file_path,
            line_number=line_number,
            rule_id=rule_id,
            auto_apply=auto_apply,
        )

        if not result.success:
            error_msg = result.error or "Unknown error occurred"
            return [
                TextContent(
                    type="text",
                    text=f"## Fix Generation Failed\n\n**Rule**: {rule_id}\n**File**: {file_path}\n**Error**: {error_msg}",
                )
            ]

        if auto_apply:
            # Fix was applied automatically
            output_lines = [
                "## IaC Fix Applied",
                "",
                f"**Rule**: {rule_id}",
                f"**File**: {file_path}",
                "",
                "### Changes Applied",
                "",
                "```diff",
                result.diff,
                "```",
                "",
                "### Explanation",
                "",
                result.explanation,
                "",
                "### Next Steps",
                "",
                "1. Review the changes above to ensure they meet your requirements",
                "2. Run `terraform plan` or equivalent to verify the changes",
                "3. Commit the updated infrastructure code",
            ]
        else:
            # Return suggested fix without applying
            output_lines = [
                "## Suggested IaC Fix",
                "",
                f"**Rule**: {rule_id}",
                f"**File**: {file_path}",
                f"**Line**: {line_number or 'N/A'}",
                "",
                "### Current Code (Before)",
                "",
                "```hcl",
                result.before,
                "```",
                "",
                "### Suggested Fix (After)",
                "",
                "```hcl",
                result.after,
                "```",
                "",
                "### Explanation",
                "",
                result.explanation,
                "",
                "---",
                "",
                "To apply this fix automatically, run:",
                "```",
                f'fix_iac(file_path="{file_path}", rule_id="{rule_id}", auto_apply=true)',
                "```",
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
        return [TextContent(type="text", text=f"Error fixing IaC issue: {str(e)}")]
