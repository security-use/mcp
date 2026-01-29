"""Handler for compliance checking tools."""

import asyncio
import os
from pathlib import Path
from typing import Any

from mcp.types import TextContent


async def handle_check_compliance(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Check project against a compliance framework.

    Analyzes the project for compliance with security frameworks like
    SOC 2, HIPAA, PCI-DSS, and CIS benchmarks.

    Args:
        arguments: Tool arguments containing:
            - path (optional): Path to the project directory
            - framework (required): Compliance framework (soc2, hipaa, pci-dss, cis)

    Returns:
        List of TextContent with compliance findings grouped by control
    """
    path = arguments.get("path", os.getcwd())
    framework = arguments.get("framework")

    if not framework:
        return [
            TextContent(
                type="text",
                text=(
                    "Error: `framework` is required.\n\n"
                    "Supported frameworks:\n"
                    "- `soc2`: SOC 2 Type II controls\n"
                    "- `hipaa`: HIPAA Security Rule\n"
                    "- `pci-dss`: PCI DSS v4.0\n"
                    "- `cis`: CIS Benchmarks"
                ),
            )
        ]

    # Validate framework
    valid_frameworks = ["soc2", "hipaa", "pci-dss", "cis"]
    if framework.lower() not in valid_frameworks:
        return [
            TextContent(
                type="text",
                text=(
                    f"Error: Invalid framework '{framework}'. "
                    f"Valid frameworks are: {', '.join(valid_frameworks)}"
                ),
            )
        ]

    # Validate path exists
    if not os.path.exists(path):
        return [TextContent(type="text", text=f"Error: Path does not exist: {path}")]

    try:
        from security_use.compliance import ComplianceChecker

        checker = ComplianceChecker()
        result = await asyncio.to_thread(
            checker.check,
            path=Path(path),
            framework=framework.lower(),
        )

        if result.error:
            return [
                TextContent(
                    type="text",
                    text=f"Error checking compliance: {result.error}",
                )
            ]

        # Calculate summary statistics
        total_controls = len(result.controls)
        passing = sum(1 for c in result.controls if c.status == "pass")
        failing = sum(1 for c in result.controls if c.status == "fail")
        not_applicable = sum(1 for c in result.controls if c.status == "n/a")

        framework_names = {
            "soc2": "SOC 2 Type II",
            "hipaa": "HIPAA Security Rule",
            "pci-dss": "PCI DSS v4.0",
            "cis": "CIS Benchmarks",
        }

        output_lines = [
            "## Compliance Check Results",
            "",
            f"**Framework**: {framework_names.get(framework.lower(), framework)}",
            f"**Project Path**: {path}",
            "",
            "### Summary",
            "",
            f"- **Total Controls**: {total_controls}",
            f"- **Passing**: {passing} ({100*passing//total_controls if total_controls else 0}%)",
            f"- **Failing**: {failing}",
            f"- **Not Applicable**: {not_applicable}",
            "",
            "---",
            "",
        ]

        # Group findings by control category
        categories: dict[str, list] = {}
        for control in result.controls:
            category = control.category or "Uncategorized"
            if category not in categories:
                categories[category] = []
            categories[category].append(control)

        for category, controls in sorted(categories.items()):
            category_failing = sum(1 for c in controls if c.status == "fail")
            output_lines.append(
                f"### {category} ({category_failing} failing)"
            )
            output_lines.append("")

            for control in controls:
                status_icon = (
                    "✓" if control.status == "pass"
                    else "✗" if control.status == "fail"
                    else "—"
                )
                output_lines.append(
                    f"- [{status_icon}] **{control.id}**: {control.title}"
                )

                if control.status == "fail" and control.findings:
                    for finding in control.findings[:3]:
                        output_lines.append(f"  - {finding}")
                    if len(control.findings) > 3:
                        output_lines.append(
                            f"  - ... and {len(control.findings) - 3} more findings"
                        )

            output_lines.append("")

        if failing > 0:
            output_lines.extend(
                [
                    "---",
                    "",
                    "### Remediation Guidance",
                    "",
                    "Review the failing controls above and address the findings. "
                    "Common remediation steps include:",
                    "",
                    "1. Enable encryption at rest and in transit",
                    "2. Implement proper access controls",
                    "3. Enable audit logging",
                    "4. Configure network security groups",
                    "5. Implement secrets management",
                ]
            )

        return [TextContent(type="text", text="\n".join(output_lines))]

    except ImportError:
        return [
            TextContent(
                type="text",
                text=(
                    "Error: security-use compliance module not available.\n\n"
                    "Please ensure the compliance feature is installed: "
                    "pip install security-use[compliance]"
                ),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error checking compliance: {str(e)}")]
