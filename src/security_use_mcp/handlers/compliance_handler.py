"""Handler for compliance checking tools."""

import asyncio
import os
from typing import Any

from mcp.types import TextContent


async def handle_check_compliance(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Check project against a compliance framework.

    Scans IaC files and maps findings to compliance framework controls like
    SOC 2, HIPAA, PCI-DSS, NIST, and CIS benchmarks.

    Args:
        arguments: Tool arguments containing:
            - path (optional): Path to the project directory
            - framework (required): Compliance framework to check against

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
                    "- `nist-800-53`: NIST 800-53\n"
                    "- `cis-aws`: CIS AWS Benchmarks\n"
                    "- `cis-azure`: CIS Azure Benchmarks\n"
                    "- `cis-gcp`: CIS GCP Benchmarks\n"
                    "- `cis-kubernetes`: CIS Kubernetes Benchmarks\n"
                    "- `iso-27001`: ISO 27001"
                ),
            )
        ]

    # Validate framework - map common names to full names
    framework_aliases = {
        "cis": "cis-aws",  # Default CIS to AWS
        "nist": "nist-800-53",
        "iso": "iso-27001",
    }
    normalized_framework = framework_aliases.get(framework.lower(), framework.lower())

    valid_frameworks = [
        "soc2",
        "hipaa",
        "pci-dss",
        "nist-800-53",
        "cis-aws",
        "cis-azure",
        "cis-gcp",
        "cis-kubernetes",
        "iso-27001",
    ]
    if normalized_framework not in valid_frameworks:
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
        from security_use import scan_iac
        from security_use.compliance import ComplianceFramework, ComplianceMapper

        # Map string to enum
        framework_enum_map = {
            "soc2": ComplianceFramework.SOC2,
            "hipaa": ComplianceFramework.HIPAA,
            "pci-dss": ComplianceFramework.PCI_DSS,
            "nist-800-53": ComplianceFramework.NIST_800_53,
            "cis-aws": ComplianceFramework.CIS_AWS,
            "cis-azure": ComplianceFramework.CIS_AZURE,
            "cis-gcp": ComplianceFramework.CIS_GCP,
            "cis-kubernetes": ComplianceFramework.CIS_K8S,
            "iso-27001": ComplianceFramework.ISO_27001,
        }
        framework_enum = framework_enum_map.get(normalized_framework)

        # First, scan IaC files
        scan_result = await asyncio.to_thread(scan_iac, path=str(path))

        if scan_result.errors:
            error_msg = "; ".join(scan_result.errors)
            return [TextContent(type="text", text=f"Scan error: {error_msg}")]

        # Map findings to compliance framework
        mapper = ComplianceMapper()
        compliance_findings = []

        for finding in scan_result.iac_findings:
            enriched = mapper.enrich_finding(finding)
            compliance_findings.append(enriched)

        # Filter by framework
        framework_findings = mapper.get_findings_by_framework(
            scan_result.iac_findings, framework_enum
        )

        framework_names = {
            "soc2": "SOC 2 Type II",
            "hipaa": "HIPAA Security Rule",
            "pci-dss": "PCI DSS v4.0",
            "nist-800-53": "NIST 800-53",
            "cis-aws": "CIS AWS Benchmarks",
            "cis-azure": "CIS Azure Benchmarks",
            "cis-gcp": "CIS GCP Benchmarks",
            "cis-kubernetes": "CIS Kubernetes Benchmarks",
            "iso-27001": "ISO 27001",
        }

        output_lines = [
            "## Compliance Check Results",
            "",
            f"**Framework**: {framework_names.get(normalized_framework, normalized_framework)}",
            f"**Project Path**: {path}",
            f"**Files Scanned**: {len(scan_result.scanned_files)}",
            "",
            "### Summary",
            "",
            f"- **Total IaC Findings**: {len(scan_result.iac_findings)}",
            f"- **Findings Mapped to {framework_names.get(normalized_framework, framework)}**: "
            f"{len(framework_findings)}",
            "",
        ]

        if not framework_findings:
            output_lines.extend(
                [
                    "**Status**: No compliance issues found for this framework.",
                    "",
                    "Your infrastructure code appears to comply with "
                    f"{framework_names.get(normalized_framework, framework)} requirements "
                    "based on the scanned files.",
                ]
            )
        else:
            output_lines.extend(
                [
                    "---",
                    "",
                ]
            )

            # Group by control
            controls_seen: dict[str, list] = {}
            for finding in framework_findings:
                mapping = mapper.get_mapping(finding.rule_id)
                for control in mapping.controls:
                    if control.framework == framework_enum:
                        key = f"{control.control_id}: {control.title}"
                        if key not in controls_seen:
                            controls_seen[key] = []
                        controls_seen[key].append(finding)

            for control_key, findings in sorted(controls_seen.items()):
                output_lines.append(f"### {control_key}")
                output_lines.append("")

                for finding in findings[:5]:  # Limit to 5 findings per control
                    output_lines.append(f"- **{finding.rule_id}**: {finding.title}")
                    output_lines.append(f"  - File: `{finding.file_path}:{finding.line_number}`")
                    output_lines.append(f"  - Severity: {finding.severity.value}")

                if len(findings) > 5:
                    output_lines.append(f"  - ... and {len(findings) - 5} more findings")

                output_lines.append("")

            output_lines.extend(
                [
                    "---",
                    "",
                    "### Remediation Guidance",
                    "",
                    "Use `fix_iac` to fix individual findings:",
                    "```",
                    'fix_iac(file_path="<file>", rule_id="<rule_id>", auto_apply=true)',
                    "```",
                ]
            )

        return [TextContent(type="text", text="\n".join(output_lines))]

    except ImportError as e:
        return [
            TextContent(
                type="text",
                text=(
                    f"Error: security-use compliance module not available: {e}\n\n"
                    "Please ensure security-use is installed: pip install security-use"
                ),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error checking compliance: {str(e)}")]
