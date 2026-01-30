"""Handler for SBOM generation tools."""

import asyncio
import os
from pathlib import Path
from typing import Any

from mcp.types import TextContent


async def handle_generate_sbom(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Generate a Software Bill of Materials (SBOM) for the project.

    Supports multiple output formats including CycloneDX and SPDX.

    Args:
        arguments: Tool arguments containing:
            - path (optional): Path to the project directory
            - format (optional): Output format (cyclonedx, spdx). Default: cyclonedx
            - include_vulnerabilities (optional): Include vulnerability info. Default: false

    Returns:
        List of TextContent with SBOM content or summary
    """
    path = arguments.get("path", os.getcwd())
    sbom_format = arguments.get("format", "cyclonedx")
    include_vulns = arguments.get("include_vulnerabilities", False)

    # Validate format
    valid_formats = ["cyclonedx", "spdx"]
    if sbom_format.lower() not in valid_formats:
        return [
            TextContent(
                type="text",
                text=(
                    f"Error: Invalid format '{sbom_format}'. "
                    f"Valid formats are: {', '.join(valid_formats)}"
                ),
            )
        ]

    # Validate path exists
    if not os.path.exists(path):
        return [TextContent(type="text", text=f"Error: Path does not exist: {path}")]

    try:
        from security_use.sbom import SBOMFormat, SBOMGenerator

        # Map format string to enum
        format_map = {
            "cyclonedx": SBOMFormat.CYCLONEDX_JSON,
            "spdx": SBOMFormat.SPDX_JSON,
        }
        output_format = format_map.get(sbom_format.lower(), SBOMFormat.CYCLONEDX_JSON)

        generator = SBOMGenerator()
        result = await asyncio.to_thread(
            generator.generate,
            path=Path(path),
            format=output_format,
            include_vulnerabilities=include_vulns,
        )

        output_lines = [
            "## Software Bill of Materials (SBOM)",
            "",
            f"**Format**: {result.format.value}",
            f"**Project Path**: {path}",
            f"**Total Components**: {result.component_count}",
            f"**Generated At**: {result.generated_at}",
            "",
        ]

        # Show first part of SBOM content (truncated for readability)
        content_preview = result.content[:2000] if len(result.content) > 2000 else result.content
        output_lines.extend(
            [
                "### SBOM Content Preview",
                "",
                "```json",
                content_preview,
                "```" if len(result.content) <= 2000 else "...\n```",
                "",
            ]
        )

        if len(result.content) > 2000:
            output_lines.append(
                f"*SBOM truncated for display. Full content is {len(result.content)} characters.*"
            )
            output_lines.append("")

        output_lines.extend(
            [
                "---",
                "",
                "Use `check_compliance` to verify against compliance frameworks.",
            ]
        )

        return [TextContent(type="text", text="\n".join(output_lines))]

    except ImportError:
        return [
            TextContent(
                type="text",
                text=(
                    "Error: security-use SBOM module not available.\n\n"
                    "Please ensure security-use is installed: pip install security-use"
                ),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error generating SBOM: {str(e)}")]
