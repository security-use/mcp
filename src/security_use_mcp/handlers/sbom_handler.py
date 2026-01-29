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

    Returns:
        List of TextContent with SBOM content or file path
    """
    path = arguments.get("path", os.getcwd())
    sbom_format = arguments.get("format", "cyclonedx")

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
        from security_use.sbom import SBOMGenerator

        generator = SBOMGenerator()
        result = await asyncio.to_thread(
            generator.generate,
            path=Path(path),
            output_format=sbom_format.lower(),
        )

        if result.error:
            return [
                TextContent(
                    type="text",
                    text=f"Error generating SBOM: {result.error}",
                )
            ]

        output_lines = [
            "## Software Bill of Materials (SBOM)",
            "",
            f"**Format**: {sbom_format.upper()}",
            f"**Project Path**: {path}",
            f"**Total Components**: {result.component_count}",
            "",
            "### Summary",
            "",
            f"- **Direct Dependencies**: {result.direct_dependencies}",
            f"- **Transitive Dependencies**: {result.transitive_dependencies}",
            f"- **Licenses Detected**: {len(result.licenses)}",
            "",
        ]

        if result.licenses:
            output_lines.extend(
                [
                    "### Licenses",
                    "",
                ]
            )
            for license_name, count in sorted(
                result.licenses.items(), key=lambda x: x[1], reverse=True
            )[:10]:
                output_lines.append(f"- {license_name}: {count} components")

            if len(result.licenses) > 10:
                output_lines.append(f"- ... and {len(result.licenses) - 10} more")

            output_lines.append("")

        if result.output_file:
            output_lines.extend(
                [
                    "### Output File",
                    "",
                    f"SBOM saved to: `{result.output_file}`",
                    "",
                ]
            )

        output_lines.extend(
            [
                "---",
                "",
                "Use `check_compliance` to verify SBOM against compliance frameworks.",
            ]
        )

        return [TextContent(type="text", text="\n".join(output_lines))]

    except ImportError:
        return [
            TextContent(
                type="text",
                text=(
                    "Error: security-use SBOM module not available.\n\n"
                    "Please ensure the SBOM feature is installed: "
                    "pip install security-use[sbom]"
                ),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error generating SBOM: {str(e)}")]
