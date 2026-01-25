"""MCP Server for security scanning tools.

This server exposes security scanning and remediation tools to AI assistants
via the Model Context Protocol (MCP). It integrates with Cursor and other
MCP-compatible clients.
"""

import asyncio
import json
import os
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

# Import security-use scanners
from security_use.scanners.dependency_scanner import DependencyScanner
from security_use.scanners.iac_scanner import IaCScanner
from security_use.fixers.dependency_fixer import DependencyFixer
from security_use.fixers.iac_fixer import IaCFixer

# Initialize the MCP server
server = Server("security-use-mcp")

# Initialize scanners and fixers
dependency_scanner = DependencyScanner()
iac_scanner = IaCScanner()
dependency_fixer = DependencyFixer()
iac_fixer = IaCFixer()


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List all available security tools."""
    return [
        Tool(
            name="scan_dependencies",
            description=(
                "Scan the project for dependency vulnerabilities. "
                "Analyzes requirements.txt, pyproject.toml, and other dependency files "
                "to find known security vulnerabilities (CVEs) in installed packages."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": (
                            "Path to the project directory to scan. "
                            "Defaults to current working directory if not specified."
                        ),
                    }
                },
                "required": [],
            },
        ),
        Tool(
            name="scan_iac",
            description=(
                "Scan Infrastructure as Code files for security misconfigurations. "
                "Supports Terraform (.tf), CloudFormation (.yaml/.json), and other IaC formats. "
                "Detects issues like open S3 buckets, overly permissive IAM, missing encryption, etc."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": (
                            "Path to the directory or file to scan. "
                            "Defaults to current working directory if not specified."
                        ),
                    }
                },
                "required": [],
            },
        ),
        Tool(
            name="fix_vulnerability",
            description=(
                "Fix a detected dependency vulnerability by updating to a safe version. "
                "Modifies requirements.txt or pyproject.toml with the patched version."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "package_name": {
                        "type": "string",
                        "description": "Name of the vulnerable package to fix.",
                    },
                    "target_version": {
                        "type": "string",
                        "description": (
                            "Specific version to update to. "
                            "If not provided, updates to the minimum safe version."
                        ),
                    },
                    "path": {
                        "type": "string",
                        "description": (
                            "Path to the project directory. "
                            "Defaults to current working directory if not specified."
                        ),
                    },
                },
                "required": ["package_name"],
            },
        ),
        Tool(
            name="fix_iac",
            description=(
                "Fix an Infrastructure as Code security misconfiguration. "
                "Can either suggest a fix or apply it automatically."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the IaC file containing the issue.",
                    },
                    "line_number": {
                        "type": "integer",
                        "description": "Line number where the issue is located.",
                    },
                    "rule_id": {
                        "type": "string",
                        "description": "ID of the security rule that was violated.",
                    },
                    "auto_apply": {
                        "type": "boolean",
                        "description": (
                            "If true, automatically apply the fix. "
                            "If false, only return the suggested fix. Defaults to false."
                        ),
                    },
                },
                "required": ["file_path", "rule_id"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool invocations."""
    if name == "scan_dependencies":
        return await handle_scan_dependencies(arguments)
    elif name == "scan_iac":
        return await handle_scan_iac(arguments)
    elif name == "fix_vulnerability":
        return await handle_fix_vulnerability(arguments)
    elif name == "fix_iac":
        return await handle_fix_iac(arguments)
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def handle_scan_dependencies(arguments: dict[str, Any]) -> list[TextContent]:
    """Scan for dependency vulnerabilities."""
    path = arguments.get("path", os.getcwd())

    try:
        results = await asyncio.to_thread(dependency_scanner.scan, path)

        if not results.vulnerabilities:
            return [
                TextContent(
                    type="text",
                    text="No dependency vulnerabilities found. Your dependencies are secure.",
                )
            ]

        # Format results for AI consumption
        output_lines = [
            f"Found {len(results.vulnerabilities)} dependency vulnerabilities:\n"
        ]

        for i, vuln in enumerate(results.vulnerabilities, 1):
            output_lines.append(f"## {i}. {vuln.package_name} ({vuln.installed_version})")
            output_lines.append(f"   - **Severity**: {vuln.severity}")
            output_lines.append(f"   - **CVE**: {vuln.cve_id or 'N/A'}")
            output_lines.append(f"   - **Description**: {vuln.description}")
            output_lines.append(f"   - **Fixed in**: {vuln.fixed_version or 'No fix available'}")
            output_lines.append(f"   - **Remediation**: {vuln.remediation}")
            output_lines.append("")

        output_lines.append("\n**Recommended Action**: Use the `fix_vulnerability` tool to update vulnerable packages.")

        return [TextContent(type="text", text="\n".join(output_lines))]

    except Exception as e:
        return [TextContent(type="text", text=f"Error scanning dependencies: {str(e)}")]


async def handle_scan_iac(arguments: dict[str, Any]) -> list[TextContent]:
    """Scan for IaC security misconfigurations."""
    path = arguments.get("path", os.getcwd())

    try:
        results = await asyncio.to_thread(iac_scanner.scan, path)

        if not results.findings:
            return [
                TextContent(
                    type="text",
                    text="No IaC security issues found. Your infrastructure code follows security best practices.",
                )
            ]

        # Format results for AI consumption
        output_lines = [
            f"Found {len(results.findings)} IaC security issues:\n"
        ]

        for i, finding in enumerate(results.findings, 1):
            output_lines.append(f"## {i}. {finding.rule_id}: {finding.title}")
            output_lines.append(f"   - **File**: {finding.file_path}:{finding.line_number}")
            output_lines.append(f"   - **Severity**: {finding.severity}")
            output_lines.append(f"   - **Resource**: {finding.resource_name or 'N/A'}")
            output_lines.append(f"   - **Description**: {finding.description}")
            output_lines.append(f"   - **Remediation**: {finding.remediation}")
            output_lines.append("")

        output_lines.append("\n**Recommended Action**: Use the `fix_iac` tool to apply fixes, or review and fix manually.")

        return [TextContent(type="text", text="\n".join(output_lines))]

    except Exception as e:
        return [TextContent(type="text", text=f"Error scanning IaC files: {str(e)}")]


async def handle_fix_vulnerability(arguments: dict[str, Any]) -> list[TextContent]:
    """Fix a dependency vulnerability."""
    package_name = arguments.get("package_name")
    target_version = arguments.get("target_version")
    path = arguments.get("path", os.getcwd())

    if not package_name:
        return [TextContent(type="text", text="Error: package_name is required")]

    try:
        result = await asyncio.to_thread(
            dependency_fixer.fix,
            path=path,
            package_name=package_name,
            target_version=target_version,
        )

        if not result.success:
            return [TextContent(type="text", text=f"Failed to fix vulnerability: {result.error}")]

        # Format the result
        output_lines = [
            f"Successfully updated {package_name}:\n",
            f"- **Previous version**: {result.old_version}",
            f"- **New version**: {result.new_version}",
            f"- **File modified**: {result.file_modified}",
            "",
            "**Changes made**:",
            "```diff",
            result.diff,
            "```",
            "",
            "Please review the changes and run your tests to ensure compatibility.",
        ]

        return [TextContent(type="text", text="\n".join(output_lines))]

    except Exception as e:
        return [TextContent(type="text", text=f"Error fixing vulnerability: {str(e)}")]


async def handle_fix_iac(arguments: dict[str, Any]) -> list[TextContent]:
    """Fix an IaC security issue."""
    file_path = arguments.get("file_path")
    line_number = arguments.get("line_number")
    rule_id = arguments.get("rule_id")
    auto_apply = arguments.get("auto_apply", False)

    if not file_path or not rule_id:
        return [TextContent(type="text", text="Error: file_path and rule_id are required")]

    try:
        result = await asyncio.to_thread(
            iac_fixer.fix,
            file_path=file_path,
            line_number=line_number,
            rule_id=rule_id,
            auto_apply=auto_apply,
        )

        if not result.success:
            return [TextContent(type="text", text=f"Failed to generate fix: {result.error}")]

        if auto_apply:
            output_lines = [
                f"Successfully applied fix for {rule_id}:\n",
                f"- **File**: {file_path}",
                f"- **Rule**: {rule_id}",
                "",
                "**Changes applied**:",
                "```diff",
                result.diff,
                "```",
                "",
                "Please review the changes to ensure they meet your requirements.",
            ]
        else:
            output_lines = [
                f"Suggested fix for {rule_id}:\n",
                f"- **File**: {file_path}",
                f"- **Line**: {line_number or 'N/A'}",
                f"- **Rule**: {rule_id}",
                "",
                "**Before**:",
                "```",
                result.before,
                "```",
                "",
                "**After (suggested)**:",
                "```",
                result.after,
                "```",
                "",
                "**Explanation**: " + result.explanation,
                "",
                "To apply this fix automatically, call `fix_iac` with `auto_apply: true`.",
            ]

        return [TextContent(type="text", text="\n".join(output_lines))]

    except Exception as e:
        return [TextContent(type="text", text=f"Error fixing IaC issue: {str(e)}")]


def main():
    """Main entry point for the MCP server."""
    import asyncio

    async def run_server():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )

    asyncio.run(run_server())


if __name__ == "__main__":
    main()
