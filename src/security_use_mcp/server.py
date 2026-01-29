"""MCP Server for security scanning tools.

This server exposes security scanning and remediation tools to AI assistants
via the Model Context Protocol (MCP). It integrates with Cursor and other
MCP-compatible clients.
"""

from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

# Import handlers
from .handlers import (
    handle_create_fix_pr,
    handle_fix_iac,
    handle_fix_vulnerability,
    handle_scan_dependencies,
    handle_scan_iac,
)

# Initialize the MCP server
server = Server("security-use-mcp")


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
                "Detects issues like open S3 buckets, overly permissive IAM, missing encryption."
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
                "Modifies requirements.txt or pyproject.toml with the patched version. "
                "Returns a diff of changes for review."
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
                "Can either suggest a fix (default) or apply it automatically. "
                "Returns before/after code for review."
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
        Tool(
            name="create_fix_pr",
            description=(
                "Create a GitHub Pull Request with security fixes. "
                "Commits pending changes, pushes to a new branch, and opens a PR. "
                "Use after applying fixes with fix_vulnerability or fix_iac."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": (
                            "Repository path or owner/name. "
                            "Defaults to current working directory."
                        ),
                    },
                    "vulnerability_id": {
                        "type": "string",
                        "description": "Vulnerability ID to reference in the PR.",
                    },
                    "iac_finding_id": {
                        "type": "string",
                        "description": "IaC finding ID to reference in the PR.",
                    },
                    "branch_name": {
                        "type": "string",
                        "description": (
                            "Target branch name. "
                            "Auto-generated if not specified."
                        ),
                    },
                    "draft": {
                        "type": "boolean",
                        "description": "Create as draft PR. Defaults to true.",
                    },
                },
                "required": [],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool invocations."""
    handlers = {
        "scan_dependencies": handle_scan_dependencies,
        "scan_iac": handle_scan_iac,
        "fix_vulnerability": handle_fix_vulnerability,
        "fix_iac": handle_fix_iac,
        "create_fix_pr": handle_create_fix_pr,
    }

    handler = handlers.get(name)
    if handler:
        return await handler(arguments)
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


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
