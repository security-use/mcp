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
    handle_acknowledge_alert,
    handle_analyze_request,
    handle_block_ip,
    handle_check_compliance,
    handle_configure_sensor,
    handle_create_fix_pr,
    handle_detect_project,
    handle_detect_vulnerable_endpoints,
    handle_fix_iac,
    handle_fix_vulnerability,
    handle_generate_sbom,
    handle_get_alert_details,
    handle_get_blocked_ips,
    handle_get_security_alerts,
    handle_get_sensor_config,
    handle_init_project,
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
                            "Repository path or owner/name. Defaults to current working directory."
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
                        "description": ("Target branch name. Auto-generated if not specified."),
                    },
                    "draft": {
                        "type": "boolean",
                        "description": "Create as draft PR. Defaults to true.",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="get_security_alerts",
            description=(
                "Retrieve recent security alerts from the runtime sensor. "
                "Returns alerts with severity, attack type, and source information."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "time_range": {
                        "type": "string",
                        "description": (
                            "Time range to query (e.g., '1h', '24h', '7d'). Defaults to '24h'."
                        ),
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity level (critical, high, medium, low).",
                    },
                    "attack_type": {
                        "type": "string",
                        "description": "Filter by attack type (e.g., 'sql_injection', 'xss').",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="get_alert_details",
            description=(
                "Get full details of a specific security alert. "
                "Returns attack payload, source IP, and matched patterns."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "ID of the alert to retrieve.",
                    },
                },
                "required": ["alert_id"],
            },
        ),
        Tool(
            name="acknowledge_alert",
            description=(
                "Mark a security alert as reviewed/acknowledged. "
                "Removes the alert from active alerts list."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "ID of the alert to acknowledge.",
                    },
                    "notes": {
                        "type": "string",
                        "description": "Notes about the acknowledgment.",
                    },
                },
                "required": ["alert_id"],
            },
        ),
        Tool(
            name="block_ip",
            description=(
                "Block a source IP address. "
                "Adds the IP to the sensor's block list for the specified duration."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "IP address to block.",
                    },
                    "duration": {
                        "type": "string",
                        "description": (
                            "Block duration (e.g., '1h', '24h', 'permanent'). Defaults to '24h'."
                        ),
                    },
                },
                "required": ["ip_address"],
            },
        ),
        Tool(
            name="get_blocked_ips",
            description=(
                "List all currently blocked IP addresses. Shows IP, duration, and expiration time."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="configure_sensor",
            description=(
                "Update runtime sensor configuration. "
                "Modify detection sensitivity, patterns, and rate limits."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "sensitivity": {
                        "type": "string",
                        "description": "Detection sensitivity (low, medium, high).",
                    },
                    "patterns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Custom detection patterns to add.",
                    },
                    "rate_limits": {
                        "type": "object",
                        "description": "Rate limiting configuration.",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="generate_sbom",
            description=(
                "Generate a Software Bill of Materials (SBOM) for the project. "
                "Supports CycloneDX and SPDX formats."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": (
                            "Path to the project directory. Defaults to current working directory."
                        ),
                    },
                    "format": {
                        "type": "string",
                        "description": ("Output format (cyclonedx, spdx). Defaults to cyclonedx."),
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="check_compliance",
            description=(
                "Check project against a compliance framework. "
                "Scans IaC files and maps findings to compliance controls. "
                "Supports SOC2, HIPAA, PCI-DSS, NIST 800-53, CIS, and ISO 27001."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": (
                            "Path to the project directory. Defaults to current working directory."
                        ),
                    },
                    "framework": {
                        "type": "string",
                        "description": (
                            "Compliance framework to check against. "
                            "Options: soc2, hipaa, pci-dss, nist-800-53, "
                            "cis-aws, cis-azure, cis-gcp, cis-kubernetes, iso-27001."
                        ),
                    },
                },
                "required": ["framework"],
            },
        ),
        Tool(
            name="detect_vulnerable_endpoints",
            description=(
                "Detect vulnerable API endpoints in a project. "
                "Analyzes code to find endpoints using vulnerable packages "
                "or high-risk code patterns."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": (
                            "Path to the project directory. Defaults to current working directory."
                        ),
                    },
                    "min_risk_score": {
                        "type": "number",
                        "description": ("Minimum risk score threshold (0.0-1.0). Defaults to 0.3."),
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="analyze_request",
            description=(
                "Analyze an HTTP request for potential attacks. "
                "Detects SQL injection, XSS, path traversal, command injection, "
                "and other attack patterns."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "method": {
                        "type": "string",
                        "description": "HTTP method (GET, POST, etc.).",
                    },
                    "path": {
                        "type": "string",
                        "description": "Request path (e.g., '/api/users').",
                    },
                    "query_params": {
                        "type": "object",
                        "description": "Query parameters as key-value pairs.",
                    },
                    "headers": {
                        "type": "object",
                        "description": "Request headers as key-value pairs.",
                    },
                    "body": {
                        "type": "string",
                        "description": "Request body content.",
                    },
                    "source_ip": {
                        "type": "string",
                        "description": "Source IP address of the request.",
                    },
                },
                "required": ["method", "path"],
            },
        ),
        Tool(
            name="get_sensor_config",
            description=(
                "Generate sensor configuration for framework integration. "
                "Creates code snippets for adding SecurityMiddleware to "
                "FastAPI or Flask applications."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "description": ("Target framework (fastapi, flask). Defaults to fastapi."),
                    },
                    "block_on_detection": {
                        "type": "boolean",
                        "description": ("Whether to block malicious requests. Defaults to true."),
                    },
                    "watch_paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific paths to monitor.",
                    },
                    "api_key": {
                        "type": "string",
                        "description": "Dashboard API key for alerting.",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="init_project",
            description=(
                "Initialize security-use for a project with zero configuration. "
                "Auto-detects the framework (FastAPI, Flask, Django) and sets up "
                "runtime middleware, pre-commit hooks, and configuration files. "
                "The easiest way to add security scanning to any Python project."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": (
                            "Path to the project directory. Defaults to current working directory."
                        ),
                    },
                    "inject_middleware": {
                        "type": "boolean",
                        "description": (
                            "Whether to inject SecurityMiddleware into the app. Defaults to true."
                        ),
                    },
                    "setup_precommit": {
                        "type": "boolean",
                        "description": ("Whether to set up pre-commit hooks. Defaults to true."),
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": (
                            "If true, preview changes without modifying files. Defaults to false."
                        ),
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="detect_project",
            description=(
                "Detect project framework and configuration without making changes. "
                "Analyzes a project to identify web framework, dependency files, "
                "IaC files, and existing security configuration. "
                "Useful for understanding a project before initializing."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": (
                            "Path to the project directory. Defaults to current working directory."
                        ),
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
        "get_security_alerts": handle_get_security_alerts,
        "get_alert_details": handle_get_alert_details,
        "acknowledge_alert": handle_acknowledge_alert,
        "block_ip": handle_block_ip,
        "get_blocked_ips": handle_get_blocked_ips,
        "configure_sensor": handle_configure_sensor,
        "generate_sbom": handle_generate_sbom,
        "check_compliance": handle_check_compliance,
        "detect_vulnerable_endpoints": handle_detect_vulnerable_endpoints,
        "analyze_request": handle_analyze_request,
        "get_sensor_config": handle_get_sensor_config,
        "init_project": handle_init_project,
        "detect_project": handle_detect_project,
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
