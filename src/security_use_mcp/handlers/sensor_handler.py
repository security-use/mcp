"""Handler for runtime security sensor tools."""

import asyncio
import os
from typing import Any

from mcp.types import TextContent


async def handle_detect_vulnerable_endpoints(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Detect vulnerable endpoints in a project.

    Analyzes the codebase to find API endpoints that use vulnerable packages
    or have high-risk code patterns.

    Args:
        arguments: Tool arguments containing:
            - path (optional): Path to the project directory
            - min_risk_score (optional): Minimum risk score threshold (0.0-1.0)

    Returns:
        List of TextContent with vulnerable endpoint analysis
    """
    path = arguments.get("path", os.getcwd())

    # Validate path exists
    if not os.path.exists(path):
        return [TextContent(type="text", text=f"Error: Path does not exist: {path}")]

    try:
        from security_use.sensor import VulnerableEndpointDetector

        detector = VulnerableEndpointDetector()
        result = await asyncio.to_thread(detector.analyze, path)

        output_lines = [
            "## Vulnerable Endpoint Analysis",
            "",
            f"**Project Path**: {path}",
            f"**Total Endpoints Found**: {len(result.all_endpoints)}",
            f"**Vulnerable Endpoints**: {len(result.vulnerable_endpoints)}",
            "",
        ]

        if result.vulnerable_packages:
            output_lines.extend(
                [
                    "### Vulnerable Packages in Use",
                    "",
                ]
            )
            for pkg, vulns in result.vulnerable_packages.items():
                output_lines.append(f"- **{pkg}**: {len(vulns)} vulnerabilities")
            output_lines.append("")

        if result.vulnerable_endpoints:
            output_lines.extend(
                [
                    "### High-Risk Endpoints",
                    "",
                ]
            )

            for endpoint in result.vulnerable_endpoints[:10]:
                risk_level = (
                    "CRITICAL"
                    if endpoint.risk_score >= 0.8
                    else "HIGH"
                    if endpoint.risk_score >= 0.6
                    else "MEDIUM"
                    if endpoint.risk_score >= 0.4
                    else "LOW"
                )
                output_lines.extend(
                    [
                        f"#### {endpoint.method} {endpoint.path}",
                        f"- **Risk Score**: {endpoint.risk_score:.2f} ({risk_level})",
                        f"- **Function**: `{endpoint.function_name}`",
                        f"- **File**: `{endpoint.file_path}:{endpoint.line_number}`",
                    ]
                )
                if endpoint.vulnerable_packages:
                    output_lines.append(
                        f"- **Vulnerable Imports**: {', '.join(endpoint.vulnerable_packages)}"
                    )
                output_lines.append("")

            if len(result.vulnerable_endpoints) > 10:
                output_lines.append(
                    f"*... and {len(result.vulnerable_endpoints) - 10} more vulnerable endpoints*"
                )
                output_lines.append("")

        if result.vulnerable_paths:
            output_lines.extend(
                [
                    "### Paths to Monitor",
                    "",
                    "These paths should be monitored with the runtime sensor:",
                    "",
                ]
            )
            for p in result.vulnerable_paths[:20]:
                output_lines.append(f"- `{p}`")

            if len(result.vulnerable_paths) > 20:
                output_lines.append(f"- ... and {len(result.vulnerable_paths) - 20} more")
            output_lines.append("")

        if not result.vulnerable_endpoints:
            output_lines.extend(
                [
                    "**Status**: No high-risk endpoints detected.",
                    "",
                    "The codebase appears to have no obviously vulnerable API endpoints.",
                ]
            )

        output_lines.extend(
            [
                "---",
                "",
                "### Next Steps",
                "",
                "1. Use `scan_dependencies` to get full vulnerability details",
                "2. Use `fix_vulnerability` to patch vulnerable packages",
                "3. Add runtime monitoring with the SecurityMiddleware",
            ]
        )

        return [TextContent(type="text", text="\n".join(output_lines))]

    except ImportError:
        return [
            TextContent(
                type="text",
                text=(
                    "Error: security-use sensor module not available.\n\n"
                    "Please ensure security-use is installed: pip install security-use"
                ),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error analyzing endpoints: {str(e)}")]


async def handle_analyze_request(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Analyze an HTTP request for potential attacks.

    Uses the AttackDetector to check for SQL injection, XSS, path traversal,
    command injection, and other attack patterns.

    Args:
        arguments: Tool arguments containing:
            - method (required): HTTP method (GET, POST, etc.)
            - path (required): Request path
            - query_params (optional): Query parameters dict
            - headers (optional): Request headers dict
            - body (optional): Request body string
            - source_ip (optional): Source IP address

    Returns:
        List of TextContent with attack analysis results
    """
    method = arguments.get("method")
    path = arguments.get("path")
    query_params = arguments.get("query_params", {})
    headers = arguments.get("headers", {})
    body = arguments.get("body")
    source_ip = arguments.get("source_ip", "unknown")

    if not method:
        return [TextContent(type="text", text="Error: `method` is required")]
    if not path:
        return [TextContent(type="text", text="Error: `path` is required")]

    try:
        from security_use.sensor import AttackDetector, RequestData

        detector = AttackDetector(
            enabled_detectors=[
                "sqli",
                "xss",
                "path_traversal",
                "command_injection",
                "suspicious_headers",
            ]
        )

        request = RequestData(
            method=method.upper(),
            path=path,
            query_params=query_params,
            headers=headers,
            body=body,
            source_ip=source_ip,
        )

        events = await asyncio.to_thread(detector.analyze_request, request)

        output_lines = [
            "## Request Security Analysis",
            "",
            f"**Method**: {method.upper()}",
            f"**Path**: {path}",
            f"**Source IP**: {source_ip}",
            "",
        ]

        if not events:
            output_lines.extend(
                [
                    "### Result: No Threats Detected",
                    "",
                    "The request does not contain any obvious attack patterns.",
                ]
            )
        else:
            output_lines.extend(
                [
                    f"### ⚠️ {len(events)} Potential Threat(s) Detected",
                    "",
                ]
            )

            for event in events:
                severity_icon = (
                    "🔴"
                    if event.severity == "CRITICAL"
                    else "🟠"
                    if event.severity == "HIGH"
                    else "🟡"
                    if event.severity == "MEDIUM"
                    else "🟢"
                )
                output_lines.extend(
                    [
                        f"#### {severity_icon} {event.event_type.value.upper()}",
                        f"- **Severity**: {event.severity}",
                        f"- **Confidence**: {event.confidence:.0%}",
                        f"- **Description**: {event.description}",
                        f"- **Location**: {event.matched_pattern.location}",
                    ]
                )
                if event.matched_pattern.field:
                    output_lines.append(f"- **Field**: {event.matched_pattern.field}")
                if event.matched_pattern.matched_value:
                    output_lines.append(
                        f"- **Matched Value**: `{event.matched_pattern.matched_value[:100]}`"
                    )
                output_lines.append("")

            output_lines.extend(
                [
                    "### Recommendations",
                    "",
                    "1. Block this request if in production",
                    "2. Log the source IP for monitoring",
                    "3. Consider rate limiting the source",
                    "4. Review application input validation",
                ]
            )

        return [TextContent(type="text", text="\n".join(output_lines))]

    except ImportError:
        return [
            TextContent(
                type="text",
                text=(
                    "Error: security-use sensor module not available.\n\n"
                    "Please ensure security-use is installed: pip install security-use"
                ),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error analyzing request: {str(e)}")]


async def handle_get_sensor_config(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Generate sensor configuration for framework integration.

    Creates configuration for integrating the SecurityMiddleware into
    FastAPI, Flask, or other Python web frameworks.

    Args:
        arguments: Tool arguments containing:
            - framework (optional): Target framework (fastapi, flask)
            - block_on_detection (optional): Block malicious requests
            - watch_paths (optional): Specific paths to monitor
            - api_key (optional): Dashboard API key

    Returns:
        List of TextContent with configuration code
    """
    framework = arguments.get("framework", "fastapi")
    block_on_detection = arguments.get("block_on_detection", True)
    watch_paths = arguments.get("watch_paths")
    api_key = arguments.get("api_key", "your-api-key")

    valid_frameworks = ["fastapi", "flask"]
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

    output_lines = [
        "## Runtime Sensor Configuration",
        "",
        f"**Framework**: {framework.capitalize()}",
        f"**Block on Detection**: {block_on_detection}",
        "",
    ]

    if framework.lower() == "fastapi":
        code = f'''from fastapi import FastAPI
from security_use.sensor import SecurityMiddleware

app = FastAPI()

app.add_middleware(
    SecurityMiddleware,
    api_key="{api_key}",
    block_on_detection={block_on_detection},
    auto_detect_vulnerable=True,
    enabled_detectors=["sqli", "xss", "path_traversal", "command_injection"],'''

        if watch_paths:
            code += f"""
    watch_paths={watch_paths},"""

        code += """
    excluded_paths=["/health", "/metrics"],
)

# Your routes here
@app.get("/")
async def root():
    return {"message": "Protected by SecurityUse"}"""

        output_lines.extend(
            [
                "### FastAPI Integration",
                "",
                "Add the following to your FastAPI application:",
                "",
                "```python",
                code,
                "```",
            ]
        )

    elif framework.lower() == "flask":
        code = f'''from flask import Flask
from security_use.sensor import FlaskSecurityMiddleware

app = Flask(__name__)

app.wsgi_app = FlaskSecurityMiddleware(
    app.wsgi_app,
    api_key="{api_key}",
    block_on_detection={block_on_detection},
)

# Your routes here
@app.route("/")
def root():
    return {{"message": "Protected by SecurityUse"}}'''

        output_lines.extend(
            [
                "### Flask Integration",
                "",
                "Add the following to your Flask application:",
                "",
                "```python",
                code,
                "```",
            ]
        )

    output_lines.extend(
        [
            "",
            "---",
            "",
            "### Environment Variables",
            "",
            "Set these environment variables for production:",
            "",
            "```bash",
            f"export SECURITY_USE_API_KEY={api_key}",
            "export SECURITY_USE_LOG_LEVEL=WARNING",
            "```",
            "",
            "### Features",
            "",
            "- **SQL Injection Detection**: Blocks SQLi attempts",
            "- **XSS Detection**: Blocks cross-site scripting",
            "- **Path Traversal Detection**: Blocks directory traversal",
            "- **Command Injection Detection**: Blocks shell injection",
            "- **Rate Limiting**: Prevents brute force attacks",
            "- **Dashboard Alerting**: Sends alerts to your dashboard",
        ]
    )

    return [TextContent(type="text", text="\n".join(output_lines))]


# Keep legacy handlers for backward compatibility
async def handle_get_security_alerts(arguments: dict[str, Any]) -> list[TextContent]:
    """Retrieve security alerts - requires dashboard integration."""
    return [
        TextContent(
            type="text",
            text=(
                "## Security Alerts\n\n"
                "This tool requires dashboard integration.\n\n"
                "To view security alerts:\n"
                "1. Configure the SecurityMiddleware with your API key\n"
                "2. Visit the SecurityUse dashboard at https://securityuse.dev\n"
                "3. View alerts in the web interface\n\n"
                "Use `get_sensor_config` to generate middleware configuration."
            ),
        )
    ]


async def handle_get_alert_details(arguments: dict[str, Any]) -> list[TextContent]:
    """Get alert details - requires dashboard integration."""
    alert_id = arguments.get("alert_id")
    if not alert_id:
        return [TextContent(type="text", text="Error: `alert_id` is required")]

    return [
        TextContent(
            type="text",
            text=(
                f"## Alert Details: {alert_id}\n\n"
                "Alert details are available in the SecurityUse dashboard.\n\n"
                "Visit https://securityuse.dev to view full alert details including:\n"
                "- Attack payload\n"
                "- Source IP information\n"
                "- Matched patterns\n"
                "- Request timeline"
            ),
        )
    ]


async def handle_acknowledge_alert(arguments: dict[str, Any]) -> list[TextContent]:
    """Acknowledge alert - requires dashboard integration."""
    alert_id = arguments.get("alert_id")
    if not alert_id:
        return [TextContent(type="text", text="Error: `alert_id` is required")]

    return [
        TextContent(
            type="text",
            text=(
                f"## Acknowledge Alert: {alert_id}\n\n"
                "Alert acknowledgment is available in the SecurityUse dashboard.\n\n"
                "Visit https://securityuse.dev to manage alerts."
            ),
        )
    ]


async def handle_block_ip(arguments: dict[str, Any]) -> list[TextContent]:
    """Block IP - requires dashboard integration."""
    ip_address = arguments.get("ip_address")
    if not ip_address:
        return [TextContent(type="text", text="Error: `ip_address` is required")]

    return [
        TextContent(
            type="text",
            text=(
                f"## Block IP: {ip_address}\n\n"
                "IP blocking is managed through the SecurityUse dashboard.\n\n"
                "Visit https://securityuse.dev to manage your block list."
            ),
        )
    ]


async def handle_get_blocked_ips(arguments: dict[str, Any]) -> list[TextContent]:
    """Get blocked IPs - requires dashboard integration."""
    return [
        TextContent(
            type="text",
            text=(
                "## Blocked IP Addresses\n\n"
                "The block list is managed through the SecurityUse dashboard.\n\n"
                "Visit https://securityuse.dev to view and manage blocked IPs."
            ),
        )
    ]


async def handle_configure_sensor(arguments: dict[str, Any]) -> list[TextContent]:
    """Configure sensor - delegates to get_sensor_config."""
    # Redirect to the new config handler
    return await handle_get_sensor_config(arguments)
