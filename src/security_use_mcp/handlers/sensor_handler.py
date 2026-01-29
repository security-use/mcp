"""Handler for runtime security sensor tools."""

import asyncio
from typing import Any

from mcp.types import TextContent


async def handle_get_security_alerts(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Retrieve recent security alerts from the runtime sensor.

    Args:
        arguments: Tool arguments containing:
            - time_range (optional): Time range to query (e.g., "1h", "24h", "7d")
            - severity (optional): Filter by severity level
            - attack_type (optional): Filter by attack type

    Returns:
        List of TextContent with formatted alert list
    """
    time_range = arguments.get("time_range", "24h")
    severity = arguments.get("severity")
    attack_type = arguments.get("attack_type")

    try:
        from security_use.sensor import SensorClient

        client = SensorClient()
        alerts = await asyncio.to_thread(
            client.get_alerts,
            time_range=time_range,
            severity=severity,
            attack_type=attack_type,
        )

        if not alerts:
            return [
                TextContent(
                    type="text",
                    text=(
                        "## Security Alerts\n\n"
                        f"**Time Range**: {time_range}\n"
                        "**Status**: No alerts found\n\n"
                        "No security alerts detected in the specified time range."
                    ),
                )
            ]

        output_lines = [
            "## Security Alerts",
            "",
            f"**Time Range**: {time_range}",
            f"**Total Alerts**: {len(alerts)}",
            "",
            "---",
            "",
        ]

        for alert in alerts:
            output_lines.extend(
                [
                    f"### Alert: {alert.id}",
                    f"- **Timestamp**: {alert.timestamp}",
                    f"- **Severity**: {alert.severity}",
                    f"- **Type**: {alert.attack_type}",
                    f"- **Source IP**: {alert.source_ip}",
                    f"- **Status**: {alert.status}",
                    f"- **Summary**: {alert.summary}",
                    "",
                ]
            )

        output_lines.extend(
            [
                "---",
                "",
                "Use `get_alert_details(alert_id)` to view full details of an alert.",
            ]
        )

        return [TextContent(type="text", text="\n".join(output_lines))]

    except ImportError:
        return [
            TextContent(
                type="text",
                text=(
                    "Error: security-use sensor module not available.\n\n"
                    "Please ensure the sensor module is installed and configured."
                ),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error retrieving alerts: {str(e)}")]


async def handle_get_alert_details(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Get full details of a specific security alert.

    Args:
        arguments: Tool arguments containing:
            - alert_id (required): ID of the alert to retrieve

    Returns:
        List of TextContent with full alert details
    """
    alert_id = arguments.get("alert_id")

    if not alert_id:
        return [TextContent(type="text", text="Error: `alert_id` is required")]

    try:
        from security_use.sensor import SensorClient

        client = SensorClient()
        alert = await asyncio.to_thread(client.get_alert_details, alert_id=alert_id)

        if not alert:
            return [
                TextContent(type="text", text=f"Error: Alert not found: {alert_id}")
            ]

        output_lines = [
            "## Alert Details",
            "",
            f"**Alert ID**: {alert.id}",
            f"**Timestamp**: {alert.timestamp}",
            f"**Severity**: {alert.severity}",
            f"**Status**: {alert.status}",
            "",
            "### Attack Information",
            "",
            f"- **Type**: {alert.attack_type}",
            f"- **Source IP**: {alert.source_ip}",
            f"- **Target**: {alert.target}",
            f"- **Method**: {alert.method}",
            "",
            "### Matched Patterns",
            "",
        ]

        for pattern in alert.matched_patterns or []:
            output_lines.append(f"- {pattern}")

        output_lines.extend(
            [
                "",
                "### Full Payload",
                "",
                "```",
                alert.payload or "N/A",
                "```",
                "",
                "### Recommended Actions",
                "",
                "- Use `acknowledge_alert` to mark as reviewed",
                "- Use `block_ip` to block the source IP",
            ]
        )

        return [TextContent(type="text", text="\n".join(output_lines))]

    except ImportError:
        return [
            TextContent(
                type="text",
                text=(
                    "Error: security-use sensor module not available.\n\n"
                    "Please ensure the sensor module is installed and configured."
                ),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error retrieving alert details: {str(e)}")]


async def handle_acknowledge_alert(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Mark a security alert as reviewed/acknowledged.

    Args:
        arguments: Tool arguments containing:
            - alert_id (required): ID of the alert to acknowledge
            - notes (optional): Notes about the acknowledgment

    Returns:
        List of TextContent with acknowledgment confirmation
    """
    alert_id = arguments.get("alert_id")
    notes = arguments.get("notes", "")

    if not alert_id:
        return [TextContent(type="text", text="Error: `alert_id` is required")]

    try:
        from security_use.sensor import SensorClient

        client = SensorClient()
        result = await asyncio.to_thread(
            client.acknowledge_alert, alert_id=alert_id, notes=notes
        )

        if not result.success:
            return [
                TextContent(
                    type="text",
                    text=f"Error acknowledging alert: {result.error}",
                )
            ]

        output_lines = [
            "## Alert Acknowledged",
            "",
            f"**Alert ID**: {alert_id}",
            f"**Status**: Acknowledged",
        ]

        if notes:
            output_lines.extend(["", f"**Notes**: {notes}"])

        output_lines.extend(
            [
                "",
                "The alert has been marked as reviewed. "
                "It will no longer appear in active alerts."
            ]
        )

        return [TextContent(type="text", text="\n".join(output_lines))]

    except ImportError:
        return [
            TextContent(
                type="text",
                text=(
                    "Error: security-use sensor module not available.\n\n"
                    "Please ensure the sensor module is installed and configured."
                ),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error acknowledging alert: {str(e)}")]


async def handle_block_ip(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Block a source IP address.

    Args:
        arguments: Tool arguments containing:
            - ip_address (required): IP address to block
            - duration (optional): Block duration (e.g., "1h", "24h", "permanent")

    Returns:
        List of TextContent with block confirmation
    """
    ip_address = arguments.get("ip_address")
    duration = arguments.get("duration", "24h")

    if not ip_address:
        return [TextContent(type="text", text="Error: `ip_address` is required")]

    try:
        from security_use.sensor import SensorClient

        client = SensorClient()
        result = await asyncio.to_thread(
            client.block_ip, ip_address=ip_address, duration=duration
        )

        if not result.success:
            return [
                TextContent(
                    type="text",
                    text=f"Error blocking IP: {result.error}",
                )
            ]

        output_lines = [
            "## IP Address Blocked",
            "",
            f"**IP Address**: {ip_address}",
            f"**Duration**: {duration}",
            f"**Block ID**: {result.block_id}",
            "",
            "The IP address has been added to the block list. "
            "All traffic from this IP will be blocked.",
            "",
            "Use `get_blocked_ips` to view all blocked IPs.",
        ]

        return [TextContent(type="text", text="\n".join(output_lines))]

    except ImportError:
        return [
            TextContent(
                type="text",
                text=(
                    "Error: security-use sensor module not available.\n\n"
                    "Please ensure the sensor module is installed and configured."
                ),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error blocking IP: {str(e)}")]


async def handle_get_blocked_ips(arguments: dict[str, Any]) -> list[TextContent]:
    """
    List all currently blocked IP addresses.

    Args:
        arguments: Tool arguments (none required)

    Returns:
        List of TextContent with blocked IP list
    """
    try:
        from security_use.sensor import SensorClient

        client = SensorClient()
        blocked_ips = await asyncio.to_thread(client.get_blocked_ips)

        if not blocked_ips:
            return [
                TextContent(
                    type="text",
                    text=(
                        "## Blocked IP Addresses\n\n"
                        "**Status**: No IPs currently blocked\n\n"
                        "Use `block_ip` to block an IP address."
                    ),
                )
            ]

        output_lines = [
            "## Blocked IP Addresses",
            "",
            f"**Total Blocked**: {len(blocked_ips)}",
            "",
            "| IP Address | Duration | Blocked At | Expires |",
            "|------------|----------|------------|---------|",
        ]

        for ip in blocked_ips:
            output_lines.append(
                f"| {ip.ip_address} | {ip.duration} | {ip.blocked_at} | {ip.expires_at} |"
            )

        output_lines.extend(
            [
                "",
                "Use `configure_sensor` to manage block list settings.",
            ]
        )

        return [TextContent(type="text", text="\n".join(output_lines))]

    except ImportError:
        return [
            TextContent(
                type="text",
                text=(
                    "Error: security-use sensor module not available.\n\n"
                    "Please ensure the sensor module is installed and configured."
                ),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error retrieving blocked IPs: {str(e)}")]


async def handle_configure_sensor(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Update sensor configuration.

    Args:
        arguments: Tool arguments containing:
            - sensitivity (optional): Detection sensitivity (low, medium, high)
            - patterns (optional): Custom detection patterns to add
            - rate_limits (optional): Rate limiting configuration

    Returns:
        List of TextContent with configuration update confirmation
    """
    sensitivity = arguments.get("sensitivity")
    patterns = arguments.get("patterns")
    rate_limits = arguments.get("rate_limits")

    if not any([sensitivity, patterns, rate_limits]):
        return [
            TextContent(
                type="text",
                text=(
                    "Error: At least one configuration parameter is required.\n\n"
                    "Available parameters:\n"
                    "- `sensitivity`: Detection sensitivity (low, medium, high)\n"
                    "- `patterns`: Custom detection patterns\n"
                    "- `rate_limits`: Rate limiting configuration"
                ),
            )
        ]

    try:
        from security_use.sensor import SensorClient

        client = SensorClient()
        result = await asyncio.to_thread(
            client.configure,
            sensitivity=sensitivity,
            patterns=patterns,
            rate_limits=rate_limits,
        )

        if not result.success:
            return [
                TextContent(
                    type="text",
                    text=f"Error updating configuration: {result.error}",
                )
            ]

        output_lines = [
            "## Sensor Configuration Updated",
            "",
        ]

        if sensitivity:
            output_lines.append(f"**Sensitivity**: {sensitivity}")
        if patterns:
            output_lines.append(f"**Patterns Added**: {len(patterns)}")
        if rate_limits:
            output_lines.append(f"**Rate Limits Updated**: Yes")

        output_lines.extend(
            [
                "",
                "The sensor configuration has been updated. "
                "Changes will take effect immediately.",
            ]
        )

        return [TextContent(type="text", text="\n".join(output_lines))]

    except ImportError:
        return [
            TextContent(
                type="text",
                text=(
                    "Error: security-use sensor module not available.\n\n"
                    "Please ensure the sensor module is installed and configured."
                ),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error configuring sensor: {str(e)}")]
