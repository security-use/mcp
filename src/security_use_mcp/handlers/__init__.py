"""Tool handlers for the MCP server."""

from .dependency_handler import handle_fix_vulnerability, handle_scan_dependencies
from .github_handler import handle_create_fix_pr
from .iac_handler import handle_fix_iac, handle_scan_iac
from .sensor_handler import (
    handle_acknowledge_alert,
    handle_block_ip,
    handle_configure_sensor,
    handle_get_alert_details,
    handle_get_blocked_ips,
    handle_get_security_alerts,
)

__all__ = [
    "handle_scan_dependencies",
    "handle_fix_vulnerability",
    "handle_scan_iac",
    "handle_fix_iac",
    "handle_create_fix_pr",
    "handle_get_security_alerts",
    "handle_get_alert_details",
    "handle_acknowledge_alert",
    "handle_block_ip",
    "handle_get_blocked_ips",
    "handle_configure_sensor",
]
