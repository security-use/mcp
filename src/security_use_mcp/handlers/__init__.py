"""Tool handlers for the MCP server."""

from .compliance_handler import handle_check_compliance
from .dependency_handler import handle_fix_vulnerability, handle_scan_dependencies
from .github_handler import handle_create_fix_pr
from .iac_handler import handle_fix_iac, handle_scan_iac
from .init_handler import handle_detect_project, handle_init_project
from .sbom_handler import handle_generate_sbom
from .sensor_handler import (
    handle_acknowledge_alert,
    handle_analyze_request,
    handle_block_ip,
    handle_configure_sensor,
    handle_detect_vulnerable_endpoints,
    handle_get_alert_details,
    handle_get_blocked_ips,
    handle_get_security_alerts,
    handle_get_sensor_config,
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
    "handle_generate_sbom",
    "handle_check_compliance",
    "handle_detect_vulnerable_endpoints",
    "handle_analyze_request",
    "handle_get_sensor_config",
    "handle_init_project",
    "handle_detect_project",
]
