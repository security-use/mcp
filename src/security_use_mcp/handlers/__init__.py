"""Tool handlers for the MCP server."""

from .dependency_handler import handle_fix_vulnerability, handle_scan_dependencies
from .iac_handler import handle_fix_iac, handle_scan_iac

__all__ = [
    "handle_scan_dependencies",
    "handle_fix_vulnerability",
    "handle_scan_iac",
    "handle_fix_iac",
]
