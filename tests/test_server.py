"""Tests for the MCP server."""

import pytest
from security_use_mcp.server import server, list_tools


@pytest.mark.asyncio
async def test_list_tools():
    """Test that all tools are listed."""
    tools = await list_tools()
    tool_names = [tool.name for tool in tools]

    assert "scan_dependencies" in tool_names
    assert "scan_iac" in tool_names
    assert "fix_vulnerability" in tool_names
    assert "fix_iac" in tool_names


@pytest.mark.asyncio
async def test_scan_dependencies_tool_schema():
    """Test scan_dependencies tool has correct schema."""
    tools = await list_tools()
    scan_deps = next(t for t in tools if t.name == "scan_dependencies")

    assert scan_deps.inputSchema["type"] == "object"
    assert "path" in scan_deps.inputSchema["properties"]
    assert scan_deps.inputSchema["required"] == []


@pytest.mark.asyncio
async def test_scan_iac_tool_schema():
    """Test scan_iac tool has correct schema."""
    tools = await list_tools()
    scan_iac = next(t for t in tools if t.name == "scan_iac")

    assert scan_iac.inputSchema["type"] == "object"
    assert "path" in scan_iac.inputSchema["properties"]


@pytest.mark.asyncio
async def test_fix_vulnerability_tool_schema():
    """Test fix_vulnerability tool has correct schema."""
    tools = await list_tools()
    fix_vuln = next(t for t in tools if t.name == "fix_vulnerability")

    assert fix_vuln.inputSchema["type"] == "object"
    assert "package_name" in fix_vuln.inputSchema["properties"]
    assert "package_name" in fix_vuln.inputSchema["required"]


@pytest.mark.asyncio
async def test_fix_iac_tool_schema():
    """Test fix_iac tool has correct schema."""
    tools = await list_tools()
    fix_iac = next(t for t in tools if t.name == "fix_iac")

    assert fix_iac.inputSchema["type"] == "object"
    assert "file_path" in fix_iac.inputSchema["properties"]
    assert "rule_id" in fix_iac.inputSchema["properties"]
    assert "file_path" in fix_iac.inputSchema["required"]
    assert "rule_id" in fix_iac.inputSchema["required"]
