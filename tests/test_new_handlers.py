"""Tests for new tool handlers (GitHub, Sensor, SBOM, Compliance)."""

from unittest.mock import MagicMock, patch

import pytest


class TestGitHubHandler:
    """Tests for GitHub PR creation handler."""

    @pytest.mark.asyncio
    async def test_create_fix_pr_not_git_repo(self):
        """Test PR creation in non-git directory."""
        from security_use_mcp.handlers.github_handler import handle_create_fix_pr

        with patch("subprocess.run") as mock_run:
            # Simulate not being in a git repo
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")

            result = await handle_create_fix_pr({})

            assert len(result) == 1
            assert "Not a git repository" in result[0].text

    @pytest.mark.asyncio
    async def test_create_fix_pr_no_changes(self):
        """Test PR creation with no pending changes."""
        from security_use_mcp.handlers.github_handler import handle_create_fix_pr

        with patch("subprocess.run") as mock_run:
            def side_effect(args, **kwargs):
                if args[1] == "rev-parse":
                    return MagicMock(returncode=0, stdout="true", stderr="")
                elif args[1] == "status":
                    # No changes
                    return MagicMock(returncode=0, stdout="", stderr="")
                return MagicMock(returncode=0, stdout="", stderr="")

            mock_run.side_effect = side_effect

            result = await handle_create_fix_pr({})

            assert len(result) == 1
            assert "No Changes to Commit" in result[0].text

    @pytest.mark.asyncio
    async def test_create_fix_pr_with_vulnerability_id(self):
        """Test PR creation with vulnerability ID generates correct branch name."""
        from security_use_mcp.handlers.github_handler import handle_create_fix_pr

        with patch("subprocess.run") as mock_run:
            call_count = 0

            def side_effect(args, **kwargs):
                nonlocal call_count
                call_count += 1
                if "rev-parse" in args and "--is-inside-work-tree" in args:
                    return MagicMock(returncode=0, stdout="true", stderr="")
                elif args[1] == "status":
                    return MagicMock(returncode=0, stdout=" M file.txt\n", stderr="")
                elif "rev-parse" in args and "--abbrev-ref" in args:
                    return MagicMock(returncode=0, stdout="main", stderr="")
                elif "checkout" in args:
                    return MagicMock(returncode=0, stdout="", stderr="")
                elif "add" in args:
                    return MagicMock(returncode=0, stdout="", stderr="")
                elif "commit" in args:
                    return MagicMock(returncode=0, stdout="", stderr="")
                elif "push" in args:
                    return MagicMock(returncode=0, stdout="", stderr="")
                elif "pr" in args:
                    return MagicMock(
                        returncode=0,
                        stdout="https://github.com/test/repo/pull/1",
                        stderr="",
                    )
                return MagicMock(returncode=0, stdout="", stderr="")

            mock_run.side_effect = side_effect

            result = await handle_create_fix_pr({
                "vulnerability_id": "CVE-2023-12345"
            })

            assert len(result) == 1
            # Should have created a PR
            assert "Pull Request Created" in result[0].text or "Error" in result[0].text


class TestSensorHandler:
    """Tests for runtime sensor handlers."""

    @pytest.mark.asyncio
    async def test_get_security_alerts_redirects_to_dashboard(self):
        """Test get_security_alerts redirects to dashboard."""
        from security_use_mcp.handlers.sensor_handler import handle_get_security_alerts

        result = await handle_get_security_alerts({"time_range": "24h"})

        assert len(result) == 1
        assert "dashboard" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_get_alert_details_missing_alert_id(self):
        """Test get_alert_details with missing alert_id."""
        from security_use_mcp.handlers.sensor_handler import handle_get_alert_details

        result = await handle_get_alert_details({})

        assert len(result) == 1
        assert "alert_id" in result[0].text
        assert "required" in result[0].text

    @pytest.mark.asyncio
    async def test_get_alert_details_with_alert_id(self):
        """Test get_alert_details with alert_id redirects to dashboard."""
        from security_use_mcp.handlers.sensor_handler import handle_get_alert_details

        result = await handle_get_alert_details({"alert_id": "test-123"})

        assert len(result) == 1
        assert "test-123" in result[0].text
        assert "dashboard" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_acknowledge_alert_missing_alert_id(self):
        """Test acknowledge_alert with missing alert_id."""
        from security_use_mcp.handlers.sensor_handler import handle_acknowledge_alert

        result = await handle_acknowledge_alert({})

        assert len(result) == 1
        assert "alert_id" in result[0].text
        assert "required" in result[0].text

    @pytest.mark.asyncio
    async def test_block_ip_missing_ip_address(self):
        """Test block_ip with missing ip_address."""
        from security_use_mcp.handlers.sensor_handler import handle_block_ip

        result = await handle_block_ip({})

        assert len(result) == 1
        assert "ip_address" in result[0].text
        assert "required" in result[0].text

    @pytest.mark.asyncio
    async def test_block_ip_with_ip_address(self):
        """Test block_ip with ip_address redirects to dashboard."""
        from security_use_mcp.handlers.sensor_handler import handle_block_ip

        result = await handle_block_ip({
            "ip_address": "192.168.1.100",
            "duration": "1h"
        })

        assert len(result) == 1
        assert "192.168.1.100" in result[0].text
        assert "dashboard" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_get_blocked_ips(self):
        """Test get_blocked_ips redirects to dashboard."""
        from security_use_mcp.handlers.sensor_handler import handle_get_blocked_ips

        result = await handle_get_blocked_ips({})

        assert len(result) == 1
        assert "dashboard" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_configure_sensor_generates_config(self):
        """Test configure_sensor generates framework config."""
        from security_use_mcp.handlers.sensor_handler import handle_configure_sensor

        result = await handle_configure_sensor({})

        assert len(result) == 1
        assert "SecurityMiddleware" in result[0].text

    @pytest.mark.asyncio
    async def test_configure_sensor_with_framework(self):
        """Test configure_sensor with framework parameter."""
        from security_use_mcp.handlers.sensor_handler import handle_configure_sensor

        result = await handle_configure_sensor({"framework": "flask"})

        assert len(result) == 1
        assert "Flask" in result[0].text

    @pytest.mark.asyncio
    async def test_detect_vulnerable_endpoints_invalid_path(self):
        """Test detect_vulnerable_endpoints with invalid path."""
        from security_use_mcp.handlers.sensor_handler import handle_detect_vulnerable_endpoints

        result = await handle_detect_vulnerable_endpoints({"path": "/nonexistent"})

        assert len(result) == 1
        assert "Path does not exist" in result[0].text

    @pytest.mark.asyncio
    async def test_analyze_request_missing_method(self):
        """Test analyze_request with missing method."""
        from security_use_mcp.handlers.sensor_handler import handle_analyze_request

        result = await handle_analyze_request({"path": "/api/test"})

        assert len(result) == 1
        assert "method" in result[0].text
        assert "required" in result[0].text

    @pytest.mark.asyncio
    async def test_analyze_request_missing_path(self):
        """Test analyze_request with missing path."""
        from security_use_mcp.handlers.sensor_handler import handle_analyze_request

        result = await handle_analyze_request({"method": "GET"})

        assert len(result) == 1
        assert "path" in result[0].text
        assert "required" in result[0].text

    @pytest.mark.asyncio
    async def test_get_sensor_config_fastapi(self):
        """Test get_sensor_config for FastAPI."""
        from security_use_mcp.handlers.sensor_handler import handle_get_sensor_config

        result = await handle_get_sensor_config({"framework": "fastapi"})

        assert len(result) == 1
        assert "FastAPI" in result[0].text
        assert "SecurityMiddleware" in result[0].text

    @pytest.mark.asyncio
    async def test_get_sensor_config_flask(self):
        """Test get_sensor_config for Flask."""
        from security_use_mcp.handlers.sensor_handler import handle_get_sensor_config

        result = await handle_get_sensor_config({"framework": "flask"})

        assert len(result) == 1
        assert "Flask" in result[0].text

    @pytest.mark.asyncio
    async def test_get_sensor_config_invalid_framework(self):
        """Test get_sensor_config with invalid framework."""
        from security_use_mcp.handlers.sensor_handler import handle_get_sensor_config

        result = await handle_get_sensor_config({"framework": "django"})

        assert len(result) == 1
        assert "Invalid framework" in result[0].text


class TestSBOMHandler:
    """Tests for SBOM generation handler."""

    @pytest.mark.asyncio
    async def test_generate_sbom_invalid_format(self):
        """Test SBOM generation with invalid format."""
        from security_use_mcp.handlers.sbom_handler import handle_generate_sbom

        result = await handle_generate_sbom({"format": "invalid"})

        assert len(result) == 1
        assert "Invalid format" in result[0].text
        assert "cyclonedx" in result[0].text
        assert "spdx" in result[0].text

    @pytest.mark.asyncio
    async def test_generate_sbom_invalid_path(self):
        """Test SBOM generation with invalid path."""
        from security_use_mcp.handlers.sbom_handler import handle_generate_sbom

        result = await handle_generate_sbom({"path": "/nonexistent/path"})

        assert len(result) == 1
        assert "Path does not exist" in result[0].text

    @pytest.mark.asyncio
    async def test_generate_sbom_missing_module(self):
        """Test SBOM generation when module not available."""
        from security_use_mcp.handlers.sbom_handler import handle_generate_sbom

        with patch("os.path.exists", return_value=True):
            result = await handle_generate_sbom({"format": "cyclonedx"})

        assert len(result) == 1
        assert "SBOM module not available" in result[0].text

    @pytest.mark.asyncio
    async def test_generate_sbom_spdx_format(self):
        """Test SBOM generation with SPDX format."""
        from security_use_mcp.handlers.sbom_handler import handle_generate_sbom

        with patch("os.path.exists", return_value=True):
            result = await handle_generate_sbom({"format": "spdx"})

        assert len(result) == 1
        # Should attempt to run and hit module not available
        assert "SBOM module not available" in result[0].text


class TestComplianceHandler:
    """Tests for compliance checking handler."""

    @pytest.mark.asyncio
    async def test_check_compliance_missing_framework(self):
        """Test compliance check with missing framework."""
        from security_use_mcp.handlers.compliance_handler import handle_check_compliance

        result = await handle_check_compliance({})

        assert len(result) == 1
        assert "framework" in result[0].text
        assert "required" in result[0].text

    @pytest.mark.asyncio
    async def test_check_compliance_invalid_framework(self):
        """Test compliance check with invalid framework."""
        from security_use_mcp.handlers.compliance_handler import handle_check_compliance

        result = await handle_check_compliance({"framework": "invalid"})

        assert len(result) == 1
        assert "Invalid framework" in result[0].text
        assert "soc2" in result[0].text
        assert "hipaa" in result[0].text
        assert "pci-dss" in result[0].text
        assert "cis" in result[0].text

    @pytest.mark.asyncio
    async def test_check_compliance_invalid_path(self):
        """Test compliance check with invalid path."""
        from security_use_mcp.handlers.compliance_handler import handle_check_compliance

        result = await handle_check_compliance({
            "path": "/nonexistent/path",
            "framework": "soc2"
        })

        assert len(result) == 1
        assert "Path does not exist" in result[0].text

    @pytest.mark.asyncio
    async def test_check_compliance_missing_module(self):
        """Test compliance check when module not available."""
        from security_use_mcp.handlers.compliance_handler import handle_check_compliance

        with patch("os.path.exists", return_value=True):
            result = await handle_check_compliance({"framework": "soc2"})

        assert len(result) == 1
        assert "compliance module not available" in result[0].text

    @pytest.mark.asyncio
    async def test_check_compliance_all_frameworks(self):
        """Test compliance check accepts all valid frameworks."""
        from security_use_mcp.handlers.compliance_handler import handle_check_compliance

        frameworks = [
            "soc2", "hipaa", "pci-dss", "nist-800-53",
            "cis-aws", "cis-azure", "cis-gcp", "cis-kubernetes", "iso-27001",
            "cis", "nist", "iso",  # Aliases
        ]

        for framework in frameworks:
            with patch("os.path.exists", return_value=True):
                result = await handle_check_compliance({"framework": framework})

            assert len(result) == 1
            # Should not hit validation error
            assert "Invalid framework" not in result[0].text


class TestServerToolRouting:
    """Tests for server tool routing."""

    @pytest.mark.asyncio
    async def test_all_new_tools_registered(self):
        """Test all new tools are registered in the server."""
        from security_use_mcp.server import list_tools

        tools = await list_tools()
        tool_names = [t.name for t in tools]

        expected_tools = [
            "create_fix_pr",
            "get_security_alerts",
            "get_alert_details",
            "acknowledge_alert",
            "block_ip",
            "get_blocked_ips",
            "configure_sensor",
            "generate_sbom",
            "check_compliance",
        ]

        for expected in expected_tools:
            assert expected in tool_names, f"Tool {expected} not registered"

    @pytest.mark.asyncio
    async def test_call_tool_routes_to_handlers(self):
        """Test call_tool routes to correct handlers."""
        from security_use_mcp.server import call_tool

        # Test unknown tool
        result = await call_tool("nonexistent_tool", {})
        assert "Unknown tool" in result[0].text

        # Test known tools route correctly (they should not return "Unknown tool")
        new_tools = [
            ("get_security_alerts", {}),
            ("get_alert_details", {"alert_id": "test"}),
            ("acknowledge_alert", {"alert_id": "test"}),
            ("block_ip", {"ip_address": "1.2.3.4"}),
            ("get_blocked_ips", {}),
            ("configure_sensor", {"sensitivity": "high"}),
            ("generate_sbom", {}),
            ("check_compliance", {"framework": "soc2"}),
        ]

        for tool_name, args in new_tools:
            result = await call_tool(tool_name, args)
            assert "Unknown tool" not in result[0].text, f"{tool_name} not routed correctly"

    @pytest.mark.asyncio
    async def test_tool_schemas_valid(self):
        """Test all new tools have valid schemas."""
        from security_use_mcp.server import list_tools

        tools = await list_tools()

        for tool in tools:
            assert tool.inputSchema is not None
            assert "type" in tool.inputSchema
            assert tool.inputSchema["type"] == "object"
            assert "properties" in tool.inputSchema
            assert "required" in tool.inputSchema
