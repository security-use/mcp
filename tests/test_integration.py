"""Integration tests for the MCP server."""

from unittest.mock import MagicMock, patch

import pytest
from security_use.models import IaCFinding, ScanResult, Severity, Vulnerability

from security_use_mcp.handlers.dependency_handler import (
    handle_fix_vulnerability,
    handle_scan_dependencies,
)
from security_use_mcp.handlers.iac_handler import (
    handle_fix_iac,
    handle_scan_iac,
)
from security_use_mcp.models import FixResult


class TestDependencyScanningIntegration:
    """Integration tests for dependency scanning."""

    @pytest.mark.asyncio
    async def test_scan_nonexistent_path(self):
        """Test scanning a path that doesn't exist."""
        result = await handle_scan_dependencies({"path": "/nonexistent/path"})

        assert len(result) == 1
        assert "does not exist" in result[0].text

    @pytest.mark.asyncio
    async def test_scan_with_multiple_severities(self):
        """Test scanning with vulnerabilities of different severities."""
        mock_result = ScanResult(
            vulnerabilities=[
                Vulnerability(
                    id="CRITICAL-001",
                    package="pkg-critical",
                    installed_version="1.0.0",
                    severity=Severity.CRITICAL,
                    title="Critical vulnerability",
                    description="A critical issue",
                    affected_versions=">=1.0.0",
                ),
                Vulnerability(
                    id="HIGH-001",
                    package="pkg-high",
                    installed_version="1.0.0",
                    severity=Severity.HIGH,
                    title="High vulnerability",
                    description="A high issue",
                    affected_versions=">=1.0.0",
                ),
                Vulnerability(
                    id="LOW-001",
                    package="pkg-low",
                    installed_version="1.0.0",
                    severity=Severity.LOW,
                    title="Low vulnerability",
                    description="A low issue",
                    affected_versions=">=1.0.0",
                ),
            ],
            iac_findings=[],
            scanned_files=["requirements.txt"],
            errors=[],
        )

        with patch("os.path.exists", return_value=True):
            with patch("security_use_mcp.handlers.dependency_handler._scanner") as mock_scanner:
                mock_scanner.scan_path = MagicMock(return_value=mock_result)

                result = await handle_scan_dependencies({"path": "/test/path"})

                assert len(result) == 1
                text = result[0].text
                # Check all severities are present
                assert "CRITICAL" in text
                assert "HIGH" in text
                assert "LOW" in text
                # Check grouping order (CRITICAL before HIGH before LOW)
                crit_pos = text.find("CRITICAL")
                high_pos = text.find("HIGH")
                low_pos = text.find("LOW")
                assert crit_pos < high_pos < low_pos

    @pytest.mark.asyncio
    async def test_scan_with_scan_errors(self):
        """Test handling of scan errors."""
        mock_result = ScanResult(
            vulnerabilities=[],
            iac_findings=[],
            scanned_files=[],
            errors=["Failed to parse requirements.txt", "Network timeout"],
        )

        with patch("os.path.exists", return_value=True):
            with patch("security_use_mcp.handlers.dependency_handler._scanner") as mock_scanner:
                mock_scanner.scan_path = MagicMock(return_value=mock_result)

                result = await handle_scan_dependencies({"path": "/test/path"})

                assert len(result) == 1
                assert "error" in result[0].text.lower()


class TestIaCScanningIntegration:
    """Integration tests for IaC scanning."""

    @pytest.mark.asyncio
    async def test_scan_with_multiple_findings(self):
        """Test scanning with multiple IaC findings."""
        mock_result = ScanResult(
            vulnerabilities=[],
            iac_findings=[
                IaCFinding(
                    rule_id="S3_PUBLIC_ACCESS",
                    title="S3 bucket is publicly accessible",
                    file_path="s3.tf",
                    line_number=10,
                    severity=Severity.CRITICAL,
                    description="S3 bucket allows public read access",
                    remediation="Set acl to 'private'",
                    resource_name="my-bucket",
                    resource_type="aws_s3_bucket",
                ),
                IaCFinding(
                    rule_id="SG_OPEN_INGRESS",
                    title="Security group allows unrestricted ingress",
                    file_path="sg.tf",
                    line_number=25,
                    severity=Severity.HIGH,
                    description="Security group allows 0.0.0.0/0",
                    remediation="Restrict CIDR blocks",
                    resource_name="my-sg",
                    resource_type="aws_security_group",
                ),
            ],
            scanned_files=["s3.tf", "sg.tf"],
            errors=[],
        )

        with patch("os.path.exists", return_value=True):
            with patch("security_use_mcp.handlers.iac_handler._scanner") as mock_scanner:
                mock_scanner.scan_path = MagicMock(return_value=mock_result)

                result = await handle_scan_iac({"path": "/test/path"})

                assert len(result) == 1
                text = result[0].text
                assert "S3_PUBLIC_ACCESS" in text
                assert "SG_OPEN_INGRESS" in text
                assert "s3.tf:10" in text
                assert "sg.tf:25" in text

    @pytest.mark.asyncio
    async def test_scan_with_fix_code_suggestions(self):
        """Test IaC findings that include fix code suggestions."""
        mock_result = ScanResult(
            vulnerabilities=[],
            iac_findings=[
                IaCFinding(
                    rule_id="S3_PUBLIC_ACCESS",
                    title="S3 bucket is publicly accessible",
                    file_path="s3.tf",
                    line_number=10,
                    severity=Severity.CRITICAL,
                    description="S3 bucket allows public read access",
                    remediation="Set acl to 'private'",
                    resource_name="my-bucket",
                    resource_type="aws_s3_bucket",
                    fix_code='acl = "private"',
                ),
            ],
            scanned_files=["s3.tf"],
            errors=[],
        )

        with patch("os.path.exists", return_value=True):
            with patch("security_use_mcp.handlers.iac_handler._scanner") as mock_scanner:
                mock_scanner.scan_path = MagicMock(return_value=mock_result)

                result = await handle_scan_iac({"path": "/test/path"})

                assert len(result) == 1
                text = result[0].text
                assert "Suggested fix" in text
                assert "private" in text


class TestFixerIntegration:
    """Integration tests for fixers."""

    @pytest.mark.asyncio
    async def test_fix_vulnerability_failure(self):
        """Test handling of fix failures."""
        mock_result = FixResult(
            success=False,
            error="Package not found in any dependency file",
        )

        with patch("os.path.exists", return_value=True):
            with patch("security_use.fixers.dependency_fixer.DependencyFixer") as mock_fixer_cls:
                mock_fixer_instance = MagicMock()
                mock_fixer_instance.fix = MagicMock(return_value=mock_result)
                mock_fixer_cls.return_value = mock_fixer_instance

                result = await handle_fix_vulnerability(
                    {
                        "package_name": "nonexistent-pkg",
                        "path": "/test/path",
                    }
                )

                assert len(result) == 1
                assert "Failed" in result[0].text
                assert "not found" in result[0].text

    @pytest.mark.asyncio
    async def test_fix_iac_failure(self):
        """Test handling of IaC fix failures."""
        mock_result = FixResult(
            success=False,
            error="No fix available for this rule",
        )

        with patch("os.path.exists", return_value=True):
            with patch("security_use.fixers.iac_fixer.IaCFixer") as mock_fixer_cls:
                mock_fixer_instance = MagicMock()
                mock_fixer_instance.fix = MagicMock(return_value=mock_result)
                mock_fixer_cls.return_value = mock_fixer_instance

                result = await handle_fix_iac(
                    {
                        "file_path": "s3.tf",
                        "rule_id": "UNKNOWN_RULE",
                    }
                )

                assert len(result) == 1
                assert "Failed" in result[0].text


class TestEdgeCases:
    """Edge case tests."""

    @pytest.mark.asyncio
    async def test_scan_with_empty_path(self):
        """Test scanning with empty path defaults to cwd."""
        mock_result = ScanResult(
            vulnerabilities=[],
            iac_findings=[],
            scanned_files=[],
            errors=[],
        )

        with patch("os.path.exists", return_value=True):
            with patch("security_use_mcp.handlers.dependency_handler._scanner") as mock_scanner:
                mock_scanner.scan_path = MagicMock(return_value=mock_result)

                result = await handle_scan_dependencies({})

                assert len(result) == 1
                # Should use cwd and succeed
                mock_scanner.scan_path.assert_called_once()

    @pytest.mark.asyncio
    async def test_fix_with_target_version(self):
        """Test fixing with specific target version."""
        mock_result = FixResult(
            success=True,
            file_modified="requirements.txt",
            old_version="1.0.0",
            new_version="2.0.0",
            diff="-pkg==1.0.0\n+pkg==2.0.0",
        )

        with patch("os.path.exists", return_value=True):
            with patch("security_use.fixers.dependency_fixer.DependencyFixer") as mock_fixer_cls:
                mock_fixer_instance = MagicMock()
                mock_fixer_instance.fix = MagicMock(return_value=mock_result)
                mock_fixer_cls.return_value = mock_fixer_instance

                result = await handle_fix_vulnerability(
                    {
                        "package_name": "pkg",
                        "target_version": "2.0.0",
                        "path": "/test/path",
                    }
                )

                assert len(result) == 1
                assert "2.0.0" in result[0].text
                # Verify target_version was passed
                call_kwargs = mock_fixer_instance.fix.call_args.kwargs
                assert call_kwargs.get("target_version") == "2.0.0"
