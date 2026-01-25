"""Tests for tool handlers."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from security_use_mcp.models import (
    DependencyScanResult,
    IaCScanResult,
    Vulnerability,
    IaCFinding,
    FixResult,
    Severity,
)


class TestDependencyHandler:
    """Tests for dependency scanning and fixing handlers."""

    @pytest.mark.asyncio
    async def test_scan_dependencies_no_vulnerabilities(self):
        """Test scanning with no vulnerabilities found."""
        from security_use_mcp.handlers.dependency_handler import handle_scan_dependencies

        mock_result = DependencyScanResult(
            vulnerabilities=[],
            scanned_files=["requirements.txt"],
            total_dependencies=10,
            scan_duration_ms=150,
        )

        with patch(
            "security_use_mcp.handlers.dependency_handler._scanner"
        ) as mock_scanner:
            mock_scanner.scan = MagicMock(return_value=mock_result)

            result = await handle_scan_dependencies({"path": "/test/path"})

            assert len(result) == 1
            assert "No vulnerabilities found" in result[0].text

    @pytest.mark.asyncio
    async def test_scan_dependencies_with_vulnerabilities(self):
        """Test scanning with vulnerabilities found."""
        from security_use_mcp.handlers.dependency_handler import handle_scan_dependencies

        mock_result = DependencyScanResult(
            vulnerabilities=[
                Vulnerability(
                    package_name="requests",
                    installed_version="2.25.0",
                    severity=Severity.HIGH,
                    description="CVE-2023-32681 vulnerability",
                    cve_id="CVE-2023-32681",
                    fixed_version="2.31.0",
                    remediation="Upgrade to requests>=2.31.0",
                )
            ],
            scanned_files=["requirements.txt"],
            total_dependencies=10,
            scan_duration_ms=150,
        )

        with patch(
            "security_use_mcp.handlers.dependency_handler._scanner"
        ) as mock_scanner:
            mock_scanner.scan = MagicMock(return_value=mock_result)

            result = await handle_scan_dependencies({"path": "/test/path"})

            assert len(result) == 1
            assert "requests" in result[0].text
            assert "HIGH" in result[0].text
            assert "CVE-2023-32681" in result[0].text

    @pytest.mark.asyncio
    async def test_fix_vulnerability_success(self):
        """Test successful vulnerability fix."""
        from security_use_mcp.handlers.dependency_handler import handle_fix_vulnerability

        mock_result = FixResult(
            success=True,
            file_modified="requirements.txt",
            old_version="2.25.0",
            new_version="2.31.0",
            diff="-requests==2.25.0\n+requests==2.31.0",
        )

        with patch(
            "security_use_mcp.handlers.dependency_handler._fixer"
        ) as mock_fixer:
            mock_fixer.fix = MagicMock(return_value=mock_result)

            result = await handle_fix_vulnerability({
                "package_name": "requests",
                "path": "/test/path",
            })

            assert len(result) == 1
            assert "Successfully" in result[0].text or "Fix Applied" in result[0].text
            assert "2.31.0" in result[0].text

    @pytest.mark.asyncio
    async def test_fix_vulnerability_missing_package_name(self):
        """Test fix with missing package name."""
        from security_use_mcp.handlers.dependency_handler import handle_fix_vulnerability

        result = await handle_fix_vulnerability({"path": "/test/path"})

        assert len(result) == 1
        assert "required" in result[0].text.lower()


class TestIaCHandler:
    """Tests for IaC scanning and fixing handlers."""

    @pytest.mark.asyncio
    async def test_scan_iac_no_findings(self):
        """Test IaC scanning with no findings."""
        from security_use_mcp.handlers.iac_handler import handle_scan_iac

        mock_result = IaCScanResult(
            findings=[],
            scanned_files=["main.tf", "variables.tf"],
            scan_duration_ms=200,
        )

        with patch("security_use_mcp.handlers.iac_handler._scanner") as mock_scanner:
            mock_scanner.scan = MagicMock(return_value=mock_result)

            result = await handle_scan_iac({"path": "/test/path"})

            assert len(result) == 1
            assert "No security issues found" in result[0].text

    @pytest.mark.asyncio
    async def test_scan_iac_with_findings(self):
        """Test IaC scanning with findings."""
        from security_use_mcp.handlers.iac_handler import handle_scan_iac

        mock_result = IaCScanResult(
            findings=[
                IaCFinding(
                    rule_id="AWS001",
                    title="S3 bucket is publicly accessible",
                    file_path="s3.tf",
                    line_number=15,
                    severity=Severity.CRITICAL,
                    description="S3 bucket allows public read access",
                    remediation="Set acl to 'private' or configure bucket policy",
                    resource_name="my-bucket",
                    resource_type="aws_s3_bucket",
                )
            ],
            scanned_files=["s3.tf"],
            scan_duration_ms=200,
        )

        with patch("security_use_mcp.handlers.iac_handler._scanner") as mock_scanner:
            mock_scanner.scan = MagicMock(return_value=mock_result)

            result = await handle_scan_iac({"path": "/test/path"})

            assert len(result) == 1
            assert "AWS001" in result[0].text
            assert "s3.tf:15" in result[0].text
            assert "CRITICAL" in result[0].text

    @pytest.mark.asyncio
    async def test_fix_iac_suggestion(self):
        """Test IaC fix suggestion (not auto-applied)."""
        from security_use_mcp.handlers.iac_handler import handle_fix_iac

        mock_result = FixResult(
            success=True,
            before='resource "aws_s3_bucket" "my-bucket" {\n  acl = "public-read"\n}',
            after='resource "aws_s3_bucket" "my-bucket" {\n  acl = "private"\n}',
            explanation="Changed ACL from public-read to private to prevent unauthorized access.",
        )

        with patch("security_use_mcp.handlers.iac_handler._fixer") as mock_fixer:
            mock_fixer.fix = MagicMock(return_value=mock_result)

            result = await handle_fix_iac({
                "file_path": "s3.tf",
                "rule_id": "AWS001",
                "auto_apply": False,
            })

            assert len(result) == 1
            assert "Suggested" in result[0].text
            assert "Before" in result[0].text
            assert "After" in result[0].text

    @pytest.mark.asyncio
    async def test_fix_iac_auto_apply(self):
        """Test IaC fix with auto-apply."""
        from security_use_mcp.handlers.iac_handler import handle_fix_iac

        mock_result = FixResult(
            success=True,
            diff='-  acl = "public-read"\n+  acl = "private"',
            explanation="Changed ACL from public-read to private.",
        )

        with patch("security_use_mcp.handlers.iac_handler._fixer") as mock_fixer:
            mock_fixer.fix = MagicMock(return_value=mock_result)

            result = await handle_fix_iac({
                "file_path": "s3.tf",
                "rule_id": "AWS001",
                "auto_apply": True,
            })

            assert len(result) == 1
            assert "Applied" in result[0].text

    @pytest.mark.asyncio
    async def test_fix_iac_missing_required_params(self):
        """Test fix_iac with missing required parameters."""
        from security_use_mcp.handlers.iac_handler import handle_fix_iac

        # Missing file_path
        result = await handle_fix_iac({"rule_id": "AWS001"})
        assert "required" in result[0].text.lower()

        # Missing rule_id
        result = await handle_fix_iac({"file_path": "s3.tf"})
        assert "required" in result[0].text.lower()
