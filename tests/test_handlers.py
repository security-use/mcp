"""Tests for tool handlers."""

from unittest.mock import MagicMock, patch

import pytest
from security_use.models import IaCFinding, ScanResult, Severity, Vulnerability

from security_use_mcp.models import FixResult


class TestDependencyHandler:
    """Tests for dependency scanning and fixing handlers."""

    @pytest.mark.asyncio
    async def test_scan_dependencies_no_vulnerabilities(self):
        """Test scanning with no vulnerabilities found."""
        from security_use_mcp.handlers.dependency_handler import handle_scan_dependencies

        mock_result = ScanResult(
            vulnerabilities=[],
            iac_findings=[],
            scanned_files=["requirements.txt"],
            errors=[],
        )

        with patch("os.path.exists", return_value=True):
            with patch("security_use_mcp.handlers.dependency_handler._scanner") as mock_scanner:
                mock_scanner.scan_path = MagicMock(return_value=mock_result)

                result = await handle_scan_dependencies({"path": "/test/path"})

                assert len(result) == 1
                assert "No vulnerabilities found" in result[0].text

    @pytest.mark.asyncio
    async def test_scan_dependencies_with_vulnerabilities(self):
        """Test scanning with vulnerabilities found."""
        from security_use_mcp.handlers.dependency_handler import handle_scan_dependencies

        mock_result = ScanResult(
            vulnerabilities=[
                Vulnerability(
                    id="GHSA-xxxx-yyyy-zzzz",
                    package="requests",
                    installed_version="2.25.0",
                    severity=Severity.HIGH,
                    title="CVE-2023-32681 vulnerability",
                    description="A security vulnerability in requests",
                    affected_versions=">=2.0.0,<2.31.0",
                    fixed_version="2.31.0",
                    references=["https://example.com"],
                )
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
                assert "requests" in result[0].text
                assert "HIGH" in result[0].text

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

        with patch("os.path.exists", return_value=True):
            with patch("security_use.fixers.dependency_fixer.DependencyFixer") as mock_fixer_cls:
                mock_fixer_instance = MagicMock()
                mock_fixer_instance.fix = MagicMock(return_value=mock_result)
                mock_fixer_cls.return_value = mock_fixer_instance

                result = await handle_fix_vulnerability(
                    {
                        "package_name": "requests",
                        "path": "/test/path",
                    }
                )

                assert len(result) == 1
                # Check for success indicators
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

        mock_result = ScanResult(
            vulnerabilities=[],
            iac_findings=[],
            scanned_files=["main.tf", "variables.tf"],
            errors=[],
        )

        with patch("os.path.exists", return_value=True):
            with patch("security_use_mcp.handlers.iac_handler._scanner") as mock_scanner:
                mock_scanner.scan_path = MagicMock(return_value=mock_result)

                result = await handle_scan_iac({"path": "/test/path"})

                assert len(result) == 1
                assert "No security issues found" in result[0].text

    @pytest.mark.asyncio
    async def test_scan_iac_with_findings(self):
        """Test IaC scanning with findings."""
        from security_use_mcp.handlers.iac_handler import handle_scan_iac

        mock_result = ScanResult(
            vulnerabilities=[],
            iac_findings=[
                IaCFinding(
                    rule_id="S3_PUBLIC_ACCESS",
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
            errors=[],
        )

        with patch("os.path.exists", return_value=True):
            with patch("security_use_mcp.handlers.iac_handler._scanner") as mock_scanner:
                mock_scanner.scan_path = MagicMock(return_value=mock_result)

                result = await handle_scan_iac({"path": "/test/path"})

                assert len(result) == 1
                assert "S3_PUBLIC_ACCESS" in result[0].text
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

        with patch("os.path.exists", return_value=True):
            with patch("security_use.fixers.iac_fixer.IaCFixer") as mock_fixer_cls:
                mock_fixer_instance = MagicMock()
                mock_fixer_instance.fix = MagicMock(return_value=mock_result)
                mock_fixer_cls.return_value = mock_fixer_instance

                result = await handle_fix_iac(
                    {
                        "file_path": "s3.tf",
                        "rule_id": "S3_PUBLIC_ACCESS",
                        "auto_apply": False,
                    }
                )

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

        with patch("os.path.exists", return_value=True):
            with patch("security_use.fixers.iac_fixer.IaCFixer") as mock_fixer_cls:
                mock_fixer_instance = MagicMock()
                mock_fixer_instance.fix = MagicMock(return_value=mock_result)
                mock_fixer_cls.return_value = mock_fixer_instance

                result = await handle_fix_iac(
                    {
                        "file_path": "s3.tf",
                        "rule_id": "S3_PUBLIC_ACCESS",
                        "auto_apply": True,
                    }
                )

                assert len(result) == 1
                assert "Applied" in result[0].text

    @pytest.mark.asyncio
    async def test_fix_iac_missing_required_params(self):
        """Test fix_iac with missing required parameters."""
        from security_use_mcp.handlers.iac_handler import handle_fix_iac

        # Missing file_path
        result = await handle_fix_iac({"rule_id": "S3_PUBLIC_ACCESS"})
        assert "required" in result[0].text.lower()

        # Missing rule_id
        result = await handle_fix_iac({"file_path": "s3.tf"})
        assert "required" in result[0].text.lower()
