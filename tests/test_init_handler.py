"""Tests for init handlers."""

import pytest
from pathlib import Path
from textwrap import dedent
from unittest.mock import MagicMock, patch, AsyncMock


class TestInitProjectHandler:
    """Tests for the init_project handler."""

    @pytest.mark.asyncio
    async def test_init_project_fastapi(self, tmp_path: Path):
        """Test initializing a FastAPI project."""
        from security_use_mcp.handlers.init_handler import handle_init_project

        # Create a FastAPI project
        app_file = tmp_path / "main.py"
        app_file.write_text(
            dedent("""
            from fastapi import FastAPI
            
            app = FastAPI()
            
            @app.get("/")
            def root():
                return {"message": "Hello"}
        """)
        )
        (tmp_path / "requirements.txt").write_text("fastapi\nuvicorn")

        result = await handle_init_project({"path": str(tmp_path)})

        assert len(result) == 1
        assert "FastAPI" in result[0].text or "Fastapi" in result[0].text
        assert "main.py" in result[0].text

    @pytest.mark.asyncio
    async def test_init_project_dry_run(self, tmp_path: Path):
        """Test dry run mode doesn't modify files."""
        from security_use_mcp.handlers.init_handler import handle_init_project

        # Create a FastAPI project
        app_file = tmp_path / "main.py"
        original_content = dedent("""
            from fastapi import FastAPI
            app = FastAPI()
        """)
        app_file.write_text(original_content)

        result = await handle_init_project({"path": str(tmp_path), "dry_run": True})

        assert len(result) == 1
        assert "Dry run" in result[0].text

        # Verify no config was created
        assert not (tmp_path / ".security-use.yaml").exists()

        # Verify app wasn't modified
        assert app_file.read_text() == original_content

    @pytest.mark.asyncio
    async def test_init_project_invalid_path(self):
        """Test handling of invalid path."""
        from security_use_mcp.handlers.init_handler import handle_init_project

        result = await handle_init_project({"path": "/nonexistent/path"})

        assert len(result) == 1
        assert "Error" in result[0].text
        assert "does not exist" in result[0].text

    @pytest.mark.asyncio
    async def test_init_project_skip_middleware(self, tmp_path: Path):
        """Test skipping middleware injection."""
        from security_use_mcp.handlers.init_handler import handle_init_project

        # Create a FastAPI project
        app_file = tmp_path / "main.py"
        original_content = "from fastapi import FastAPI\napp = FastAPI()"
        app_file.write_text(original_content)

        result = await handle_init_project({"path": str(tmp_path), "inject_middleware": False})

        assert len(result) == 1

        # Verify middleware was not injected
        assert "SecurityMiddleware" not in app_file.read_text()


class TestDetectProjectHandler:
    """Tests for the detect_project handler."""

    @pytest.mark.asyncio
    async def test_detect_fastapi_project(self, tmp_path: Path):
        """Test detecting a FastAPI project."""
        from security_use_mcp.handlers.init_handler import handle_detect_project

        # Create a FastAPI project
        (tmp_path / "main.py").write_text(
            dedent("""
            from fastapi import FastAPI
            app = FastAPI()
        """)
        )
        (tmp_path / "requirements.txt").write_text("fastapi")

        result = await handle_detect_project({"path": str(tmp_path)})

        assert len(result) == 1
        assert "FastAPI" in result[0].text
        assert "requirements.txt" in result[0].text

    @pytest.mark.asyncio
    async def test_detect_flask_project(self, tmp_path: Path):
        """Test detecting a Flask project."""
        from security_use_mcp.handlers.init_handler import handle_detect_project

        (tmp_path / "app.py").write_text(
            dedent("""
            from flask import Flask
            application = Flask(__name__)
        """)
        )

        result = await handle_detect_project({"path": str(tmp_path)})

        assert len(result) == 1
        assert "Flask" in result[0].text

    @pytest.mark.asyncio
    async def test_detect_terraform_project(self, tmp_path: Path):
        """Test detecting Terraform files."""
        from security_use_mcp.handlers.init_handler import handle_detect_project

        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "example" {}')

        result = await handle_detect_project({"path": str(tmp_path)})

        assert len(result) == 1
        assert "Terraform" in result[0].text

    @pytest.mark.asyncio
    async def test_detect_empty_project(self, tmp_path: Path):
        """Test detecting an empty project."""
        from security_use_mcp.handlers.init_handler import handle_detect_project

        result = await handle_detect_project({"path": str(tmp_path)})

        assert len(result) == 1
        assert "Unknown" in result[0].text or "No" in result[0].text

    @pytest.mark.asyncio
    async def test_detect_invalid_path(self):
        """Test handling of invalid path."""
        from security_use_mcp.handlers.init_handler import handle_detect_project

        result = await handle_detect_project({"path": "/nonexistent/path"})

        assert len(result) == 1
        assert "Error" in result[0].text

    @pytest.mark.asyncio
    async def test_detect_existing_config(self, tmp_path: Path):
        """Test detecting existing security-use config."""
        from security_use_mcp.handlers.init_handler import handle_detect_project

        (tmp_path / ".security-use.yaml").write_text("version: 1")

        result = await handle_detect_project({"path": str(tmp_path)})

        assert len(result) == 1
        assert "Present" in result[0].text or "✓" in result[0].text
