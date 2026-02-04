"""Handler for project initialization tools."""

import asyncio
import os
from pathlib import Path
from typing import Any

from mcp.types import TextContent


async def handle_init_project(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Initialize security-use for a project.

    Automatically detects the project framework (FastAPI, Flask, Django) and sets up:
    - .security-use.yaml configuration file
    - Runtime protection middleware (FastAPI/Flask injection, Django instructions)
    - Pre-commit hooks for scanning

    Args:
        arguments: Tool arguments containing:
            - path: Project path (default: current directory)
            - inject_middleware: Whether to inject runtime middleware (default: true)
            - setup_precommit: Whether to set up pre-commit hooks (default: true)
            - dry_run: Preview changes without modifying files (default: false)

    Returns:
        List of TextContent with initialization results
    """
    path = arguments.get("path", os.getcwd())
    inject_middleware = arguments.get("inject_middleware", True)
    setup_precommit = arguments.get("setup_precommit", True)
    dry_run = arguments.get("dry_run", False)

    # Validate path exists
    if not os.path.exists(path):
        return [TextContent(type="text", text=f"Error: Path does not exist: {path}")]

    try:
        # Import here to avoid circular imports and ensure security-use is available
        from security_use.init import ProjectInitializer

        # Run initialization in thread pool
        def run_init():
            initializer = ProjectInitializer(Path(path))
            info = initializer.detect()
            results = initializer.initialize(
                info,
                inject_middleware=inject_middleware,
                setup_precommit=setup_precommit,
                dry_run=dry_run,
            )
            return info, results

        info, results = await asyncio.to_thread(run_init)

        # Format results
        output_lines = [
            "## Project Initialization Results",
            "",
        ]

        if dry_run:
            output_lines.append("**Mode**: Dry run (no changes made)")
            output_lines.append("")

        # Detection results
        output_lines.extend(
            [
                "### Detection",
                "",
                f"- **Framework**: {info.framework.value.title()}",
                f"- **App File**: {info.primary_app.path.name if info.primary_app else 'N/A'}",
            ]
        )

        if info.primary_app and info.primary_app.has_middleware:
            output_lines.append("  - SecurityMiddleware already present")

        dep_files = []
        if info.has_requirements:
            dep_files.append("requirements.txt")
        if info.has_pyproject:
            dep_files.append("pyproject.toml")
        if info.has_pipfile:
            dep_files.append("Pipfile")

        output_lines.append(
            f"- **Dependencies**: {', '.join(dep_files) if dep_files else 'None found'}"
        )

        iac_types = []
        if info.has_terraform:
            iac_types.append("Terraform")
        if info.has_cloudformation:
            iac_types.append("CloudFormation")
        output_lines.append(f"- **IaC**: {', '.join(iac_types) if iac_types else 'None found'}")

        output_lines.append("")

        # Actions taken
        output_lines.extend(
            [
                "### Actions",
                "",
            ]
        )

        # Config
        if results["config"]["success"]:
            output_lines.append(f"✓ {results['config']['message']}")
        elif results["config"]["message"]:
            output_lines.append(f"○ {results['config']['message']}")

        # Middleware
        if results["middleware"]["success"]:
            output_lines.append(f"✓ {results['middleware']['message']}")
        elif results["middleware"]["message"]:
            output_lines.append(f"○ {results['middleware']['message']}")

        # Pre-commit
        if results["precommit"]["success"]:
            output_lines.append(f"✓ {results['precommit']['message']}")
        elif results["precommit"]["message"]:
            output_lines.append(f"○ {results['precommit']['message']}")

        output_lines.append("")

        # Next steps
        output_lines.extend(
            [
                "### Next Steps",
                "",
                "1. Run `security-use auth login` to connect to the dashboard",
                "2. Run `security-use scan all .` to perform your first scan",
                "3. Run `pip install pre-commit && pre-commit install` to enable git hooks",
            ]
        )

        return [TextContent(type="text", text="\n".join(output_lines))]

    except ImportError as e:
        return [
            TextContent(
                type="text",
                text=f"Error: security-use not installed. Run: pip install security-use\n\n{e}",
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Initialization error: {e}")]


async def handle_detect_project(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Detect project framework and configuration without making changes.

    Analyzes a project directory to identify:
    - Web framework (FastAPI, Flask, Django)
    - Dependency files
    - Infrastructure as Code files
    - Existing security configuration

    Args:
        arguments: Tool arguments containing optional 'path' parameter

    Returns:
        List of TextContent with detection results
    """
    path = arguments.get("path", os.getcwd())

    if not os.path.exists(path):
        return [TextContent(type="text", text=f"Error: Path does not exist: {path}")]

    try:
        from security_use.init import Framework, ProjectDetector

        def run_detect():
            detector = ProjectDetector(Path(path))
            return detector.detect()

        info = await asyncio.to_thread(run_detect)

        output_lines = [
            "## Project Detection Results",
            "",
            f"**Path**: {info.root}",
            "",
            "### Framework",
            "",
        ]

        framework_info = {
            Framework.FASTAPI: "⚡ FastAPI (ASGI)",
            Framework.FLASK: "🌶️ Flask (WSGI)",
            Framework.DJANGO: "🎸 Django",
            Framework.UNKNOWN: "❓ Unknown",
        }

        output_lines.append(f"- **Detected**: {framework_info.get(info.framework, 'Unknown')}")

        if info.app_files:
            output_lines.append(f"- **App Files Found**: {len(info.app_files)}")
            for app in info.app_files:
                middleware_status = " (has middleware)" if app.has_middleware else ""
                output_lines.append(
                    f"  - `{app.path.name}` - {app.framework.value}{middleware_status}"
                )

        output_lines.append("")
        output_lines.append("### Dependencies")
        output_lines.append("")

        dep_status = []
        if info.has_requirements:
            dep_status.append("✓ requirements.txt")
        if info.has_pyproject:
            dep_status.append("✓ pyproject.toml")
        if info.has_pipfile:
            dep_status.append("✓ Pipfile")
        if info.has_poetry_lock:
            dep_status.append("✓ poetry.lock")

        if dep_status:
            output_lines.extend([f"- {s}" for s in dep_status])
        else:
            output_lines.append("- No dependency files found")

        output_lines.append("")
        output_lines.append("### Infrastructure as Code")
        output_lines.append("")

        if info.has_terraform or info.has_cloudformation:
            if info.has_terraform:
                output_lines.append("- ✓ Terraform files detected")
            if info.has_cloudformation:
                output_lines.append("- ✓ CloudFormation templates detected")
        else:
            output_lines.append("- No IaC files found")

        output_lines.append("")
        output_lines.append("### Existing Configuration")
        output_lines.append("")
        config_status = "✓ Present" if info.has_security_use_config else "✗ Not found"
        output_lines.append(f"- **security-use config**: {config_status}")
        output_lines.append(
            f"- **pre-commit hooks**: {'✓ Present' if info.has_pre_commit else '✗ Not found'}"
        )
        output_lines.append(
            f"- **Dockerfile**: {'✓ Present' if info.has_dockerfile else '✗ Not found'}"
        )

        return [TextContent(type="text", text="\n".join(output_lines))]

    except ImportError as e:
        return [
            TextContent(
                type="text",
                text=f"Error: security-use not installed. Run: pip install security-use\n\n{e}",
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Detection error: {e}")]
