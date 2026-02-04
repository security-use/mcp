"""Handler for GitHub PR creation tools."""

import asyncio
import os
import subprocess
from typing import Any

from mcp.types import TextContent


async def handle_create_fix_pr(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Create a GitHub PR with security fixes.

    Creates a new branch, commits the security fix changes, and opens a PR
    with a detailed description of the vulnerability being fixed.

    Args:
        arguments: Tool arguments containing:
            - repo (optional): Repository path or owner/name
            - vulnerability_id (optional): Vulnerability ID to reference
            - iac_finding_id (optional): IaC finding ID to reference
            - branch_name (optional): Target branch name
            - draft (optional): Create as draft PR (default: true)

    Returns:
        List of TextContent with PR details
    """
    repo = arguments.get("repo", os.getcwd())
    vulnerability_id = arguments.get("vulnerability_id")
    iac_finding_id = arguments.get("iac_finding_id")
    branch_name = arguments.get("branch_name")
    draft = arguments.get("draft", True)

    # Validate we're in a git repository
    if os.path.isdir(repo):
        working_dir = repo
    else:
        working_dir = os.getcwd()

    try:
        # Check if this is a git repo
        result = await asyncio.to_thread(
            subprocess.run,
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=working_dir,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return [TextContent(type="text", text="Error: Not a git repository")]

        # Check for staged or unstaged changes
        status_result = await asyncio.to_thread(
            subprocess.run,
            ["git", "status", "--porcelain"],
            cwd=working_dir,
            capture_output=True,
            text=True,
        )

        if not status_result.stdout.strip():
            return [
                TextContent(
                    type="text",
                    text=(
                        "## No Changes to Commit\n\n"
                        "There are no changes to create a PR from. "
                        "Please apply a security fix first using:\n"
                        "- `fix_vulnerability` for dependency vulnerabilities\n"
                        "- `fix_iac` for infrastructure code issues"
                    ),
                )
            ]

        # Get the list of changed files
        changed_files = [line[3:] for line in status_result.stdout.strip().split("\n") if line]

        # Generate branch name if not provided
        if not branch_name:
            if vulnerability_id:
                branch_name = f"security-fix/{vulnerability_id.lower().replace(':', '-')}"
            elif iac_finding_id:
                branch_name = f"security-fix/{iac_finding_id.lower().replace(':', '-')}"
            else:
                import time

                branch_name = f"security-fix/{int(time.time())}"

        # Create and checkout new branch
        checkout_result = await asyncio.to_thread(
            subprocess.run,
            ["git", "checkout", "-b", branch_name],
            cwd=working_dir,
            capture_output=True,
            text=True,
        )

        if checkout_result.returncode != 0:
            # Branch might already exist, try switching to it
            checkout_result = await asyncio.to_thread(
                subprocess.run,
                ["git", "checkout", branch_name],
                cwd=working_dir,
                capture_output=True,
                text=True,
            )
            if checkout_result.returncode != 0:
                return [
                    TextContent(
                        type="text",
                        text=f"Error creating branch: {checkout_result.stderr}",
                    )
                ]

        # Stage all changes
        await asyncio.to_thread(
            subprocess.run,
            ["git", "add", "-A"],
            cwd=working_dir,
            capture_output=True,
            text=True,
        )

        # Create commit message
        if vulnerability_id:
            commit_msg = f"fix: patch security vulnerability {vulnerability_id}"
            pr_title = f"Security Fix: {vulnerability_id}"
            pr_body = f"""## Security Fix

This PR addresses a security vulnerability.

### Vulnerability Details
- **ID**: {vulnerability_id}

### Changed Files
{chr(10).join(f"- `{f}`" for f in changed_files)}

### Testing
- [ ] Verify the fix resolves the vulnerability
- [ ] Run existing test suite
- [ ] Check for any breaking changes

---
*Created by security-use-mcp*"""
        elif iac_finding_id:
            commit_msg = f"fix: remediate IaC security issue {iac_finding_id}"
            pr_title = f"IaC Security Fix: {iac_finding_id}"
            pr_body = f"""## Infrastructure Security Fix

This PR addresses an infrastructure-as-code security misconfiguration.

### Finding Details
- **Rule ID**: {iac_finding_id}

### Changed Files
{chr(10).join(f"- `{f}`" for f in changed_files)}

### Testing
- [ ] Run `terraform plan` or equivalent to verify changes
- [ ] Review security implications
- [ ] Verify no unintended resource changes

---
*Created by security-use-mcp*"""
        else:
            commit_msg = "fix: apply security fixes"
            pr_title = "Security Fixes"
            pr_body = f"""## Security Fixes

This PR contains security fixes.

### Changed Files
{chr(10).join(f"- `{f}`" for f in changed_files)}

### Testing
- [ ] Verify fixes resolve the security issues
- [ ] Run existing test suite
- [ ] Check for any breaking changes

---
*Created by security-use-mcp*"""

        # Commit changes
        commit_result = await asyncio.to_thread(
            subprocess.run,
            ["git", "commit", "-m", commit_msg],
            cwd=working_dir,
            capture_output=True,
            text=True,
        )

        if commit_result.returncode != 0:
            return [
                TextContent(
                    type="text",
                    text=f"Error committing changes: {commit_result.stderr}",
                )
            ]

        # Push to remote
        push_result = await asyncio.to_thread(
            subprocess.run,
            ["git", "push", "-u", "origin", branch_name],
            cwd=working_dir,
            capture_output=True,
            text=True,
        )

        if push_result.returncode != 0:
            return [
                TextContent(
                    type="text",
                    text=f"Error pushing branch: {push_result.stderr}",
                )
            ]

        # Create PR using gh CLI
        pr_cmd = ["gh", "pr", "create", "--title", pr_title, "--body", pr_body]
        if draft:
            pr_cmd.append("--draft")

        pr_result = await asyncio.to_thread(
            subprocess.run,
            pr_cmd,
            cwd=working_dir,
            capture_output=True,
            text=True,
        )

        if pr_result.returncode != 0:
            return [
                TextContent(
                    type="text",
                    text=f"Error creating PR: {pr_result.stderr}",
                )
            ]

        pr_url = pr_result.stdout.strip()

        # Format success response
        output_lines = [
            "## Pull Request Created",
            "",
            f"**PR URL**: {pr_url}",
            f"**Branch**: {branch_name}",
            f"**Draft**: {'Yes' if draft else 'No'}",
            "",
            "### Changed Files",
            "",
        ]
        for f in changed_files:
            output_lines.append(f"- `{f}`")

        output_lines.extend(
            [
                "",
                "### Next Steps",
                "",
                "1. Review the PR on GitHub",
                "2. Request reviews from team members",
                "3. Address any CI/CD failures",
                "4. Merge when ready",
            ]
        )

        return [TextContent(type="text", text="\n".join(output_lines))]

    except FileNotFoundError:
        return [
            TextContent(
                type="text",
                text=(
                    "Error: git or gh CLI not found. "
                    "Please ensure git and GitHub CLI are installed."
                ),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error creating PR: {str(e)}")]
