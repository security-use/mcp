# Cursor Integration Guide

This guide explains how to set up the Security-Use MCP server with Cursor for AI-powered security scanning and remediation.

## Prerequisites

- [Cursor](https://cursor.sh/) IDE installed
- Python 3.10 or higher
- pip package manager

## Installation

### Option 1: Install from PyPI (Recommended)

```bash
pip install security-use-mcp
```

### Option 2: Install from Source

```bash
git clone https://github.com/security-use/mcp.git
cd mcp
pip install -e .
```

## Configuration

### Step 1: Locate Cursor's MCP Configuration

Cursor's MCP configuration file is typically located at:

- **macOS/Linux**: `~/.cursor/mcp.json`
- **Windows**: `%APPDATA%\Cursor\mcp.json`

If the file doesn't exist, create it.

### Step 2: Add the Security-Use MCP Server

Add the following configuration to your `mcp.json`:

```json
{
  "mcpServers": {
    "security-use": {
      "command": "security-use-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

If you installed from source, use the full path:

```json
{
  "mcpServers": {
    "security-use": {
      "command": "python",
      "args": ["-m", "security_use_mcp.server"],
      "env": {}
    }
  }
}
```

### Step 3: Restart Cursor

After updating the configuration, restart Cursor for the changes to take effect.

### Step 4: Verify the Integration

1. Open Cursor's AI chat (Cmd+L / Ctrl+L)
2. Type: "What security tools are available?"
3. The AI should list the security-use tools: `scan_dependencies`, `scan_iac`, `fix_vulnerability`, `fix_iac`

## Available Tools

### scan_dependencies

Scans your project for known vulnerabilities in dependencies.

**Example prompts:**
- "Scan this project for dependency vulnerabilities"
- "Check if my Python packages have any security issues"
- "Are there any CVEs in my requirements.txt?"

### scan_iac

Scans Infrastructure as Code files for security misconfigurations.

**Example prompts:**
- "Scan my Terraform files for security issues"
- "Check this CloudFormation template for misconfigurations"
- "Are my AWS resources configured securely?"

### fix_vulnerability

Automatically fixes vulnerable dependencies by updating to safe versions.

**Example prompts:**
- "Fix the requests vulnerability"
- "Update django to a secure version"
- "Fix all critical dependency vulnerabilities"

### fix_iac

Provides fix suggestions or automatically fixes IaC security issues.

**Example prompts:**
- "How do I fix the S3 bucket public access issue?"
- "Fix the IAM policy that's too permissive"
- "Apply the fix for AWS001 in main.tf"

## Example Workflow

### 1. Scan for Vulnerabilities

Open the AI chat and ask:

```
Scan this project for security vulnerabilities in both dependencies and infrastructure code.
```

### 2. Review the Results

The AI will present findings grouped by severity with details about each issue.

### 3. Fix Issues

Ask the AI to fix specific issues:

```
Fix the critical vulnerability in the requests package.
```

Or fix IaC issues:

```
Fix the S3 bucket public access issue in s3.tf on line 15.
```

### 4. Review Changes

The AI will show you a diff of the changes made. Review them before committing.

## Advanced Configuration

### Environment Variables

You can pass environment variables to the MCP server:

```json
{
  "mcpServers": {
    "security-use": {
      "command": "security-use-mcp",
      "args": [],
      "env": {
        "SECURITY_USE_LOG_LEVEL": "DEBUG",
        "SECURITY_USE_CACHE_DIR": "/tmp/security-use-cache"
      }
    }
  }
}
```

### Multiple Projects

The tools automatically use the current working directory. To scan a specific path, mention it in your prompt:

```
Scan /path/to/my/project for vulnerabilities
```

## Troubleshooting

### Server Not Starting

1. **Check Python version**: Ensure Python 3.10+ is installed
   ```bash
   python --version
   ```

2. **Verify installation**: Check if the package is installed
   ```bash
   pip show security-use-mcp
   ```

3. **Check logs**: Look for errors in Cursor's developer console (Help > Toggle Developer Tools)

### Tools Not Appearing

1. **Restart Cursor**: Sometimes a restart is needed after configuration changes

2. **Verify mcp.json**: Ensure the JSON is valid and properly formatted

3. **Check command path**: If using a virtual environment, use the full path to the Python executable

### Scan Returns Errors

1. **Check file permissions**: Ensure the MCP server can read project files

2. **Verify security-use package**: The core scanning package must be installed
   ```bash
   pip install security-use
   ```

### Performance Issues

For large projects, scanning may take longer. You can:

1. **Scan specific directories**: Ask to scan a specific path instead of the entire project

2. **Enable caching**: Set the `SECURITY_USE_CACHE_DIR` environment variable

## Getting Help

- **GitHub Issues**: [security-use/mcp](https://github.com/security-use/mcp/issues)
- **Documentation**: [security-use.dev](https://security-use.dev)

## Security Considerations

- The MCP server runs locally and does not send data to external services (except for CVE database lookups)
- Scan results are processed entirely on your machine
- Fix operations modify local files only - always review changes before committing
