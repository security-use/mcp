# Security-Use MCP Server

An MCP (Model Context Protocol) server that gives AI assistants like Cursor, Claude, and other MCP-compatible tools the ability to scan for security vulnerabilities and automatically fix them.

## What It Does

This MCP server exposes four powerful security tools to your AI assistant:

| Tool | Description |
|------|-------------|
| `scan_dependencies` | Scans your project's dependencies (requirements.txt, package.json, pyproject.toml, etc.) for known vulnerabilities using the OSV database |
| `scan_iac` | Scans Infrastructure as Code files (Terraform, CloudFormation) for security misconfigurations |
| `fix_vulnerability` | Automatically updates vulnerable packages to secure versions |
| `fix_iac` | Generates and applies fixes for IaC security issues |

## Supported Formats

### Dependency Scanning
- Python: `requirements.txt`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `setup.py`
- JavaScript/Node.js: `package.json`, `package-lock.json`
- Java: `pom.xml`

### Infrastructure as Code
- Terraform (`.tf` files)
- AWS CloudFormation (`.yaml`, `.yml`, `.json`)
- AWS SAM templates
- AWS CDK synthesized output

### IaC Security Rules
The scanner checks for common AWS misconfigurations including:
- **CKV_AWS_20**: S3 buckets with public access (CRITICAL)
- **CKV_AWS_19**: S3 buckets without encryption (HIGH)
- **CKV_AWS_23**: Security groups with unrestricted ingress (HIGH)
- **CKV_AWS_16**: RDS instances without encryption (HIGH)
- **CKV_AWS_3**: EBS volumes without encryption (HIGH)
- **CKV_AWS_35**: CloudTrail not enabled (MEDIUM)
- **CKV_AWS_14**: IAM users without MFA (MEDIUM)
- **CKV_AWS_12**: VPC without flow logs (MEDIUM)

## Installation

### From PyPI

```bash
pip install security-use-mcp
```

### From Source

```bash
git clone https://github.com/security-use/mcp.git
cd mcp
pip install -e .
```

## Quick Setup for Cursor

1. **Install the package** (see above)

2. **Add to Cursor's MCP configuration** (`~/.cursor/mcp.json`):

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

If you installed from source or use a virtual environment:

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

3. **Restart Cursor**

4. **Test it** - Open Cursor's AI chat and ask:
   > "Scan this project for security vulnerabilities"

## Usage Examples

Once configured, you can ask your AI assistant things like:

### Dependency Scanning
- "Scan this project for vulnerable dependencies"
- "Check if my Python packages have any CVEs"
- "Are there any security issues in my requirements.txt?"

### IaC Scanning
- "Scan my Terraform files for security issues"
- "Check this CloudFormation template for misconfigurations"
- "Are my S3 buckets configured securely?"

### Fixing Vulnerabilities
- "Fix the requests vulnerability"
- "Update django to a secure version"
- "Fix the S3 bucket public access issue in main.tf"

## Example Output

### Dependency Scan Results
```
## Dependency Security Scan Results

**Found 2 vulnerabilities**

### CRITICAL (1)

#### requests (2.25.0)
- **ID**: GHSA-xxxx-yyyy-zzzz
- **Title**: CVE-2023-32681 - Unintended leak of Proxy-Authorization header
- **Fixed in**: 2.31.0

### HIGH (1)

#### django (3.1.0)
- **ID**: CVE-2023-xxxxx
- **Title**: SQL Injection in QuerySet.values()
- **Fixed in**: 3.2.19
```

### IaC Scan Results
```
## IaC Security Scan Results

**Found 2 security issues**

### CRITICAL (1)

#### CKV_AWS_20: S3 bucket with public access
- **File**: `s3.tf:15`
- **Resource**: aws_s3_bucket.my-bucket
- **Remediation**: Set acl to 'private'

### HIGH (1)

#### CKV_AWS_23: Security group allows unrestricted ingress
- **File**: `sg.tf:8`
- **Resource**: aws_security_group.web
- **Remediation**: Restrict CIDR blocks to specific IPs
```

## Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECURITY_USE_LOG_LEVEL` | Logging level (DEBUG, INFO, WARN, ERROR) | INFO |
| `SECURITY_USE_CACHE_DIR` | Directory for caching vulnerability data | System temp |

Example configuration with environment variables:

```json
{
  "mcpServers": {
    "security-use": {
      "command": "security-use-mcp",
      "args": [],
      "env": {
        "SECURITY_USE_LOG_LEVEL": "DEBUG"
      }
    }
  }
}
```

## Development

### Setup

```bash
# Clone the repository
git clone https://github.com/security-use/mcp.git
cd mcp

# Install with dev dependencies
pip install -e ".[dev]"

# Also install the core security-use package
pip install -e ../security-use
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=security_use_mcp

# Run specific test file
pytest tests/test_handlers.py -v
```

### Linting

```bash
# Check code style
ruff check src/ tests/

# Auto-fix issues
ruff check src/ tests/ --fix
```

### Testing the Server

You can test the MCP server directly:

```bash
# Start the server (it communicates via stdin/stdout)
python -m security_use_mcp.server

# Or use the entry point
security-use-mcp
```

## Troubleshooting

### Server Not Starting

1. Check Python version (requires 3.10+):
   ```bash
   python --version
   ```

2. Verify installation:
   ```bash
   pip show security-use-mcp
   pip show security-use
   ```

3. Test the server directly:
   ```bash
   python -c "from security_use_mcp.server import server; print('OK')"
   ```

### Tools Not Appearing in Cursor

1. Restart Cursor after changing `mcp.json`
2. Check that the JSON is valid
3. Look for errors in Cursor's Developer Tools (Help > Toggle Developer Tools)

### Scan Returns No Results

1. Make sure you have dependency files (requirements.txt, package.json, etc.) or IaC files (.tf, .yaml) in your project
2. Check that the path is correct when scanning specific directories

## Architecture

```
security-use-mcp/
├── src/security_use_mcp/
│   ├── server.py          # MCP server implementation
│   ├── models.py          # Data models for results
│   └── handlers/          # Tool handlers
│       ├── dependency_handler.py
│       └── iac_handler.py
└── tests/
    ├── test_server.py     # Server tests
    ├── test_handlers.py   # Handler unit tests
    └── test_integration.py # Integration tests
```

The MCP server wraps the [security-use](https://github.com/security-use/security-use) Python package, which provides:
- Dependency scanning via the OSV (Open Source Vulnerabilities) database
- IaC scanning with configurable security rules
- Automated fixing capabilities

## Related Projects

- [security-use](https://github.com/security-use/security-use) - Core security scanning library
- [security-use-vscode](https://github.com/security-use/lsp-server/tree/main/vscode-extension) - VS Code extension
- [MCP Specification](https://modelcontextprotocol.io/) - Model Context Protocol documentation

## License

MIT
