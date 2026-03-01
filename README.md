# Security-Use MCP Server

An MCP (Model Context Protocol) server that gives AI assistants like Cursor, Claude, and other MCP-compatible tools the ability to scan for security vulnerabilities and automatically fix them.

## What It Does

This MCP server exposes powerful security tools to your AI assistant:

### Core Security Tools

| Tool | Description |
|------|-------------|
| `scan_dependencies` | Scans your project's dependencies for known vulnerabilities using the OSV database |
| `scan_iac` | Scans Infrastructure as Code files for security misconfigurations |
| `fix_vulnerability` | Automatically updates vulnerable packages to secure versions |
| `fix_iac` | Generates and applies fixes for IaC security issues |

### SBOM & Compliance Tools

| Tool | Description |
|------|-------------|
| `generate_sbom` | Generate Software Bill of Materials in CycloneDX or SPDX format |
| `check_compliance` | Check against SOC2, HIPAA, PCI-DSS, NIST 800-53, CIS, and ISO 27001 |

### Runtime Security Tools

| Tool | Description |
|------|-------------|
| `detect_vulnerable_endpoints` | Find API endpoints using vulnerable packages |
| `analyze_request` | Analyze HTTP requests for SQL injection, XSS, and other attacks |
| `get_sensor_config` | Generate SecurityMiddleware configuration for FastAPI/Flask |

### GitHub Integration

| Tool | Description |
|------|-------------|
| `create_fix_pr` | Create a GitHub PR with security fixes |

## Supported Formats

### Dependency Scanning
- **Python**: `requirements.txt`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `setup.py`
- **JavaScript/Node.js**: `package.json`, `package-lock.json`, `yarn.lock`
- **Java**: `pom.xml`, `build.gradle`
- **.NET**: `csproj`, `packages.config`
- **PHP**: `composer.json`, `composer.lock`
- **Conda**: `environment.yml`

### Infrastructure as Code
- **Terraform** (`.tf` files)
- **AWS CloudFormation** (`.yaml`, `.yml`, `.json`)
- **AWS SAM templates**
- **AWS CDK synthesized output**

### IaC Security Rules
The scanner checks for misconfigurations across multiple cloud providers:

**AWS**
- S3 buckets with public access or missing encryption
- Security groups with unrestricted ingress
- RDS/EBS without encryption
- CloudTrail not enabled
- IAM users without MFA

**Azure**
- Storage accounts with public access
- Network security group issues
- Key Vault misconfigurations

**GCP**
- Cloud Storage bucket permissions
- Firewall rules
- KMS configurations

**Kubernetes**
- Container security contexts
- Network policies
- RBAC configurations

### Compliance Frameworks
- **SOC 2** Type II controls
- **HIPAA** Security Rule
- **PCI-DSS** v4.0
- **NIST 800-53**
- **CIS Benchmarks** (AWS, Azure, GCP, Kubernetes)
- **ISO 27001**

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

### Compliance Checking
- "Check this project against SOC2 requirements"
- "Are we compliant with HIPAA security controls?"
- "Run a PCI-DSS compliance check on our infrastructure"

### SBOM Generation
- "Generate an SBOM for this project"
- "Create a CycloneDX bill of materials"
- "Generate an SPDX software inventory"

### Runtime Security
- "Find vulnerable endpoints in this Flask app"
- "Analyze this request for SQL injection: GET /api/users?id=1' OR '1'='1"
- "Generate security middleware config for my FastAPI app"

### GitHub Integration
- "Create a PR with these security fixes"
- "Open a draft PR for the vulnerability fix"

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

### Compliance Check Results
```
## Compliance Check Results

**Framework**: SOC 2 Type II
**Files Scanned**: 15

### Summary
- **Total IaC Findings**: 8
- **Findings Mapped to SOC 2**: 6

### CC6.1: Logical and Physical Access Controls
- **CKV_AWS_23**: Security group allows unrestricted ingress
  - File: `sg.tf:8`
  - Severity: HIGH

### CC6.6: System Operations - Encryption
- **CKV_AWS_19**: S3 bucket without encryption
  - File: `s3.tf:15`
  - Severity: HIGH
```

### Request Analysis Results
```
## Request Security Analysis

**Method**: GET
**Path**: /api/users
**Source IP**: 192.168.1.100

### ⚠️ 1 Potential Threat(s) Detected

#### 🔴 SQL_INJECTION
- **Severity**: CRITICAL
- **Confidence**: 95%
- **Description**: SQL injection attempt detected in query parameter
- **Location**: query
- **Field**: id
- **Matched Value**: `1' OR '1'='1`

### Recommendations
1. Block this request if in production
2. Log the source IP for monitoring
3. Review application input validation
```

## Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECURITY_USE_LOG_LEVEL` | Logging level (DEBUG, INFO, WARN, ERROR) | INFO |
| `SECURITY_USE_CACHE_DIR` | Directory for caching vulnerability data | System temp |
| `SECURITY_USE_API_KEY` | API key for dashboard alerting | None |

Example configuration with environment variables:

```json
{
  "mcpServers": {
    "security-use": {
      "command": "security-use-mcp",
      "args": [],
      "env": {
        "SECURITY_USE_LOG_LEVEL": "DEBUG",
        "SECURITY_USE_API_KEY": "your-api-key"
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

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

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
│       ├── dependency_handler.py  # Dependency scanning/fixing
│       ├── iac_handler.py         # IaC scanning/fixing
│       ├── github_handler.py      # GitHub PR creation
│       ├── sbom_handler.py        # SBOM generation
│       ├── compliance_handler.py  # Compliance checking
│       └── sensor_handler.py      # Runtime security tools
└── tests/
    ├── test_server.py         # Server tests
    ├── test_handlers.py       # Handler unit tests
    ├── test_new_handlers.py   # New handler tests
    └── test_integration.py    # Integration tests
```

The MCP server wraps the [security-use](https://github.com/security-use/security-use) Python package, which provides:
- Dependency scanning via the OSV (Open Source Vulnerabilities) database
- IaC scanning with configurable security rules for AWS, Azure, GCP, and Kubernetes
- SBOM generation in CycloneDX and SPDX formats
- Compliance framework mapping (SOC2, HIPAA, PCI-DSS, NIST, CIS, ISO 27001)
- Runtime attack detection (SQL injection, XSS, path traversal, command injection)
- Automated fixing capabilities

## Related Projects

- [security-use](https://github.com/security-use/security-use) - Core security scanning library
- [security-use-vscode](https://github.com/security-use/lsp-server/tree/main/vscode-extension) - VS Code extension
- [MCP Specification](https://modelcontextprotocol.io/) - Model Context Protocol documentation

## License

MIT
