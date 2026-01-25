# Security-Use MCP Server

MCP (Model Context Protocol) server that exposes security scanning tools to AI assistants like Cursor.

## Features

- **scan_dependencies** - Scan project dependencies for known vulnerabilities (CVEs)
- **scan_iac** - Scan Infrastructure as Code files for security misconfigurations
- **fix_vulnerability** - Automatically fix vulnerable dependencies
- **fix_iac** - Generate and apply fixes for IaC security issues

## Installation

```bash
pip install security-use-mcp
```

Or install from source:

```bash
git clone https://github.com/security-use/mcp.git
cd mcp
pip install -e .
```

## Usage with Cursor

See [Cursor Integration Guide](docs/cursor-integration.md) for detailed setup instructions.

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check src/
```

## License

MIT