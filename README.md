# IOCRC - Indicator of Compromise Reputation Checker

IOCRC is a command-line tool for scanning and analyzing security indicators (IOCs) across multiple threat intelligence services. It provides a unified interface to query services like VirusTotal and Shodan, making it easier to investigate potential security threats.

## Features

- **Multi-Service Integration**: Query multiple threat intelligence services with a single command
- **Support for Multiple IOC Types**:
  - IP Addresses
  - Domain Names
  - URLs
  - File Hashes (MD5, SHA1, SHA256)
- **Rich Console Output**: Clear, formatted results using tables and color-coding
- **Secure API Key Management**: Safe storage of API keys using system keyring
- **Error Handling**: Comprehensive error messages with helpful resolution tips

## Installation

### Prerequisites

- Python 3.11 or higher
- [UV](https://github.com/astral/uv) package manager

### Development Installation

1. Clone the repository:
```bash
git clone https://github.com/BlueishTsunami/IOCRC.git
cd IOCRC
```

2. Install dependencies using UV:
```bash
# Create a new virtual environment and install dependencies
uv venv
source .venv/bin/activate  # On Unix/macOS
# OR
.venv\Scripts\activate     # On Windows

# Install dependencies
uv pip install -e .
```

## API Key Setup

IOCRC requires API keys for the services it uses. You can set them up using the following commands:

```bash
# Set VirusTotal API key
iocrc key set --service virustotal

# Set Shodan API key
iocrc key set --service shodan
```

You can obtain API keys from:
- VirusTotal: [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
- Shodan: [https://account.shodan.io/register](https://account.shodan.io/register)

## Usage

### Full Scan
Run a comprehensive scan using all available services:
```bash
iocrc scan full
```

### Service-Specific Scans
Query individual services:
```bash
# VirusTotal scan
iocrc scan vt

# Shodan lookup
iocrc scan shodan
```

### Examples

```bash
# Scan an IP address
iocrc scan full
> Enter an IOC to scan: 8.8.8.8

# Check a domain
iocrc scan vt
> Enter an IOC for VirusTotal: example.com

# Look up host information
iocrc scan shodan
> Enter an IP address for Shodan: 1.1.1.1
```

## Supported IOC Types

- **IP Addresses**: IPv4 addresses (e.g., 8.8.8.8)
- **Domains**: Valid domain names (e.g., example.com)
- **URLs**: Valid URLs starting with http:// or https://
- **File Hashes**: MD5, SHA1, or SHA256 hashes

## Error Messages

IOCRC provides detailed error messages with suggestions for resolution:

- API key errors: Instructions for setting up or updating API keys
- Rate limiting: Information about usage limits and waiting periods
- Network issues: Connectivity troubleshooting tips
- Invalid inputs: Format requirements and examples

## Development

### Project Structure
```
.
├── .venv/                  # Virtual environment (created by UV)
├── src/                    # Source code
│   ├── apis/              # API integrations
│   ├── utils/             # Utility functions
│   └── main.py            # CLI entry point
├── pyproject.toml         # Project metadata and dependencies
├── uv.lock               # Dependency lock file
└── README.md             # This file
```

### Common Development Tasks

```bash
# Update dependencies
uv pip sync

# Create/update lock file
uv lock

# Run tests
uv run pytest

# Check dependency tree
uv tree
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the GPL-3.0 License - see the LICENSE file for details.

## Acknowledgments

- [VirusTotal](https://www.virustotal.com/) for their comprehensive threat intelligence API
- [Shodan](https://www.shodan.io/) for their internet security search engine
- [Rich](https://rich.readthedocs.io/) for beautiful terminal formatting
- [Typer](https://typer.tiangolo.com/) for the CLI interface
- [UV](https://github.com/astral/uv) for modern Python packaging
