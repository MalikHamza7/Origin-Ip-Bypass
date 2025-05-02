# Web Origin IP Bypass

A tool to discover origin IPs by bypassing WAF protection.

Developed By M Hamza

## Overview

Web Origin IP Bypass helps penetration testers and security researchers discover the true origin IP addresses of websites protected by WAFs (Web Application Firewalls). This tool follows a methodical workflow:

1. Gather subdomains for the target domain
2. Hunt for subdomains without WAF protection
3. Extract ASN (Autonomous System Number) information
4. Check BGP data to identify IP ranges
5. Verify live IPs that could be origin servers

## Features

- Comprehensive subdomain enumeration from multiple sources
- WAF detection for common WAF providers (Cloudflare, AWS WAF, Akamai, etc.)
- ASN extraction and organization information
- IP range discovery for identified ASNs
- Live IP verification
- Detailed reporting with progress tracking
- Colored terminal output for better readability

## Installation

```bash
# Clone the repository
git clone https://github.com/username/web-origin-ip-bypass.git
cd web-origin-ip-bypass

# Install requirements
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python main.py -d example.com
```

### Interactive Mode

```bash
python main.py
```

### Run Specific Steps

```bash
# Only enumerate subdomains
python main.py -d example.com -s

# Only detect WAF
python main.py -d example.com -w

# Only extract ASN
python main.py -d example.com -a

# Only find IP ranges
python main.py -d example.com -i
```

### Additional Options

```bash
# Save results to file
python main.py -d example.com -o results.txt

# Enable verbose output
python main.py -d example.com -v

# Show help
python main.py -h

# Show usage examples
python main.py --help-examples
```

## Disclaimer

This tool is provided for educational and legitimate security testing purposes only. Use responsibly and only on systems you have permission to test. The authors are not responsible for any misuse or damage caused by this tool.

## License

MIT License

## Acknowledgments

- The security research community for sharing techniques and knowledge
- Open-source intelligence tools that make this research possible
