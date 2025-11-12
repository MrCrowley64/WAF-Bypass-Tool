# WAF Bypass Tool

A professional penetration testing tool for evaluating Web Application Firewall (WAF) effectiveness through automated payload testing. This tool helps security researchers and pentesters identify potential bypasses in WAF configurations.

## Features

- **Multi-Category Payload Testing**: Tests XSS, SQLi, LFI, RCE, XXE and more
- **Parallel Testing**: Multi-threaded execution for faster results
- **Flexible Configuration**: Custom headers, proxies, and block codes
- **Multiple Injection Points**: Tests GET params, POST data, and HTTP headers
- **Result Analysis**: Detailed bypass rate calculation and categorization
- **cURL Replay**: Generate cURL commands to reproduce findings
- **JSON Output**: Machine-readable results for automation
- **Progress Tracking**: Real-time progress display

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/waf-bypass-tool.git
cd waf-bypass-tool
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python3 waf_bypass.py --host=example.com
```

### Advanced Usage

```bash
# Test with custom proxy
python3 waf_bypass.py --host=https://example.com --proxy=http://127.0.0.1:8080

# Add custom headers
python3 waf_bypass.py --host=example.com --header="Authorization: Bearer token123"

# Specify custom block codes
python3 waf_bypass.py --host=example.com --block-code=403 --block-code=406

# Increase threads for faster testing
python3 waf_bypass.py --host=example.com --threads=10

# Get detailed results with cURL replay
python3 waf_bypass.py --host=example.com --details --curl-replay

# Exclude specific payload categories
python3 waf_bypass.py --host=example.com --exclude-dir=XXE,RCE

# JSON output for automation
python3 waf_bypass.py --host=example.com --json-format
```

## Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--host` | Target host (required) | `--host=example.com:80` |
| `--proxy` | HTTP/HTTPS proxy server | `--proxy=http://127.0.0.1:8080` |
| `--header` | Add custom HTTP header | `--header='Authorization: Basic ...'` |
| `--user-agent` | Set custom User-Agent | `--user-agent='MyScanner/1.0'` |
| `--block-code` | HTTP status codes indicating WAF block | `--block-code=403` |
| `--threads` | Number of parallel threads (default: 5) | `--threads=10` |
| `--timeout` | Request timeout in seconds (default: 30) | `--timeout=10` |
| `--json-format` | Output results in JSON format | `--json-format` |
| `--details` | Show detailed payload information | `--details` |
| `--no-progress` | Disable progress bar | `--no-progress` |
| `--curl-replay` | Generate cURL commands for replay | `--curl-replay` |
| `--exclude-dir` | Exclude payload directories | `--exclude-dir=SQLi,XSS` |

## Payload Structure

Payloads are organized by category in the `payloads/` directory:

```
payloads/
├── xss/
│   ├── basic.txt
│   └── bypass.txt
├── sqli/
│   ├── basic.txt
│   └── bypass.txt
├── lfi/
│   ├── basic.txt
│   └── bypass.txt
├── rce/
│   ├── basic.txt
│   └── bypass.txt
└── xxe/
    └── basic.txt
```

### Adding Custom Payloads

1. Create a new directory in `payloads/` for your category
2. Add `.txt` files with one payload per line
3. Lines starting with `#` are treated as comments

Example:
```bash
mkdir payloads/my-custom-attacks
echo "custom-payload-1" > payloads/my-custom-attacks/test.txt
echo "custom-payload-2" >> payloads/my-custom-attacks/test.txt
```

## Example Output

```
##
# Target:       http://example.com
# Proxy:        http://127.0.0.1:8080
# Timeout:      30s
# Threads:      5
# Block codes:  403
# User-Agent:   Mozilla/5.0...
##

Loading payloads...
Loaded 50 payloads from 5 categories
Categories: XSS, SQLI, LFI, RCE, XXE

Starting tests...

Progress: 100.0% (50/50)

============================================================
RESULTS
============================================================
Total Tests:    50
Bypassed (✓):   12
Blocked (✗):    35
Failed:         3
Bypass Rate:    24.00%
============================================================
```

## Use Cases

- **WAF Testing**: Evaluate WAF effectiveness during security assessments
- **Security Research**: Test new bypass techniques against WAF rules
- **Penetration Testing**: Identify vulnerable endpoints during authorized testing
- **Security Training**: Learn about WAF bypass techniques in controlled environments

## Legal Disclaimer

**IMPORTANT**: This tool is designed for authorized security testing only.

- Only use against systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal
- The authors assume no liability for misuse of this tool
- Always comply with applicable laws and regulations
- Obtain proper authorization before conducting security assessments

## Technical Details

### Testing Methodology

The tool performs testing through multiple injection vectors:
1. **GET Parameters**: Injects payloads as URL parameters
2. **POST Data**: Sends payloads in request body
3. **HTTP Headers**: Tests header-based injection (X-Test)

### Result Categories

- **Bypassed**: Payload reached the application (non-block status code)
- **Blocked**: WAF blocked the request (configured block codes)
- **Failed**: Request failed due to timeout or network error

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-payloads`)
3. Add your payloads or improvements
4. Test thoroughly
5. Submit a pull request

### Payload Contribution Guidelines

- Test payloads before submitting
- Organize by attack category
- Add comments explaining complex payloads
- Include both basic and bypass variants

## Author

**Henri** - Security Researcher & Penetration Tester
- GitHub: [YOUR_GITHUB_USERNAME]
- LinkedIn: [YOUR_LINKEDIN_PROFILE]

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OWASP Top 10 project for security guidance
- Security research community for payload techniques
- WAF vendors for advancing web application security

## Roadmap

- [ ] Add more payload categories (SSRF, SSTI, etc.)
- [ ] Implement machine learning for intelligent payload generation
- [ ] Add WAF fingerprinting capabilities
- [ ] Support for authenticated testing
- [ ] Integration with Burp Suite and OWASP ZAP
- [ ] Automated payload encoding/obfuscation
- [ ] Response analysis for blind vulnerabilities

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Contact via LinkedIn

---

**Remember**: Use responsibly and ethically. Always obtain proper authorization before testing.
