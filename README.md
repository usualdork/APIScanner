# APIScanner

## API Security Assessment Tool

A comprehensive security assessment tool for analyzing API security based on Postman collections, focusing on OWASP API Top 10 vulnerabilities and industry best practices.

## Overview

This tool performs automated security assessments of any API implementation using Postman collections, generating detailed reports that highlight potential vulnerabilities, security misconfigurations, and areas for improvement. It follows the OWASP API Security Top 10 guidelines to ensure thorough coverage of common API security risks.

## Features

- **Automated Security Scanning**: Comprehensive analysis of API endpoints
- **OWASP API Top 10 Assessment**: Evaluation against latest security standards
- **Rate Limiting Analysis**: Detection of missing or inadequate rate limiting
- **TLS Security Verification**: Validation of transport layer security
- **Authentication Analysis**: Review of authentication mechanisms
- **Detailed HTML Reports**: Generated reports with actionable insights
- **Visual Analytics**: Charts and graphs for security metrics

## Project Structure

```
api_security_report/
├── README.md
├── security_report/
│   ├── auth_script.js
│   ├── security_report.html
│   ├── owasp_distribution.png
│   └── severity_distribution.png
└── postman_collection.json
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/usualdork/APIScanner.git
cd api-security-assessment
```

2. Install dependencies:
```bash
npm install
```

## Usage

1. Install OWASP ZAP from https://www.zaproxy.org/download/

2. Install required Python dependencies:
```bash
pip install requests python-owasp-zap-v2.4 matplotlib seaborn jinja2
```

3. Start ZAP manually:
   - Launch OWASP ZAP
   - Navigate to Tools -> Options -> API
   - Note down or generate your API key

4. Run the security assessment with your Postman collection:
```bash
python3 1.py --collection sample_postman_collection.json --zap-key your-zap-api-key
```

Additional options:
- `--zap-host`: ZAP host (default: localhost)
- `--zap-port`: ZAP port (default: 8080)
- `--skip-zap`: Skip ZAP integration
- `--zap-path`: Custom path to ZAP executable

5. View the generated report in the `security_report` directory

## Security Assessment Coverage

- **API1:2023**: Broken Object Level Authorization
- **API2:2023**: Broken Authentication
- **API3:2023**: Broken Object Property Level Authorization
- **API4:2023**: Unrestricted Resource Consumption
- **API5:2023**: Broken Function Level Authorization
- **API6:2023**: Unrestricted Access to Sensitive Business Flows
- **API7:2023**: Server Side Request Forgery
- **API8:2023**: Security Misconfiguration
- **API9:2023**: Improper Inventory Management
- **API10:2023**: Unsafe Consumption of APIs

## Report Interpretation

The generated HTML reports include:
- Executive Summary
- Detailed findings for each API endpoint
- Severity distribution of identified issues
- OWASP API Top 10 risk assessment
- Specific recommendations for remediation

## Best Practices

1. Regular Security Assessments
2. Proper Rate Limiting Implementation
3. Strong Authentication Mechanisms
4. Input Validation
5. TLS 1.2+ Usage
6. Comprehensive API Documentation
7. Error Handling Best Practices
8. Access Control Implementation
9. Monitoring and Logging

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is meant for security assessment purposes only. Always ensure you have proper authorization before testing any API endpoints.
