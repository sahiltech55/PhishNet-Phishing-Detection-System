# PhishNet: A Rule-Enhanced Machine Learning Approach for Securing Against Phishing Threats

This project is a lightweight Python-based phishing URL detector that checks and blocks suspected phishing sites by analyzing URL patterns, SSL certificates, and domain age. The tool works cross-platform and modifies the system's hosts file to block malicious URLs.

## 🚀 Features

- Detects phishing URLs based on:
  - Suspicious patterns in URLs
  - Free domain usage
  - Embedded IP addresses
  - Dangerous keywords
  - Invalid SSL certificate
  - Domain age (< 30 days)
- Blocks URLs by adding entries to the local `hosts` file
- Works on both Windows and Unix systems
- Simple command-line interface

## 🛠 Requirements

```bash
pip install requests
