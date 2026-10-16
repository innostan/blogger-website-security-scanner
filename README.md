# Blogger Website Security Scanner

A Python project exploring how to make basic website security checks easier to understand for bloggers and independent website owners.

## Why I Built This

Website owners may not know which security-related headers their sites return or whether an HTTPS connection is being verified correctly. This project is an early-stage attempt to make some of those technical details visible.

## Current Features

- Validates website URLs.
- Checks resolved IP addresses and rejects non-public destinations.
- Connects to a selected validated IP address.
- Preserves hostname-based HTTPS certificate verification.
- Checks that the connected peer IP matches the selected IP.
- Detects redirects without automatically following them.
- Checks for common security headers:
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Referrer-Policy`
- Includes automated tests for URL validation and connection behavior.

## Technology

- Python
- `urllib3`
- `socket`
- `ipaddress`
- `unittest`

## Project Status

This project is under active development. It is a basic defensive security tool, not a complete vulnerability scanner or a guarantee that a website is secure.

## Planned Improvements

- Expand automated test coverage.
- Improve error handling and reporting.
- Explain findings in plain language.
- Make the results more useful to independent website owners.
- Document safe testing examples.

## Responsible Use

Only test websites you own or have explicit permission to assess. Do not use this tool to access private systems or bypass access controls.

## Author

Built by [innostan](https://github.com/innostan) as part of a hands-on journey into Python and defensive cybersecurity.
