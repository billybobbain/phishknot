# Security Policy

## Reporting a Vulnerability

If you find a security issue in this project, please open a GitHub issue with:

- a clear description of the issue
- steps to reproduce
- expected vs actual behavior
- impact assessment (if known)

Please do not include secrets or sensitive personal data in the report.

## Scope and Intent

This repository is for defensive research and education.  
Do not use this code for phishing, credential theft, or any malicious activity.

## Safe Usage Notes

- Prefer running with `NO_DOWNLOAD=true` unless you explicitly need page fetches.
- Use an isolated environment (container/VM) when processing suspicious URLs.
- Keep dependencies up to date.
