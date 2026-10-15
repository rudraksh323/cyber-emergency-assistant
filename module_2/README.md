# Cyber Emergency Assistant - Module 2

Module 2 provides shared utility functions and an explainable, offline phishing URL checker for the Cyber Emergency Assistant.

## Features

- Scores URLs as `SAFE`, `SUSPICIOUS`, or `DANGEROUS`.
- Detects raw IP-address links.
- Checks suspicious top-level domains.
- Detects one-character brand misspellings.
- Finds urgent, account, login, OTP, and KYC-related terms.
- Warns about links without HTTPS and unusually long URLs.
- Produces human-readable reasons for every score.
- Provides safe wrappers for timestamps and system commands.

## Dependency

Module 2 imports the brand list, suspicious TLDs, and red-flag words from `module_1/config.py`. Keep the `module_1` and `module_2` directories under the same project directory.

## Run The Tests

From the `pbl_modules` directory:

```bash
python -m unittest module_2.test_security_utils -v
```

## Quick Example

```bash
python -c "from module_2 import check_url, format_url_result; print(format_url_result(check_url('http://paypa1.xyz/verify-account')))"
```

The scanner works locally and does not send the URL to an external service.
