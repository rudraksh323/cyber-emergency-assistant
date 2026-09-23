# Cyber Emergency Assistant — Module 1

## Module 1: `config.py`

This module contains the configuration and static data used by the Cyber Emergency Assistant.

### Purpose

`config.py` provides the common settings and predefined security data required by the other modules of the project. It is the first module in the project's five-module development plan.

## Contents

### Application Configuration
- **Application name:** Cyber Emergency Assistant
- **Version:** 1.1
- Detects the operating system using Python's `platform` module.
- Defines the base project directory and incident directory.

### OS-Specific Hosts File

The module automatically selects the appropriate hosts file:

- **Windows:** `C:\Windows\System32\drivers\etc\hosts`
- **Linux:** `/etc/hosts`

### Trusted DNS Servers

The project defines two trusted DNS servers:

- `1.1.1.1`
- `9.9.9.9`

### Brand Watch List

The configuration contains a list of commonly targeted brands and services, including:

- Google
- Gmail
- PayPal
- Amazon
- Apple
- Microsoft
- Netflix
- Facebook
- Instagram
- WhatsApp
- LinkedIn
- SBI
- HDFC Bank
- ICICI Bank
- Paytm
- PhonePe
- IRCTC

### Suspicious TLDs

The module maintains a list of domain extensions considered suspicious by the project's rule-based checks:

`xyz`, `tk`, `ml`, `ga`, `cf`, `gq`, `top`, `click`, `loan`

### Red-Flag Words

The following words are used as indicators when checking suspicious links:

`login`, `verify`, `secure`, `account`, `update`, `confirm`, `password`, `otp`, `kyc`, `urgent`, `suspended`, `prize`, `winner`

### Recovery Guidance

The module also stores recovery instructions that can be displayed after a cyber incident, including:

1. Stay calm and disconnect from the network.
2. Do not restart the computer immediately because running processes may provide useful evidence.
3. Change email and bank passwords from a trusted device.
4. Enable two-factor authentication.
5. Contact the bank if payment or net banking was involved.
6. Run a full scan using updated antivirus software.
7. Reconnect to the internet only after the scan is clean.
8. Keep the incident report for possible cybercrime complaints.

## Technologies Used

- Python 3
- `platform`
- `pathlib`

## Module Status

**Completed — Module 1 of 5**

`config.py` is the foundation configuration module. The remaining project modules will be added progressively during development.

## Planned Project Modules

| Module | File | Purpose | Status |
|---|---|---|---|
| 1 | `config.py` | Configuration and static security data | ✅ Completed |
| 2 | `security_utils.py` | Helper functions and URL/phishing checker | Planned |
| 3 | `evidence.py` | Evidence collection, hosts-file scan and SHA-256 sealing | Planned |
| 4 | `killswitch.py` | Network isolation, DNS reset and incident reporting | Planned |
| 5 | `main.py` | CLI, GUI and project entry point | Planned |

## Note

This module only contains configuration and static data. It does not independently perform the complete emergency-response workflow. Its values are intended to be imported and used by the other project modules.
