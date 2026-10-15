# Cyber Emergency Assistant - Module 3

## Module 3: `evidence.py`

This module handles read-only system evidence collection, hosts-file analysis, SHA-256 sealing, and integrity verification.

## Purpose

During a suspected cyber incident, volatile information such as running processes and active network connections can disappear after shutdown or restart. Module 3 preserves a small snapshot before Module 4 performs containment actions.

## Evidence Collected

### Linux

- Running processes using `ps aux`
- Network connections using `ss -tunap`
- Network interfaces using `ip -br addr`
- Logged-in users using `who`
- A copy of `/etc/hosts`

### Windows

- Running processes using `tasklist`
- Network connections using `netstat -ano`
- Network configuration using `ipconfig /all`
- Logged-in users using `query user`
- A copy of the Windows hosts file

## Hosts-File Detection

The hosts file is checked for redirects involving brands from Module 1 and common security services. Comments and empty lines are ignored. Findings include the original line number, hostname, and destination address.

## Evidence Integrity

Each evidence file is processed with SHA-256. The resulting digests are stored in `MANIFEST.sha256`. The manifest can later be verified to detect missing or modified files.

The manifest provides tamper detection, but it is not a digital signature and does not prove that the original machine data was trustworthy.

## Safety

- Collection commands are read-only.
- The system hosts file is copied, never modified.
- Tests use temporary files and simulated command output.
- Evidence remains on the local machine.

## Module Status

**Completed - Module 3 of 5**

## Project Progress

| Module | File | Purpose | Status |
|---|---|---|---|
| 1 | `config.py` | Configuration and static security data | Completed |
| 2 | `security_utils.py` | Helper functions and URL/phishing checker | Completed |
| 3 | `evidence.py` | Evidence collection, hosts-file scan and SHA-256 sealing | Completed |
| 4 | `killswitch.py` | Network isolation, DNS reset and incident reporting | Planned |
| 5 | `main.py` | CLI, GUI and project entry point | Planned |

## Limitations

- Command availability and output vary by operating system.
- Administrator privileges may be required for complete network details.
- Hosts-file detection is rule-based and can produce false positives.
- Local SHA-256 manifests are not equivalent to signed forensic chain-of-custody records.
