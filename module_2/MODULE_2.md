# Cyber Emergency Assistant - Module 2

## Module 2: `security_utils.py`

This module contains shared helper functions and the project's rule-based phishing URL checker.

## Purpose

Module 2 converts the static security information from Module 1 into explainable URL risk decisions. It is designed to help non-technical users understand why a link may be unsafe without uploading their browsing data to a third-party service.

## URL Analysis Workflow

1. Normalize the supplied address.
2. Parse and validate its hostname.
3. Check whether it uses a raw IP address.
4. Compare its top-level domain with the suspicious-TLD list.
5. Compare its hostname with commonly impersonated brands.
6. Search for urgent and credential-related words.
7. Check HTTPS usage and URL length.
8. Return a score, classification, and list of reasons.

## Risk Levels

| Score | Classification | Meaning |
|---:|---|---|
| 0-1 | `SAFE` | No major heuristic indicators detected |
| 2-4 | `SUSPICIOUS` | The user should verify the destination carefully |
| 5+ | `DANGEROUS` | Multiple or high-risk phishing indicators detected |

These classifications are heuristic warnings, not guarantees that a site is safe or malicious.

## Helper Functions

- `now()` creates consistent report timestamps.
- `run()` executes a fixed command supplied by another project module and captures its output.
- `edit_distance()` detects small spelling differences in brand names.
- `check_url()` returns the structured URL risk result.
- `format_url_result()` produces readable CLI and GUI output.

## Privacy And Safety

- URL analysis is performed locally.
- The module does not download website content.
- The module does not visit a supplied URL.
- The module does not transmit URLs to an external API.
- System command execution has a 15-second timeout and captures failures as output.

## Technologies Used

- Python 3
- `urllib.parse`
- `socket`
- `subprocess`
- `datetime`
- `unittest`

## Module Status

**Completed - Module 2 of 5**

## Project Progress

| Module | File | Purpose | Status |
|---|---|---|---|
| 1 | `config.py` | Configuration and static security data | Completed |
| 2 | `security_utils.py` | Helper functions and URL/phishing checker | Completed |
| 3 | `evidence.py` | Evidence collection, hosts-file scan and SHA-256 sealing | Planned |
| 4 | `killswitch.py` | Network isolation, DNS reset and incident reporting | Planned |
| 5 | `main.py` | CLI, GUI and project entry point | Planned |

## Limitations

- Rule-based scoring can produce false positives and false negatives.
- The module does not use domain reputation, certificate, redirect, or domain-age data.
- The brand comparison is intentionally simple and is not a replacement for a full threat-intelligence system.
