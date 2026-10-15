"""Module 3: evidence collection, hosts-file scanning, and integrity checks."""

from .evidence import (
    check_hosts_file,
    collect_evidence,
    hash_evidence,
    verify_evidence,
)

__all__ = [
    "check_hosts_file",
    "collect_evidence",
    "hash_evidence",
    "verify_evidence",
]
