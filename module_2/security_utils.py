"""
Cyber Emergency Assistant - shared helpers and phishing URL checker.

This module builds on the security data defined by Module 1.
"""

import socket
import subprocess
from datetime import datetime
from urllib.parse import urlparse

try:
    from module_1.config import BAD_TLDS, BRANDS, RED_FLAG_WORDS
except ModuleNotFoundError:
    # The GitHub repository keeps Module 1's config.py at its root.
    from config import BAD_TLDS, BRANDS, RED_FLAG_WORDS


def now():
    """Return the current local time in a report-friendly format."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run(cmd):
    """Run a system command safely and return its combined output."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        return (result.stdout or "") + (result.stderr or "")
    except FileNotFoundError:
        return f"[{cmd[0]} is not installed on this system]"
    except Exception as exc:
        return f"[could not run {cmd[0]}: {exc}]"


def edit_distance(a, b):
    """Calculate the Levenshtein edit distance between two strings."""
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))

    previous = list(range(len(b) + 1))
    for index_a, char_a in enumerate(a, 1):
        row = [index_a]
        for index_b, char_b in enumerate(b, 1):
            cost = 0 if char_a == char_b else 1
            row.append(
                min(
                    previous[index_b] + 1,
                    row[index_b - 1] + 1,
                    previous[index_b - 1] + cost,
                )
            )
        previous = row
    return previous[-1]


def check_url(raw_url):
    """Score a URL with local, explainable phishing heuristics."""
    url = raw_url.strip()
    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    lookup_host = host[4:] if host.startswith("www.") else host
    path_and_query = (parsed.path + "?" + (parsed.query or "")).lower()

    reasons = []
    score = 0

    if not host:
        return {
            "url": raw_url,
            "host": "",
            "score": 5,
            "level": "DANGEROUS",
            "reasons": ["this is not a valid web address"],
        }

    try:
        socket.inet_aton(host)
        score += 2
        reasons.append("goes directly to a raw IP address instead of a domain name")
    except OSError:
        pass

    tld = host.rsplit(".", 1)[-1]
    if tld in BAD_TLDS:
        score += 2
        reasons.append(f"uses '.{tld}', a domain ending often abused by phishing sites")

    core = lookup_host.split(".")[0].replace("-", "")
    for brand in BRANDS:
        if core == brand:
            break
        if len(brand) >= 5 and edit_distance(core, brand) == 1:
            score += 3
            reasons.append(f"looks like a misspelled '{brand}' website ({host})")
            break
        if brand in lookup_host and not lookup_host.startswith(brand):
            score += 2
            reasons.append(f"mentions '{brand}', but the actual host is '{host}'")
            break

    hits = [
        word
        for word in RED_FLAG_WORDS
        if word in path_and_query or word in host
    ]
    if hits:
        score += min(2, len(hits))
        reasons.append("uses urgent or login-related words: " + ", ".join(hits[:4]))

    if parsed.scheme != "https":
        score += 1
        reasons.append("does not use HTTPS")

    if len(url) > 100:
        score += 1
        reasons.append("uses a very long link that may hide its destination")

    if score >= 5:
        level = "DANGEROUS"
    elif score >= 2:
        level = "SUSPICIOUS"
    else:
        level = "SAFE"

    return {
        "url": raw_url,
        "host": host,
        "score": score,
        "level": level,
        "reasons": reasons,
    }


def format_url_result(result):
    """Convert a URL scan result into readable terminal output."""
    heading = (
        f"{result['level']} (score {result['score']}) - {result['url']}"
    )
    if not result["reasons"]:
        return heading + "\n   no risk indicators found"
    details = "\n".join(f"   - {reason}" for reason in result["reasons"])
    return heading + "\n" + details
