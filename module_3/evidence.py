"""Evidence collection, hosts-file analysis, and SHA-256 integrity checks."""

import hashlib
from pathlib import Path

try:
    from module_1.config import BRANDS, HOSTS_FILE, OS_NAME
except ModuleNotFoundError:
    # The GitHub repository keeps Module 1's config.py at its root.
    from config import BRANDS, HOSTS_FILE, OS_NAME

try:
    from module_2.security_utils import run
except ModuleNotFoundError:
    # This fallback supports the final combined application layout.
    from security_utils import run


EVIDENCE_COMMANDS = {
    "Linux": {
        "processes.txt": ["ps", "aux"],
        "network_connections.txt": ["ss", "-tunap"],
        "network_interfaces.txt": ["ip", "-br", "addr"],
        "logged_in_users.txt": ["who"],
    },
    "Windows": {
        "processes.txt": ["tasklist"],
        "network_connections.txt": ["netstat", "-ano"],
        "network_interfaces.txt": ["ipconfig", "/all"],
        "logged_in_users.txt": ["query", "user"],
    },
}

HOSTS_WATCH_LIST = BRANDS + [
    "windowsupdate",
    "avast",
    "norton",
    "defender",
    "malwarebytes",
]

MANIFEST_NAME = "MANIFEST.sha256"


def collect_evidence(folder, os_name=OS_NAME, hosts_file=HOSTS_FILE, command_runner=run):
    """Collect a small, read-only system snapshot into an evidence directory."""
    evidence_folder = Path(folder)
    evidence_folder.mkdir(parents=True, exist_ok=True)
    collected = []

    for filename, command in EVIDENCE_COMMANDS.get(os_name, {}).items():
        output = command_runner(command)
        (evidence_folder / filename).write_text(
            output,
            encoding="utf-8",
            errors="replace",
        )
        collected.append(filename)

    source_hosts = Path(hosts_file)
    if source_hosts.exists():
        try:
            hosts_content = source_hosts.read_text(encoding="utf-8", errors="replace")
            hosts_copy = evidence_folder / "hosts_file_copy.txt"
            hosts_copy.write_text(hosts_content, encoding="utf-8")
            collected.append(hosts_copy.name)
        except OSError:
            pass

    return collected


def check_hosts_file(hosts_file=HOSTS_FILE):
    """Return redirects involving commonly targeted brands and security services."""
    source_hosts = Path(hosts_file)
    if not source_hosts.exists():
        return []

    try:
        lines = source_hosts.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    findings = []
    for line_number, line in enumerate(lines, 1):
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue

        parts = entry.split()
        if len(parts) < 2:
            continue

        address, hostnames = parts[0], parts[1:]
        for hostname in hostnames:
            normalized = hostname.lower().rstrip(".")
            if any(keyword in normalized for keyword in HOSTS_WATCH_LIST):
                findings.append(
                    f"line {line_number}: {hostname} is redirected to {address}"
                )

    return findings


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_evidence(folder):
    """Hash every evidence file and write a sha256sum-compatible manifest."""
    evidence_folder = Path(folder)
    if not evidence_folder.exists():
        return {}

    hashes = {}
    for evidence_file in sorted(evidence_folder.iterdir()):
        if evidence_file.is_file() and evidence_file.name != MANIFEST_NAME:
            hashes[evidence_file.name] = _sha256(evidence_file)

    manifest = evidence_folder / MANIFEST_NAME
    lines = [f"{digest}  {filename}" for filename, digest in hashes.items()]
    manifest.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return hashes


def verify_evidence(folder):
    """Verify evidence against its manifest and return results by filename."""
    evidence_folder = Path(folder)
    manifest = evidence_folder / MANIFEST_NAME
    if not manifest.exists():
        return {}

    results = {}
    for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue

        try:
            expected, filename = line.split(maxsplit=1)
        except ValueError:
            results[f"invalid manifest line: {line}"] = False
            continue

        filename = filename.lstrip("* ")
        evidence_file = evidence_folder / filename
        results[filename] = (
            evidence_file.is_file() and _sha256(evidence_file) == expected.lower()
        )

    return results
