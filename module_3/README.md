# Cyber Emergency Assistant - Module 3

Module 3 collects read-only system evidence, checks the hosts file for suspicious redirects, and protects evidence integrity with SHA-256 hashes.

## Features

- Collects processes, network connections, interfaces, and logged-in users.
- Supports Linux and Windows command sets.
- Preserves a copy of the system hosts file.
- Detects redirects involving watched brands and security services.
- Creates a `MANIFEST.sha256` evidence manifest.
- Verifies evidence against a previously generated manifest.
- Uses only the Python standard library.

## Dependencies

- Module 1 supplies OS, hosts-file, and brand configuration.
- Module 2 supplies the safe command runner.

## Run The Tests

From the project directory containing `module_1`, `module_2`, and `module_3`:

```bash
python -m unittest module_3.test_evidence -v
```

The tests use temporary files and simulated command output. They do not read or modify the real system hosts file.

## Example

```python
from module_3 import collect_evidence, hash_evidence, verify_evidence

collect_evidence("incidents/demo/evidence")
hash_evidence("incidents/demo/evidence")
print(verify_evidence("incidents/demo/evidence"))
```

Evidence can contain sensitive system information. Generated incident directories should not be committed to a public repository.
