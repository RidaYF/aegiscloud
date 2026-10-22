"""
Adds the MITRE techniques needed by scenario 2 to mitre/techniques.json.

Run from the project root:
    python add_techniques.py
It copies the field layout of an existing entry (T1580) so the file stays consistent.
Verify names and descriptions at https://attack.mitre.org before the final report.
"""
import json
from pathlib import Path

PATH = Path("mitre") / "techniques.json"
NEW = {
    "T1069.003": {
        "name": "Permission Groups Discovery: Cloud Groups",
        "tactics": ["Discovery"],
        "summary": "Adversary lists cloud groups and roles to learn which permissions exist.",
        "url": "https://attack.mitre.org/techniques/T1069/003/",
    },
    "T1136.003": {
        "name": "Create Account: Cloud Account",
        "tactics": ["Persistence"],
        "summary": "Adversary creates a new cloud account to keep access to the environment.",
        "url": "https://attack.mitre.org/techniques/T1136/003/",
    },
    "T1098.003": {
        "name": "Account Manipulation: Additional Cloud Roles",
        "tactics": ["Persistence", "Privilege Escalation"],
        "summary": "Adversary attaches extra roles or policies to an account to gain more privileges.",
        "url": "https://attack.mitre.org/techniques/T1098/003/",
    },
    "T1098.001": {
        "name": "Account Manipulation: Additional Cloud Credentials",
        "tactics": ["Persistence"],
        "summary": "Adversary adds new keys or credentials to an account to keep access.",
        "url": "https://attack.mitre.org/techniques/T1098/001/",
    },
}


def main():
    data = json.loads(PATH.read_text(encoding="utf-8-sig"))
    template = data["T1580"]
    extra_keys = set(template) - {"name", "tactics", "summary", "url"}
    if extra_keys:
        raise SystemExit(f"T1580 has extra fields {sorted(extra_keys)}; "
                         "send me the first lines of techniques.json, nothing was changed.")
    added = [t for t in NEW if t not in data]
    for t in added:
        data[t] = NEW[t]
    PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Added: {added or 'nothing (already present)'}")
    print(f"Catalog now has {len(data)} techniques.")


if __name__ == "__main__":
    main()
