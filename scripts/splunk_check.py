"""
Read-only connectivity check for Splunk's REST API (port 8089).

It does two things and changes nothing:
  1. Reads server info (version, license state).
  2. Runs one small search ("oneshot") and prints the result count.

The AI agent in Module 8 uses this same REST access, so this check proves the
agent will be able to search Splunk.

Usage (from the repository root, with the venv active):
    python scripts/splunk_check.py
"""

import sys
from pathlib import Path

import requests
import urllib3

ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


def load_env(path: Path) -> dict:
    if not path.exists():
        sys.exit(f"ERROR: {path} not found.")
    env = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip()
    return env


def main() -> None:
    env = load_env(ENV_FILE)
    # Lab only: Splunk uses a self-signed certificate.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    base = env.get("SPLUNK_URL", "https://localhost:8089").rstrip("/")
    common = {"auth": (env.get("SPLUNK_USER", "admin"), env.get("SPLUNK_PASSWORD", "")),
              "verify": False, "timeout": 60}

    # 1. Server info
    r = requests.get(f"{base}/services/server/info", params={"output_mode": "json"}, **common)
    print(f"server/info: HTTP {r.status_code}")
    if r.status_code != 200:
        sys.exit(r.text[:300])
    content = r.json()["entry"][0]["content"]
    print(f"  version:       {content.get('version')}")
    print(f"  license state: {content.get('licenseState')}")
    print(f"  is free:       {content.get('isFree')}")

    # 2. One small search (read-only)
    index = env.get("SPLUNK_INDEX", "lab_security")
    r = requests.post(f"{base}/services/search/jobs",
                      data={"search": f"search index={index} earliest=-15m | stats count",
                            "exec_mode": "oneshot", "output_mode": "json"},
                      **common)
    print(f"search (oneshot): HTTP {r.status_code}")
    if r.status_code != 200:
        sys.exit(r.text[:300])
    results = r.json().get("results", [])
    print(f"  events in {index} (last 15 min): {results[0]['count'] if results else 0}")
    print("OK: the REST API is reachable and searches work.")


if __name__ == "__main__":
    main()
