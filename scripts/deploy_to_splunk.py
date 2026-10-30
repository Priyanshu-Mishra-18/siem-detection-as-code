"""
Deploy Sigma correlation rules to Splunk as scheduled alerts.

For every Sigma correlation rule in detections/rules/:
  1. convert it to SPL with pySigma,
  2. prefix the index to search,
  3. create the matching saved search (alert) in Splunk through the REST API,
     or update it if it already exists.

Usage (from the repository root, with the venv active):
    python scripts/deploy_to_splunk.py --dry-run   # show what would be deployed
    python scripts/deploy_to_splunk.py             # deploy for real

Connection settings come from the .env file (never hard-coded here):
    SPLUNK_PASSWORD   required
    SPLUNK_URL        optional, default https://localhost:8089
    SPLUNK_USER       optional, default admin
    SPLUNK_INDEX      optional, default lab_security
"""

import argparse
import sys
from pathlib import Path

import requests
import urllib3
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "detections" / "rules"
ENV_FILE = REPO_ROOT / ".env"

# Sigma level -> Splunk alert severity (the number behind the UI label)
SEVERITY = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

# Every deployed alert gets this prefix, so you can tell
# code-managed alerts apart from ones created by hand in the UI.
NAME_PREFIX = "Sigma - "


def load_env(path: Path) -> dict:
    """Read KEY=VALUE lines from the .env file."""
    if not path.exists():
        sys.exit(f"ERROR: {path} not found. Create it first (see README).")
    env = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip()
    return env


def build_alerts(index: str) -> list[dict]:
    """Convert every correlation rule into the settings of one Splunk alert."""
    collection = SigmaCollection.load_ruleset([RULES_DIR])
    alerts = []
    for rule in collection.rules:
        if not isinstance(rule, SigmaCorrelationRule):
            continue  # base rules are only building blocks

        # Convert the correlation rule together with the rules it references
        referenced = [ref.rule for ref in rule.rules]
        spl = SplunkBackend().convert(SigmaCollection([*referenced, rule]))[0]
        spl = f"index={index} {spl}"

        timespan = rule.timespan.spec  # e.g. "15m"
        level = rule.level.name.lower() if rule.level else "medium"

        alerts.append({
            "name": f"{NAME_PREFIX}{rule.title}",
            "params": {
                "search": spl,
                "description": f"{rule.description.strip()} (Sigma id: {rule.id})",
                # Schedule: run every <timespan>, looking back exactly <timespan>
                "is_scheduled": "1",
                "cron_schedule": f"*/{rule.timespan.count} * * * *"
                if rule.timespan.unit == "m" else "*/15 * * * *",
                "dispatch.earliest_time": f"-{timespan}",
                "dispatch.latest_time": "now",
                # Trigger when the search returns any result, once per result
                "alert_type": "number of events",
                "alert_comparator": "greater than",
                "alert_threshold": "0",
                "alert.digest_mode": "0",
                # Show it under Activity > Triggered Alerts
                "alert.track": "1",
                "alert.severity": str(SEVERITY.get(level, 3)),
                # Throttle repeats from the same entity for an hour
                "alert.suppress": "1",
                "alert.suppress.fields": ",".join(rule.group_by or []),
                "alert.suppress.period": "60m",
            },
        })
    return alerts


def deploy(alert: dict, base_url: str, auth: tuple) -> None:
    """Create the alert, or update it if it already exists."""
    collection_url = f"{base_url}/servicesNS/nobody/search/saved/searches"
    entity_url = f"{collection_url}/{requests.utils.quote(alert['name'], safe='')}"
    common = {"auth": auth, "verify": False, "timeout": 30}

    exists = requests.get(entity_url, params={"output_mode": "json"}, **common)
    if exists.status_code == 200:
        resp = requests.post(entity_url, data=alert["params"], **common)
        action = "Updated"
    elif exists.status_code == 404:
        resp = requests.post(collection_url, data={"name": alert["name"], **alert["params"]}, **common)
        action = "Created"
    else:
        sys.exit(f"ERROR checking '{alert['name']}': HTTP {exists.status_code} {exists.text[:300]}")

    if resp.status_code not in (200, 201):
        sys.exit(f"ERROR deploying '{alert['name']}': HTTP {resp.status_code} {resp.text[:300]}")
    print(f"{action}: {alert['name']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--dry-run", action="store_true",
                        help="print the alerts without contacting Splunk")
    args = parser.parse_args()

    env = load_env(ENV_FILE)
    index = env.get("SPLUNK_INDEX", "lab_security")
    alerts = build_alerts(index)
    print(f"Found {len(alerts)} correlation rule(s) in {RULES_DIR.relative_to(REPO_ROOT)}")

    if args.dry_run:
        for a in alerts:
            print(f"\n=== {a['name']} ===")
            for key, value in a["params"].items():
                print(f"  {key}: {value}")
        print("\nDry run: nothing was sent to Splunk.")
        return

    if "SPLUNK_PASSWORD" not in env:
        sys.exit("ERROR: SPLUNK_PASSWORD missing from .env")
    # Lab only: Splunk uses a self-signed certificate, so skip verification.
    # In production, point verify= at the CA certificate instead.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    base_url = env.get("SPLUNK_URL", "https://localhost:8089").rstrip("/")
    auth = (env.get("SPLUNK_USER", "admin"), env["SPLUNK_PASSWORD"])
    for a in alerts:
        deploy(a, base_url, auth)
    print("Done.")


if __name__ == "__main__":
    main()
