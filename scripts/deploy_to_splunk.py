"""
Deploy Sigma detections and the Risk-Based Alerting (RBA) engine to Splunk.

What it deploys, through Splunk's REST API:
  1. Indexes: the event index and the risk index (created only if missing).
  2. One scheduled search per Sigma correlation rule in detections/rules/:
       - rule HAS an `rba:` block  -> risk report: writes risk points to the risk index
       - rule has NO `rba:` block  -> direct alert (the Module 5 behaviour)
  3. The risk alert: fires when one risk object's total risk crosses the threshold.

Every item is created if new, or updated if it exists, so running the script
again is always safe (idempotent).

Usage (from the repository root, with the venv active):
    python scripts/deploy_to_splunk.py --dry-run   # show what would be deployed
    python scripts/deploy_to_splunk.py             # deploy for real

Settings come from the .env file (never hard-coded here):
    SPLUNK_PASSWORD     required
    SPLUNK_URL          optional, default https://localhost:8089
    SPLUNK_USER         optional, default admin
    SPLUNK_INDEX        optional, default lab_security
    SPLUNK_RISK_INDEX   optional, default lab_risk
"""

import argparse
import re
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

# Risk alert settings
RISK_THRESHOLD = 100          # alert when an object's total risk reaches this
RISK_WINDOW = "-7d"           # how far back to add up risk points
RISK_ALERT_CRON = "5,20,35,50 * * * *"   # 5 minutes after the risk reports run
RISK_ALERT_NAME = "RBA - Risk Threshold Exceeded - Alert"

# Index sizes in MB, used only when an index has to be created
INDEX_SIZES_MB = {"event": 5120, "risk": 1024}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

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


def cron_for(timespan) -> str:
    """Run every <timespan>: 15m -> */15 * * * *, 1h -> 0 */1 * * *."""
    if timespan.unit == "m" and 60 % timespan.count == 0:
        return f"*/{timespan.count} * * * *"
    if timespan.unit == "h" and 24 % timespan.count == 0:
        return f"0 */{timespan.count} * * *"
    sys.exit(f"ERROR: unsupported timespan {timespan.spec}; use minutes dividing 60 or hours dividing 24")


def message_to_spl(template: str) -> str:
    """Turn 'Scan of {value_count} ports' into: "Scan of " . value_count . " ports" """
    parts = re.split(r"\{(\w+)\}", template)
    pieces = []
    for i, part in enumerate(parts):
        if i % 2 == 1:                      # odd positions are field names
            pieces.append(part)
        elif part:                          # even positions are literal text
            pieces.append('"' + part.replace('"', '\\"') + '"')
    return " . ".join(pieces)


def mitre_techniques(rule) -> str:
    """attack.t1046 -> T1046 (comma-separated if several)."""
    ids = [t.name.upper() for t in rule.tags
           if t.namespace == "attack" and re.fullmatch(r"t\d{4}(\.\d{3})?", t.name)]
    return ",".join(ids) or "none"


# --------------------------------------------------------------------------
# Build the saved searches from the Sigma rules
# --------------------------------------------------------------------------

def build_from_rules(event_index: str, risk_index: str) -> list[dict]:
    collection = SigmaCollection.load_ruleset([RULES_DIR])
    items = []
    for rule in collection.rules:
        if not isinstance(rule, SigmaCorrelationRule):
            continue  # base rules are only building blocks

        referenced = [ref.rule for ref in rule.rules]
        spl = SplunkBackend().convert(SigmaCollection([*referenced, rule]))[0]
        spl = f"index={event_index} {spl}"

        timespan = rule.timespan
        level = rule.level.name.lower() if rule.level else "medium"
        description = f"{rule.description.strip()} (Sigma id: {rule.id})"
        schedule = {
            "is_scheduled": "1",
            "cron_schedule": cron_for(timespan),
            "dispatch.earliest_time": f"-{timespan.spec}",   # look back exactly one run
            "dispatch.latest_time": "now",
        }
        rba = rule.custom_attributes.get("rba")

        if rba:
            # Risk report: write risk points instead of alerting
            if not rule.group_by:
                sys.exit(f"ERROR: '{rule.title}' has an rba block but no group-by field")
            risk_spl = (
                f"{spl}\n"
                f"| eval risk_object={rule.group_by[0]}, "
                f"risk_object_type=\"{rba.get('object_type', 'system')}\", "
                f"risk_score={int(rba['score'])}, "
                f"mitre_technique=\"{mitre_techniques(rule)}\", "
                f"risk_rule_id=\"{rule.id}\", "
                f"risk_message={message_to_spl(rba['message'])}\n"
                f"| table _time risk_object risk_object_type risk_score risk_message mitre_technique risk_rule_id\n"
                f"| collect index={risk_index}"
            )
            # No search_name here on purpose: Splunk fills it with this report's name.
            # risk_rule_id is the Sigma rule id: it never changes, even if the title does.
            items.append({
                "name": f"RBA - {rule.title}",
                "kind": "risk report",
                "params": {"search": risk_spl, "description": description, **schedule,
                           "alert.track": "0"},
            })
        else:
            # Direct alert (Module 5 behaviour)
            items.append({
                "name": f"Sigma - {rule.title}",
                "kind": "direct alert",
                "params": {
                    "search": spl, "description": description, **schedule,
                    "alert_type": "number of events",
                    "alert_comparator": "greater than",
                    "alert_threshold": "0",
                    "alert.digest_mode": "0",
                    "alert.track": "1",
                    "alert.severity": str(SEVERITY.get(level, 3)),
                    "alert.suppress": "1",
                    "alert.suppress.fields": ",".join(rule.group_by or []),
                    "alert.suppress.period": "60m",
                },
            })
    return items


def build_risk_alert(risk_index: str) -> dict:
    search = (
        f"index={risk_index}\n"
        f"| eval rule_key=coalesce(risk_rule_id, search_name)\n"
        f"| stats sum(risk_score) AS total_risk,\n"
        f"        dc(rule_key) AS distinct_detections,\n"
        f"        values(search_name) AS detections,\n"
        f"        values(risk_message) AS what_happened,\n"
        f"        values(mitre_technique) AS techniques,\n"
        f"        min(_time) AS first_seen, max(_time) AS last_seen\n"
        f"  BY risk_object\n"
        f"| where total_risk >= {RISK_THRESHOLD}\n"
        f"| convert ctime(first_seen) ctime(last_seen)"
    )
    return {
        "name": RISK_ALERT_NAME,
        "kind": "risk alert",
        "params": {
            "search": search,
            "description": f"Risk object reached {RISK_THRESHOLD}+ total risk in {RISK_WINDOW[1:]}.",
            "is_scheduled": "1",
            "cron_schedule": RISK_ALERT_CRON,
            "dispatch.earliest_time": RISK_WINDOW,
            "dispatch.latest_time": "now",
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "alert.digest_mode": "0",
            "alert.track": "1",
            "alert.severity": "4",
            "alert.suppress": "1",
            "alert.suppress.fields": "risk_object",
            "alert.suppress.period": "24h",
        },
    }


# --------------------------------------------------------------------------
# Talk to Splunk
# --------------------------------------------------------------------------

def ensure_index(name: str, max_mb: int, base_url: str, common: dict) -> None:
    url = f"{base_url}/servicesNS/nobody/search/data/indexes"
    check = requests.get(f"{url}/{name}", params={"output_mode": "json"}, **common)
    if check.status_code == 200:
        print(f"Index exists: {name}")
        return
    if check.status_code != 404:
        sys.exit(f"ERROR checking index '{name}': HTTP {check.status_code} {check.text[:300]}")
    resp = requests.post(url, data={"name": name, "maxTotalDataSizeMB": str(max_mb)}, **common)
    if resp.status_code not in (200, 201):
        sys.exit(f"ERROR creating index '{name}': HTTP {resp.status_code} {resp.text[:300]}")
    print(f"Index created: {name} ({max_mb} MB max)")


def deploy(item: dict, base_url: str, common: dict) -> None:
    """Create the saved search, or update it if it already exists."""
    collection_url = f"{base_url}/servicesNS/nobody/search/saved/searches"
    entity_url = f"{collection_url}/{requests.utils.quote(item['name'], safe='')}"

    exists = requests.get(entity_url, params={"output_mode": "json"}, **common)
    if exists.status_code == 200:
        resp = requests.post(entity_url, data=item["params"], **common)
        action = "Updated"
    elif exists.status_code == 404:
        resp = requests.post(collection_url, data={"name": item["name"], **item["params"]}, **common)
        action = "Created"
    else:
        sys.exit(f"ERROR checking '{item['name']}': HTTP {exists.status_code} {exists.text[:300]}")

    if resp.status_code not in (200, 201):
        sys.exit(f"ERROR deploying '{item['name']}': HTTP {resp.status_code} {resp.text[:300]}")
    print(f"{action} {item['kind']}: {item['name']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Deploy Sigma detections and RBA to Splunk.")
    parser.add_argument("--dry-run", action="store_true",
                        help="print what would be deployed without contacting Splunk")
    args = parser.parse_args()

    env = load_env(ENV_FILE)
    event_index = env.get("SPLUNK_INDEX", "lab_security")
    risk_index = env.get("SPLUNK_RISK_INDEX", "lab_risk")

    items = build_from_rules(event_index, risk_index)
    if any(i["kind"] == "risk report" for i in items):
        items.append(build_risk_alert(risk_index))

    print(f"Indexes: {event_index}, {risk_index}")
    print(f"Saved searches: {len(items)}")

    if args.dry_run:
        for item in items:
            print(f"\n=== [{item['kind']}] {item['name']} ===")
            for key, value in item["params"].items():
                print(f"  {key}: {value}")
        print("\nDry run: nothing was sent to Splunk.")
        return

    if "SPLUNK_PASSWORD" not in env:
        sys.exit("ERROR: SPLUNK_PASSWORD missing from .env")
    # Lab only: Splunk uses a self-signed certificate, so skip verification.
    # In production, point verify= at the CA certificate instead.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    base_url = env.get("SPLUNK_URL", "https://localhost:8089").rstrip("/")
    common = {"auth": (env.get("SPLUNK_USER", "admin"), env["SPLUNK_PASSWORD"]),
              "verify": False, "timeout": 30}

    ensure_index(event_index, INDEX_SIZES_MB["event"], base_url, common)
    ensure_index(risk_index, INDEX_SIZES_MB["risk"], base_url, common)
    for item in items:
        deploy(item, base_url, common)
    print("Done.")


if __name__ == "__main__":
    main()
