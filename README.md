# SIEM Detection-as-Code Lab

A local lab for building, testing and automating security detections with
**Cribl Stream** (data pipeline) and **Splunk Enterprise** (SIEM), using
**Sigma** rules stored in Git.

## Architecture

```
Datagen (Palo Alto traffic) -> Cribl Stream -> Splunk HEC -> index=lab_security
                               (parse, CIM-normalize, reduce _raw)
```

- Cribl pipeline `pan_traffic_parse`: parses Palo Alto CSV, keeps 15 analyst
  fields, renames to Splunk CIM, rebuilds `_raw` as key=value.
  Result on sample data: `_raw` size reduced ~44% with zero event loss.
- Detections are written as Sigma rules in `detections/rules/` and converted
  to SPL with `sigma-cli`.

## Prerequisites

- Docker Desktop (8 GB RAM free recommended)
- Python 3.10+ (for `sigma-cli`)

## Setup

1. Create a `.env` file next to `docker-compose.yml` (it is git-ignored):

   ```
   SPLUNK_PASSWORD=<choose-a-strong-password>
   SPLUNK_HEC_TOKEN=<a-uuid-for-the-hec-token>
   ```

2. Start the lab:

   ```
   docker compose up -d
   ```

3. Open the UIs:
   - Splunk Web: http://localhost:8000 (user `admin`, password from `.env`)
   - Cribl Stream: http://localhost:9000

## Detections

| Rule | ATT&CK | RBA score | Description |
|------|--------|-----------|-------------|
| `detections/rules/network/net_vertical_port_scan.yml` | T1046 | 40 | One source IP hitting >20 distinct destination ports within 15 minutes |
| `detections/rules/network/net_inbound_admin_port.yml` | T1133 | 30 | Internet host gets an allowed connection to SSH (22) or RDP (3389) |

Convert to SPL:

```
pip install sigma-cli pysigma-backend-splunk
sigma check detections/rules/
sigma convert -t splunk --without-pipeline detections/rules/
```

## Risk-Based Alerting (RBA)

Instead of alerting on every suspicious behaviour, detections add **risk
points** to the entity involved (here: the source IP) in a dedicated risk
index. One risk alert fires only when an entity's total risk crosses a
threshold, so analysts get one alert that tells the whole story instead of
many noisy ones.

```
Sigma rule (rba block) -> risk report (every 15 min) -> index=lab_risk
                                                            |
               RBA - Risk Threshold Exceeded - Alert  <-----+
               (sum of risk >= 100 over 7 days, runs 5 min after the reports)
```

Each Sigma rule opts in with an `rba:` block:

```yaml
rba:
    score: 40
    object_type: system
    message: "Vertical port scan: {value_count} distinct ports in 15 minutes"
```

Design decisions:

- **No double counting:** each risk report runs every 15 minutes over exactly
  the last 15 minutes, so every time slice is scored once.
- **Ordering:** the risk alert runs 5 minutes after the reports, so it reads
  points that have just been written.
- **7-day window:** catches attackers who spread activity over several days.
- **Stable identity:** every risk entry carries `risk_rule_id` (the Sigma rule
  id), so renaming a detection never breaks the distinct-detection count.
  `search_name` is left to Splunk (it is set to the writing report's name).
- **Throttling:** one alert per risk object per 24 hours.

## Deploy to Splunk

`scripts/deploy_to_splunk.py` builds everything from the Sigma rules and
deploys it through Splunk's REST API on port 8089:

- the event and risk indexes (created only if missing),
- a **risk report** for each rule with an `rba:` block,
- a **direct alert** for each rule without one,
- the **risk alert**.

Settings are derived from the rule: `timespan` sets the schedule and search
window, `group-by` the risk object, `tags` the ATT&CK technique, `level` the
severity of direct alerts. It reads credentials from `.env` and is idempotent
(create or update, at the app level), so the whole engine can be rebuilt with
one command.

```
python scripts/deploy_to_splunk.py --dry-run   # preview
python scripts/deploy_to_splunk.py             # deploy
```

## CI

GitHub Actions (`.github/workflows/sigma-ci.yml`) validates every rule with
`sigma check --fail-on-issues` and converts it to SPL on each push that
touches `detections/`. A broken rule fails the build before any SPL is
generated.

## Security notes

- Secrets live only in `.env`, which is excluded by `.gitignore`.
- The lab disables TLS certificate validation between Cribl and Splunk because
  Splunk uses a self-signed certificate. In production, use a CA-signed
  certificate and keep validation on.
