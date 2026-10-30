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

| Rule | ATT&CK | Description |
|------|--------|-------------|
| `detections/rules/network/net_vertical_port_scan.yml` | T1046 | One source IP hitting >20 distinct destination ports within 15 minutes |

Convert to SPL:

```
pip install sigma-cli pysigma-backend-splunk
sigma check detections/rules/
sigma convert -t splunk --without-pipeline detections/rules/
```

## Deploy to Splunk

`scripts/deploy_to_splunk.py` converts every Sigma correlation rule and
creates (or updates) the matching scheduled alert through Splunk's REST API
on port 8089. Alert settings are derived from the rule: `timespan` sets the
schedule and search window, `level` sets the severity, `group-by` sets the
throttling field. It reads credentials from `.env` and is idempotent.

```
python scripts/deploy_to_splunk.py --dry-run   # preview
python scripts/deploy_to_splunk.py             # deploy
```

Deployed alerts are prefixed `Sigma - ` to separate code-managed alerts from
manual ones.

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
