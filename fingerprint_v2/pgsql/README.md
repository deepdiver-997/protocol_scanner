# PGSQL Fingerprint Library

This directory contains the PGSQL fingerprint library built from scanner
result JSON objects.

## Contents

- `pgsql_fingerprints.json`: machine-readable fingerprint rules.
- `fingerprint_schema.json`: library format schema.
- `tools/match_pgsql_fingerprints.py`: matcher for a single protocol-result JSON object.
- `tools/online_pgsql_reprobe.py`: authorized online SSLRequest/startup reprobe and matcher.
- `reports/validation_report.md`: full-corpus and 10% holdout metrics.
- `reports/validation_report.json`: machine-readable validation metrics.
- `reports/online_reprobe_20260625.md`: sanitized online reprobe summary.
- `reports/sqlstate_gap_analysis_20260625.md`: SQLSTATE miss composition.

Raw scan corpora and raw IP lists are not committed.

## Current Evaluation

- full-corpus records: 2053
- 10% real-IP holdout records: 205
- online 10% reprobe: 205 sampled IP:port targets, 189 responded, 100%
  protocol match among responders.
- SQLSTATE gap: 294 / 2053 records have no SQLSTATE; most are empty or
  non-ErrorResponse payloads, so 85.68% is near the useful ceiling for this corpus.

The matcher expects one scanner `protocols[]` object as JSON input, not an entire
top-level scan report.
