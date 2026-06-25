# MYSQL Fingerprint Library

This directory contains the MYSQL fingerprint library built from scanner
result JSON objects.

## Contents

- `mysql_fingerprints.json`: machine-readable fingerprint rules.
- `fingerprint_schema.json`: library format schema.
- `tools/match_mysql_fingerprints.py`: matcher for a single protocol-result JSON object.
- `tools/online_mysql_reprobe.py`: authorized online handshake reprobe and matcher.
- `reports/validation_report.md`: full-corpus and 10% holdout metrics.
- `reports/validation_report.json`: machine-readable validation metrics.
- `reports/online_reprobe_20260625.md`: sanitized online reprobe summary.

Raw scan corpora and raw IP lists are not committed.

## Current Evaluation

- full-corpus records: 422199
- 10% real-IP holdout records: 42220
- online pilot: 500 sampled IP:port targets from the random 10% sample pool,
  482 responded, 100% protocol/implementation/version match among responders.

The matcher expects one scanner `protocols[]` object as JSON input, not an entire
top-level scan report.
