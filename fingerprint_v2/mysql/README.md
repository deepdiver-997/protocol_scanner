# MYSQL Fingerprint Library

This directory contains the MYSQL fingerprint library built from scanner
result JSON objects.

## Contents

- `mysql_fingerprints.json`: machine-readable fingerprint rules.
- `fingerprint_schema.json`: library format schema.
- `tools/match_mysql_fingerprints.py`: matcher for a single protocol-result JSON object.
- `reports/validation_report.md`: full-corpus and 10% holdout metrics.
- `reports/validation_report.json`: machine-readable validation metrics.

Raw scan corpora and raw IP lists are not committed.

## Current Evaluation

- full-corpus records: 422199
- 10% real-IP holdout records: 42220

The matcher expects one scanner `protocols[]` object as JSON input, not an entire
top-level scan report.
