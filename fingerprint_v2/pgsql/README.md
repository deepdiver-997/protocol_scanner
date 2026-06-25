# PGSQL Fingerprint Library

This directory contains the PGSQL fingerprint library built from scanner
result JSON objects.

## Contents

- `pgsql_fingerprints.json`: machine-readable fingerprint rules.
- `fingerprint_schema.json`: library format schema.
- `tools/match_pgsql_fingerprints.py`: matcher for a single protocol-result JSON object.
- `reports/validation_report.md`: full-corpus and 10% holdout metrics.
- `reports/validation_report.json`: machine-readable validation metrics.

Raw scan corpora and raw IP lists are not committed.

## Current Evaluation

- full-corpus records: 2053
- 10% real-IP holdout records: 205

The matcher expects one scanner `protocols[]` object as JSON input, not an entire
top-level scan report.
