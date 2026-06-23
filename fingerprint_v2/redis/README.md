# Redis Fingerprint Library

This directory contains the Redis / Redis-compatible fingerprint library built
from the provided REDIS scan corpus.

## Contents

- `redis_fingerprints.json`: machine-readable fingerprint rules.
- `fingerprint_schema.json`: schema for the fingerprint library format.
- `tools/match_redis_fingerprints.py`: offline matcher for a captured banner.
- `tools/online_redis_reprobe.py`: authorized live reprobe and matcher.
- `reports/validation_report.md`: full-corpus rule coverage report.
- `reports/holdout_eval_10pct.md`: deterministic 10% real-IP holdout evaluation
  using already captured banners.
- `reports/live_reprobe_20260623_232520.md`: authorized live reprobe summary
  for one random 10% sample.
- `reports/observed_fields.csv`: INFO field frequency table.
- `reports/normalized_templates.jsonl`: top normalized INFO response templates.

Raw scan results, raw target IP lists, and live reprobe JSON/CSV details are not
committed here.

## What This Fingerprint Library Does

The library is rule based. It can identify Redis protocol-compatible services,
extract versions, classify known compatible implementations, and detect common
deployment/runtime hints.

Current rule layers:

- protocol identity
- implementation identity: Redis, Valkey, Dragonfly, Memurai
- version extraction
- standalone / cluster mode
- INFO response depth
- deployment hints such as Redis Stack, container-like layout, Linux package
  layout, and `/usr/local` installs
- runtime hints such as Linux, epoll, and systemd supervision

## Offline Matching

```bash
python3 tools/match_redis_fingerprints.py redis_fingerprints.json banner.txt --scanner-protocol REDIS
```

## Authorized Online Reprobe

Only run against explicitly authorized targets. The script samples 10% of unique
IPs from a prior REDIS scan corpus, probes only observed Redis ports, and sends
only `PING` and `INFO server`.

```bash
python3 tools/online_redis_reprobe.py /path/to/scan_results.jsonl redis_fingerprints.json reports --fraction 0.10 --concurrency 8 --timeout 2.0 --read-timeout 0.75 --confirm-authorized
```

Each run uses a fresh random seed unless `--seed` is specified.

## Current Evaluation

Full captured corpus:

- records: 7338
- protocol identity coverage: 100%
- rules: 24

Deterministic 10% captured-banner holdout:

- unique IPs: 529
- records: 707
- protocol match: 100.0%
- strong protocol match: 99.86%
- implementation match: 99.86%
- version extraction: 99.86%
- mode extraction: 99.72%

Authorized live 10% reprobe, run once:

- selected unique IPs: 529
- selected IP:port targets: 711
- responded targets: 327
- protocol match among responded targets: 100.0%
- implementation match among responded targets: 96.64%
- version extraction among responded targets: 96.64%
- mode extraction among responded targets: 96.33%

The live reprobe also found many connection failures. Those reflect endpoint
availability drift, filtering, or timeouts, not fingerprint rule failures.
