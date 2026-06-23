# Authorized Online Redis Matcher Plan

This project currently includes an offline matcher and a 10% real-IP holdout
evaluation based on already captured banners. Active probing of public IPs was
not performed.

## Why Active Probing Was Not Run Here

The source file contains public-looking Redis endpoints. Reconnecting to a
sample of those endpoints would be active network probing. That should only be
done when the targets are explicitly authorized by the course, lab, owner, or
scanner operator.

## Authorized Online Matcher Design

Input:

```text
ip,port
192.0.2.10,6379
192.0.2.11,6380
```

Required controls:

- Use an explicit allowlist file.
- Require a `--confirm-authorized` flag.
- Default timeout no more than 2 seconds.
- Low concurrency, for example 5 to 10 workers.
- Only send Redis-safe probe commands:
  - `PING\r\n`
  - `INFO server\r\n`
- Do not send authentication, write, keyspace, config, or replication commands.
- Store raw responses locally and feed them into `redis_fingerprints.json`.
- Record failures separately: timeout, connection refused, non-Redis response.

Recommended output fields:

```text
ip,port,probe_status,protocol_match,strong_protocol_match,implementation,redis_version,mode,matched_rule_ids,response_time_ms,error
```

## Evaluation Method

1. Select 10% of unique IPs from the source corpus by stable hash.
2. Probe only those IPs if authorization is confirmed.
3. Match each live response with `redis_fingerprints.json`.
4. Compare live match coverage with `holdout_eval_10pct.json`.
5. Report drift:
   - endpoint no longer reachable
   - Redis response changed
   - implementation/version changed
   - rule no longer matches

## Current Non-Active Baseline

The current 10% holdout baseline uses 529 unique real IPs and 707 captured
Redis records:

- protocol match: 100.0%
- strong protocol match: 99.86%
- implementation match: 99.86%
- version extraction: 99.86%
- mode extraction: 99.72%

These numbers are the baseline for any later authorized live test.
