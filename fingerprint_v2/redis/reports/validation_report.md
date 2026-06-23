# Redis Fingerprint Library

This is a Redis/Redis-compatible protocol fingerprint library built from the provided REDIS scan corpus.

## Scope

- Source records: 7338
- Protocol identity coverage: 7338 / 7338 (100.0%)
- Rule layers: protocol identity, implementation, version extraction, deployment mode, probe depth, deployment hints, runtime environment.

## Files

- `redis_fingerprints.json`: the actual machine-readable fingerprint library.
- `fingerprint_schema.json`: schema for the library format.
- `match_redis_fingerprints.py`: offline matcher for a single banner file.
- `validation_report.json`: rule coverage against the provided corpus.
- `validation_report.md`: human-readable validation summary.
- `observed_fields.csv`: INFO field frequency table.

## Implementation Distribution

| implementation | count | percent |
|---|---:|---:|
| Redis | 7211 | 98.27% |
| Valkey | 90 | 1.23% |
| Dragonfly | 20 | 0.27% |
| unknown | 15 | 0.2% |
| Memurai | 2 | 0.03% |

## Rule Coverage

| rule | count | coverage |
|---|---:|---:|
| `redis.protocol.info-server` | 7323 | 99.8% |
| `redis.protocol.resp-bulk-info` | 7208 | 98.23% |
| `redis.protocol.pong` | 1 | 0.01% |
| `redis.protocol.info-error-context` | 7 | 0.1% |
| `redis.protocol.ok-context` | 6 | 0.08% |
| `redis.protocol.scanner-pong-ok-context` | 1 | 0.01% |
| `redis.protocol.auth-required` | 0 | 0% |
| `redis.impl.redis-server` | 7211 | 98.27% |
| `redis.impl.valkey` | 90 | 1.23% |
| `redis.impl.dragonfly` | 20 | 0.27% |
| `redis.impl.memurai` | 2 | 0.03% |
| `redis.extract.redis-version` | 7323 | 99.8% |
| `redis.mode.standalone` | 7284 | 99.26% |
| `redis.mode.cluster` | 31 | 0.42% |
| `redis.info.full` | 3584 | 48.84% |
| `redis.info.server-section` | 7209 | 98.24% |
| `redis.deploy.redis-stack` | 110 | 1.5% |
| `redis.deploy.container-path` | 2438 | 33.22% |
| `redis.deploy.linux-package` | 4133 | 56.32% |
| `redis.deploy.usr-local` | 20 | 0.27% |
| `redis.runtime.linux` | 7125 | 97.1% |
| `redis.runtime.epoll` | 7130 | 97.17% |
| `redis.supervised.systemd` | 376 | 5.12% |
| `redis.metadata.availability-zone` | 81 | 1.1% |

## Important Notes

- `redis.impl.redis-server` means no known alternate marker was found. Some compatible products may only expose `redis_version`, so this rule is intentionally not 1.00 confidence.
- `redis.protocol.info-error-context` and `redis.protocol.ok-context` are weak rules and require scanner context. Do not use bare `+OK` as a passive Redis fingerprint.
- Raw IP addresses are not needed by the fingerprint library; validation examples only include banner previews and ports.

## Example

```bash
python3 match_redis_fingerprints.py redis_fingerprints.json banner.txt --scanner-protocol REDIS
```
