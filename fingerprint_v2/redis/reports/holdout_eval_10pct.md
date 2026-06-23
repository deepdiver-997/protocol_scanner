# Redis Fingerprint Holdout Evaluation

This evaluation uses a deterministic 10% holdout of real IPs from the provided corpus.
It does not actively connect to those IPs; it evaluates the fingerprint library against the already captured banners.

## Split

- Total unique IPs: 5289
- Test unique IPs: 529
- Test records: 707

## Metrics

| metric | matched | coverage |
|---|---:|---:|
| protocol_match | 707 | 100.0% |
| strong_protocol_match | 706 | 99.86% |
| implementation_match | 706 | 99.86% |
| version_extraction | 706 | 99.86% |
| mode_extraction | 705 | 99.72% |

## Implementation Distribution

| implementation | count | percent |
|---|---:|---:|
| Redis | 689 | 97.45% |
| Valkey | 13 | 1.84% |
| Dragonfly | 3 | 0.42% |
| unknown | 1 | 0.14% |
| Memurai | 1 | 0.14% |

## Category Coverage

| category | matched_records | coverage |
|---|---:|---:|
| deployment_distribution | 8 | 1.13% |
| deployment_hint | 626 | 88.54% |
| deployment_mode | 705 | 99.72% |
| implementation | 706 | 99.86% |
| probe_depth | 692 | 97.88% |
| protocol_identity | 706 | 99.86% |
| protocol_identity_weak | 1 | 0.14% |
| provider_metadata | 11 | 1.56% |
| runtime_environment | 680 | 96.18% |
| version_extraction | 706 | 99.86% |

## Notes

- Weak Redis protocol matches require scanner context.
- IPs are not printed in this report; unmatched examples use short IP hashes.
