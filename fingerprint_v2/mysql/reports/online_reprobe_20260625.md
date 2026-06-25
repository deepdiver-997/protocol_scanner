# Online MySQL Reprobe 2026-06-25

This report records a sanitized online validation run for the MySQL fingerprint
library. Raw JSON/CSV outputs contain public IPs and are intentionally not
committed.

## Scope

- Source corpus: local MySQL scan-result corpus, not committed
- Total unique IPs in source corpus: 422199
- Sampling policy: random 10% IP sample pool, capped to 500 IP:port targets for this pilot
- Concurrency: 8
- Timeout: 2.0 seconds
- Active probe behavior: open TCP connection and read the initial MySQL server handshake only
- Login packet: not sent

## Metrics

| metric | count | percent | percent_of_responded |
|---|---:|---:|---:|
| responded | 482 / 500 | 96.4% |  |
| protocol_match | 482 | 96.4% | 100.0% |
| implementation_match | 482 | 96.4% | 100.0% |
| version_extraction | 482 | 96.4% | 100.0% |

## Probe Status

| status | count | percent |
|---|---:|---:|
| handshake | 482 | 96.4% |
| connect_failed | 18 | 3.6% |

## Implementation Distribution

| implementation | count | percent_of_all_targets |
|---|---:|---:|
| MySQL_or_compatible | 354 | 70.8% |
| MariaDB | 123 | 24.6% |
| Percona Server | 5 | 1.0% |
| unknown/no response | 18 | 3.6% |

## Notes

- The online matcher result is computed from live handshake banners, not from the
  offline corpus rows.
- The cap avoids turning the first MySQL validation run into a 42220-target scan.
  The script supports removing `--max-targets` for a full 10% run after explicit
  approval.
