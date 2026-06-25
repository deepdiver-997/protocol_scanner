# Online PGSQL Reprobe 2026-06-25

This report records a sanitized online validation run for the PGSQL fingerprint
library. Raw JSON/CSV outputs contain public IPs and are intentionally not
committed.

## Scope

- Source corpus: local PGSQL scan-result corpus, not committed
- Total unique IPs in source corpus: 2053
- Sampling policy: full random 10% IP sample, 205 IP:port targets
- Concurrency: 8
- Timeout: 2.0 seconds
- Active probe behavior: send PostgreSQL SSLRequest; when TLS is not requested,
  send a minimal StartupMessage with `user`, `database`, and `application_name`
- Password: not sent
- SQL: not executed

## Metrics

| metric | count | percent | percent_of_responded |
|---|---:|---:|---:|
| responded | 189 / 205 | 92.2% |  |
| protocol_match | 189 | 92.2% | 100.0% |
| sqlstate_extraction | 21 | 10.24% | 11.11% |

## Probe Status

| status | count | percent |
|---|---:|---:|
| startup_response | 110 | 53.66% |
| ssl_supported | 79 | 38.54% |
| connect_failed | 16 | 7.8% |

## Notes

- `ssl_supported` is treated as a positive PostgreSQL wire-protocol signal, so it
  matches the online-only `pgsql.protocol.ssl-request-response` rule.
- SQLSTATE extraction is lower online because many live targets stop at the
  SSLRequest response and do not expose an ErrorResponse unless TLS is continued.
