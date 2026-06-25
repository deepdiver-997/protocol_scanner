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
| responded | 187 / 205 | 91.22% |  |
| protocol_match | 187 | 91.22% | 100.0% |
| sqlstate_extraction | 22 | 10.73% | 11.76% |
| server_version_extraction | 0 | 0.0% | 0.0% |

## Probe Status

| status | count | percent |
|---|---:|---:|
| startup_response | 102 | 49.76% |
| ssl_supported | 85 | 41.46% |
| connect_failed | 18 | 8.78% |

## Auth Methods

| method | count | percent |
|---|---:|---:|
| none | 165 | 80.49% |
| cleartext_password | 30 | 14.63% |
| md5_password | 6 | 2.93% |
| sasl | 4 | 1.95% |

## Notes

- `ssl_supported` is treated as a positive PostgreSQL wire-protocol signal, so it
  matches the online-only `pgsql.protocol.ssl-request-response` rule.
- SQLSTATE extraction is lower online because many live targets stop at the
  SSLRequest response and do not expose an ErrorResponse unless TLS is continued.
- `server_version` was not observed in this unauthenticated run; ParameterStatus
  is retained as an opportunistic parser for permissive or proxy paths.
