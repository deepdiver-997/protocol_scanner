# PGSQL Fingerprint Validation

## Full Corpus

| metric | count | percent |
|---|---:|---:|
| protocol_match | 2053 | 100.0% |
| implementation_match | 531 | 25.86% |
| sqlstate_extraction | 1759 | 85.68% |

## 10% Real-IP Holdout

| metric | count | percent |
|---|---:|---:|
| protocol_match | 205 | 100.0% |
| implementation_match | 62 | 30.24% |
| sqlstate_extraction | 182 | 88.78% |

## Rule Coverage Top

| rule | count | percent |
|---|---:|---:|
| `pgsql.protocol.v3-context` | 2053 | 100.0% |
| `pgsql.extract.message` | 1778 | 86.6% |
| `pgsql.protocol.error-response` | 1771 | 86.26% |
| `pgsql.extract.sqlstate` | 1759 | 85.68% |
| `pgsql.err.bad-packet-header` | 933 | 45.45% |
| `pgsql.availability.starting-or-paused` | 400 | 19.48% |
| `pgsql.impl.redshift` | 351 | 17.1% |
| `pgsql.security.ssl-required` | 204 | 9.94% |
| `pgsql.auth.invalid-auth` | 194 | 9.45% |
| `pgsql.impl.tenant-proxy` | 130 | 6.33% |
| `pgsql.err.invalid-startup` | 92 | 4.48% |
| `pgsql.impl.cratedb` | 50 | 2.44% |
| `pgsql.protocol.authentication` | 14 | 0.68% |
| `pgsql.resource.memory` | 13 | 0.63% |

## Notes

- This corpus primarily contains PostgreSQL wire ErrorResponse/Auth responses; server version is not exposed.
- Implementation labels are hints when vendor-specific error text is present.
- The SQLSTATE miss set is analyzed in `sqlstate_gap_analysis_20260625.md`; most missing records do not contain a SQLSTATE-bearing ErrorResponse.
