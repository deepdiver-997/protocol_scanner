# PGSQL SQLSTATE Gap Analysis 2026-06-25

This report explains the 14.32% records where `pgsql.extract.sqlstate` does not
fire. Raw records and IPs are not included.

## Summary

| metric | count | percent |
|---|---:|---:|
| total PGSQL records | 2053 | 100.0% |
| SQLSTATE present | 1759 | 85.68% |
| SQLSTATE missing | 294 | 14.32% |

## Missing SQLSTATE Composition

| category | count | percent_of_missing | percent_of_total |
|---|---:|---:|---:|
| empty banner / no parsed response body | 191 | 64.97% | 9.30% |
| other non-SQLSTATE payload | 40 | 13.61% | 1.95% |
| textual or misaligned error without parsed SQLSTATE | 36 | 12.24% | 1.75% |
| Authentication response, no SQLSTATE by protocol design | 14 | 4.76% | 0.68% |
| ErrorResponse-like message without SQLSTATE field | 13 | 4.42% | 0.63% |

## Authentication Responses

| banner | count | interpretation |
|---|---:|---|
| `AuthenticationOk` | 6 | valid AuthenticationOk; SQLSTATE not expected |
| `Authentication3` | 4 | AuthenticationCleartextPassword; SQLSTATE not expected |
| `Authentication5` | 1 | AuthenticationMD5Password; SQLSTATE not expected |
| `Authentication808660528` / `Authentication808660536` | 3 | anomalous or misparsed code; keep as low-confidence anomaly |

## Message Samples Without SQLSTATE

| message pattern | count | note |
|---|---:|---|
| `invalid pgsql protocol version: 0.768` | 11 | ErrorResponse-like but SQLSTATE field absent |
| `unable to authenticate` | 4 | textual auth/proxy rejection |
| `[pg-proxy] Client must use SSL session encryption` | 2 | proxy/TLS requirement text |
| `invalid initial message` | 1 | ErrorResponse-like but SQLSTATE field absent |
| `invalid startup packet` | 1 | ErrorResponse-like but SQLSTATE field absent |

## Conclusion

The 85.68% SQLSTATE extraction rate is close to the useful ceiling for this
corpus. Most missing records do not contain a PostgreSQL ErrorResponse SQLSTATE
field at all. Only 13 records look like ErrorResponse messages with a message
field but no SQLSTATE field, so adding more SQLSTATE regexes would not materially
improve coverage. Better next work: classify missing records by response type and
add low-level auth/proxy/TLS behavior fingerprints.
