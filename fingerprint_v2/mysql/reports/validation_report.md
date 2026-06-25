# MYSQL Fingerprint Validation

## Full Corpus

| metric | count | percent |
|---|---:|---:|
| protocol_match | 422199 | 100.0% |
| implementation_match | 422198 | 100.0% |
| version_extraction | 422199 | 100.0% |

## 10% Real-IP Holdout

| metric | count | percent |
|---|---:|---:|
| protocol_match | 42220 | 100.0% |
| implementation_match | 42220 | 100.0% |
| version_extraction | 42220 | 100.0% |

## Rule Coverage Top

| rule | count | percent |
|---|---:|---:|
| `mysql.protocol.handshake-v10` | 422199 | 100.0% |
| `mysql.extract.version` | 422199 | 100.0% |
| `mysql.capability.flags-observed` | 422199 | 100.0% |
| `mysql.extract.major` | 422198 | 100.0% |
| `mysql.auth.plugin-observed` | 415196 | 98.34% |
| `mysql.impl.mysql-compatible-default` | 314689 | 74.54% |
| `mysql.impl.mariadb` | 105407 | 24.97% |
| `mysql.dist.ubuntu` | 82508 | 19.54% |
| `mysql.runtime.log-enabled` | 47431 | 11.23% |
| `mysql.dist.cloudlinux` | 35847 | 8.49% |
| `mysql.dist.debian` | 13047 | 3.09% |
| `mysql.dist.azure` | 12334 | 2.92% |
| `mysql.impl.percona` | 2078 | 0.49% |
| `mysql.impl.tidb` | 24 | 0.01% |

## Notes

- The current scanner exposes MySQL handshake version, protocol_version, auth_plugin, and capability_flags.
- The auth_plugin field appears truncated in many records and is treated as low-confidence metadata.
