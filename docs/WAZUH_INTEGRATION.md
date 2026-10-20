# Wazuh integration

VIGIL treats the Wazuh Indexer and Manager as distinct services. The Indexer performs bounded historical searches. The optional Manager supplies agent context. VIGIL never calls Wazuh Active Response.

## Configuration

```powershell
$env:VIGIL_CONNECTOR_MODE = 'wazuh'
$env:VIGIL_WAZUH_INDEXER_URL = 'https://indexer-host:9200'
$env:VIGIL_WAZUH_INDEXER_USERNAME = 'readonly-vigil'
$env:VIGIL_WAZUH_INDEXER_PASSWORD = '<secret>'
$env:VIGIL_WAZUH_INDEX_PATTERN = 'wazuh-alerts-*'
$env:VIGIL_WAZUH_CA_BUNDLE = 'C:\path\to\wazuh-ca.pem'
$env:VIGIL_WAZUH_TIMEOUT_SECONDS = '15'

# Optional Manager lookup support
$env:VIGIL_WAZUH_MANAGER_URL = 'https://manager-host:55000'
$env:VIGIL_WAZUH_MANAGER_TOKEN = '<short-lived-token>'

vigil doctor
```

The URL must use HTTPS, TLS verification cannot be disabled, the index pattern is validated, and only structured fixed-field filters are built. Use a Wazuh/OpenSearch role that can only read the explicitly approved `wazuh-alerts-*` indices. Add `wazuh-archives-*` only if Izzat has enabled, reviewed, and authorized that coverage.

Authentication, session, generic, and indicator searches create distinct query bodies. Queries enforce timezone-aware windows, fixed result limits, and case scope. HTTP 401, 403, timeout, transport/TLS, 5xx, and malformed-response failures remain distinct unavailable errors and cause partial or failed runs rather than empty-success claims.

## Normalization

Both mock events and Indexer hits are converted to the same `EvidenceRecord` contract. It includes stable evidence/native IDs, connector mode, index, host, agent, user, IPs, rule, normalized event kind, aggregate event count, command/hash fields, query scope, coverage, simulation flag, and provenance. Unknown layouts are retained as `unknown` evidence.

Representative sanitized Indexer hits are in `fixtures/realistic_wazuh_hits/ssh_sequence.json`. Automated tests verify semantic parity with `fixtures/wazuh_events/events.json` for failed authentication counts, successful login, session start, and command observation.

## Information still required from Izzat

- Indexer URL/IP and reachable port from the VIGIL host
- exact readable index names/patterns
- sanitized alert and matching `_search` hit from the deployed Wazuh version/rules
- least-privilege read-only username and password supplied out of band
- CA certificate/bundle path
- optional Manager URL and token if agent inventory context is needed
- confirmation of which logs are indexed in alerts versus archives

Live Wazuh verification is not possible without these services and credentials. The connector is fixture and fake-HTTP verified only.
