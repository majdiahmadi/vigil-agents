# Wazuh Integration

Mock mode is the verified default. To connect Izzat's future deployment, set `VIGIL_CONNECTOR_MODE=wazuh` and configure:

```powershell
$env:VIGIL_WAZUH_INDEXER_URL = 'https://indexer.example:9200'
$env:VIGIL_WAZUH_INDEXER_USERNAME = 'read-only-user'
$env:VIGIL_WAZUH_INDEXER_PASSWORD = 'secret'
$env:VIGIL_WAZUH_CA_BUNDLE = 'C:\path\to\ca.pem'
$env:VIGIL_WAZUH_MANAGER_URL = 'https://manager.example:55000'
$env:VIGIL_WAZUH_MANAGER_TOKEN = 'short-lived-token'
```

The Wazuh Indexer/OpenSearch `_search` endpoint is used for historical security events. The Manager API is optional and only used for management/agent context. Searches use server-built structured filters, bounded windows and limits. TLS verification is on by default. Native IDs, source fields, timestamps, agent IDs, rule IDs, and raw source records are retained.

Live connectivity is not verified until the external system exists. VIGIL never installs Wazuh, changes rules/settings, blocks IPs, or calls Active Response. Any response configured separately in Wazuh is outside VIGIL's human-approval boundary.

